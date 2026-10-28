// guardedPay: the one place a payment is allowed to happen.
//
// Rules (from https://docs.saifuro.com/reference/not-built-yet and /concepts/how-it-works):
// - Saifuro blocks nothing. In enforce mode the integration stops every non-allow.
// - There is no failure-mode setting. If Saifuro is unreachable we do NOT pay (fail closed).
// - An allow is only spent after its token verifies for this exact deal.
// - review: hold, hand to a human, never pay around it.
// - Any non-allow trips the circuit breaker for that recipient/category (anti-structuring).
// - observe mode: log what enforce would have done, and let the payment through.
// - One request per recipient/category at a time (the breaker's lock), so parallel splits cannot race the deny.
// - A payment that throws after an allow is reported, never thrown: we cannot know if money moved,
//   so the payee is closed until a human reconciles using the idempotency key.
import { randomUUID } from 'node:crypto';
import { SaifuroUnavailableError, type AuthorizationRequest, type Decision, type ReviewInfo, type SaifuroClient, type Verdict } from '../core/types.js';
import type { Deal, VerdictClaims } from '../verify/verify.js';
import type { CircuitBreaker, Trip } from './circuit-breaker.js';

export interface GuardConfig {
  client: SaifuroClient;
  /** Usually `(t, d) => verifyVerdict(t, d, opts)`. Must throw on anything but a valid allow for this deal. */
  verify: (token: string, deal: Deal) => Promise<VerdictClaims>;
  breaker?: CircuitBreaker;
  /** Called when a review is pending, so your system can route it to the approver. */
  onReview?: (decision: Decision) => void | Promise<void>;
  onEvent?: (event: GuardEvent) => void;
}

export type GuardEvent = { type: string; req: AuthorizationRequest; detail?: unknown };

export type GuardResult<T> =
  | { status: 'paid'; decision: Decision; receipt: T }
  | { status: 'paid_in_observe'; decision: Decision; receipt: T; wouldHaveBlocked: boolean }
  | { status: 'denied'; verdict: Verdict; reason: string; decision: Decision }
  | { status: 'held_for_review'; review: ReviewInfo; reason: string; decision: Decision }
  | { status: 'blocked_by_breaker'; trip: Trip }
  | { status: 'unavailable'; error: string }
  | { status: 'invalid_verdict'; error: string; decision: Decision }
  | { status: 'invalid_request'; error: string }
  | { status: 'pay_declined'; error: string; decision: Decision; idempotencyKey: string }
  | { status: 'pay_outcome_unknown'; error: string; decision: Decision; idempotencyKey: string };

/** The rail gets the same idempotency key as the authorization, so a retried settlement is deduplicated there. */
export type PayFn<T> = (decision: Decision, ctx: { idempotencyKey: string }) => Promise<T>;

export interface PayOptions {
  /** One key per payment intent. Reuse it on a retry of the same intent; never reuse it for a new purchase. */
  idempotencyKey?: string;
}

/** Throw this from your PayFn only when the rail says no money moved (a decline). Anything else is treated as unknown. */
export class PaymentDeclinedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PaymentDeclinedError';
  }
}

/** Rejects requests no policy should even see. A negative amount would otherwise lower a monthly total. */
export function validateRequest(req: AuthorizationRequest): string | undefined {
  if (typeof req.amount !== 'number' || !Number.isFinite(req.amount) || req.amount <= 0) return `amount must be a positive finite number, got ${req.amount}`;
  if (!req.currency || !req.recipient || !req.category) return 'currency, recipient and category are required';
  return undefined;
}

export async function guardedPay<T>(cfg: GuardConfig, req: AuthorizationRequest, pay: PayFn<T>, opts: PayOptions = {}): Promise<GuardResult<T>> {
  const invalid = validateRequest(req);
  if (invalid) {
    cfg.onEvent?.({ type: 'invalid_request', req, detail: invalid });
    return { status: 'invalid_request', error: invalid };
  }
  const idempotencyKey = opts.idempotencyKey ?? randomUUID();
  const run = () => guardedPayLocked(cfg, req, pay, idempotencyKey);
  return cfg.breaker ? cfg.breaker.withLock(req, run) : run();
}

async function guardedPayLocked<T>(cfg: GuardConfig, req: AuthorizationRequest, pay: PayFn<T>, idempotencyKey: string): Promise<GuardResult<T>> {
  const emit = (type: string, detail?: unknown) => cfg.onEvent?.({ type, req, detail });

  // 1. Circuit breaker: a recipient/category that already got a non-allow this session is closed.
  const trip = cfg.breaker?.check(req);
  if (trip) {
    emit('blocked_by_breaker', trip);
    return { status: 'blocked_by_breaker', trip };
  }

  // 2. Ask Saifuro. No answer means no payment.
  let decision: Decision;
  try {
    decision = await cfg.client.authorize(req, { idempotencyKey });
  } catch (err) {
    const error = err instanceof SaifuroUnavailableError ? err.message : `authorization failed: ${(err as Error).message}`;
    emit('unavailable', error);
    return { status: 'unavailable', error };
  }

  // 3. Observe mode: Saifuro's verdict is informational; record it and pay.
  if (decision.mode === 'observe') {
    const wouldHaveBlocked = decision.verdict !== 'allow';
    emit('observe', { verdict: decision.verdict, wouldHaveBlocked });
    const settled = await settle(cfg, decision, req, pay, idempotencyKey);
    if (settled.status !== 'paid') return settled;
    return { status: 'paid_in_observe', decision, receipt: settled.receipt, wouldHaveBlocked };
  }

  // 4. Enforce mode, review: hold and route to a human. Trips the breaker so the agent cannot pay around it.
  if (decision.verdict === 'review') {
    cfg.breaker?.trip(req, decision.verdict, decision.reason);
    await cfg.onReview?.(decision);
    emit('held_for_review', decision.review);
    return { status: 'held_for_review', review: decision.review!, reason: decision.reason, decision };
  }

  // 5. Enforce mode, any deny: stop and trip the breaker.
  if (decision.verdict !== 'allow') {
    cfg.breaker?.trip(req, decision.verdict, decision.reason);
    emit('denied', { verdict: decision.verdict, reason: decision.reason });
    return { status: 'denied', verdict: decision.verdict, reason: decision.reason, decision };
  }

  // 6. Allow: verify the signed token against the deal we are about to settle, then pay.
  return verifyThenPay(cfg, decision, req, pay, idempotencyKey);
}

/**
 * After a human approves a review, Saifuro issues a fresh allow (with `supersedes`).
 * Pay it through the same verification. The breaker is not consulted: a person approved
 * this exact deal, and the token proves it.
 */
export async function payApproved<T>(cfg: GuardConfig, approval: Decision, req: AuthorizationRequest, pay: PayFn<T>, opts: PayOptions = {}): Promise<GuardResult<T>> {
  const invalid = validateRequest(req);
  if (invalid) return { status: 'invalid_request', error: invalid };
  if (approval.verdict !== 'allow') {
    return { status: 'denied', verdict: approval.verdict, reason: approval.reason, decision: approval };
  }
  return verifyThenPay(cfg, approval, req, pay, opts.idempotencyKey ?? randomUUID());
}

async function verifyThenPay<T>(cfg: GuardConfig, decision: Decision, req: AuthorizationRequest, pay: PayFn<T>, idempotencyKey: string): Promise<GuardResult<T>> {
  try {
    await cfg.verify(decision.verdict_token, { amount: req.amount, currency: req.currency, recipient: req.recipient });
  } catch (err) {
    cfg.onEvent?.({ type: 'invalid_verdict', req, detail: (err as Error).message });
    return { status: 'invalid_verdict', error: (err as Error).message, decision };
  }
  return settle(cfg, decision, req, pay, idempotencyKey);
}

/** Calls the rail and turns every outcome into a result. A throw that is not a known decline is "unknown". */
async function settle<T>(
  cfg: GuardConfig,
  decision: Decision,
  req: AuthorizationRequest,
  pay: PayFn<T>,
  idempotencyKey: string,
): Promise<Extract<GuardResult<T>, { status: 'paid' | 'pay_declined' | 'pay_outcome_unknown' }>> {
  try {
    const receipt = await pay(decision, { idempotencyKey });
    cfg.onEvent?.({ type: 'paid', req, detail: decision.decision });
    return { status: 'paid', decision, receipt };
  } catch (err) {
    const error = (err as Error).message;
    if (err instanceof PaymentDeclinedError) {
      cfg.onEvent?.({ type: 'pay_declined', req, detail: error });
      return { status: 'pay_declined', error, decision, idempotencyKey };
    }
    // Timeout, dropped socket, 5xx: the money may have moved. Close the payee so the agent's retry cannot double-pay.
    cfg.breaker?.trip(req, 'pay_outcome_unknown', error);
    cfg.onEvent?.({ type: 'pay_outcome_unknown', req, detail: { error, idempotencyKey } });
    return { status: 'pay_outcome_unknown', error, decision, idempotencyKey };
  }
}

/** One line a model can act on. Deliberately blunt: the agent must not improvise around a verdict. */
export function instructionFor(result: GuardResult<unknown>): string {
  switch (result.status) {
    case 'paid':
      return 'paid';
    case 'paid_in_observe':
      return result.wouldHaveBlocked ? `paid (observe mode; enforce would have blocked: ${result.decision.verdict})` : 'paid (observe mode)';
    case 'denied':
      return `denied: ${result.verdict} (${result.reason}). Do not retry, split, relabel or pay another way. Stop and ask the user.`;
    case 'held_for_review':
      return `held for human review ${result.review.review} (waits for ${result.review.waits_for}). Do not retry, split or pay another way. Tell the user it awaits approval.`;
    case 'blocked_by_breaker':
      return `blocked: an earlier ${result.trip.verdict} on ${result.trip.key} closed this payee/category until a human clears it. Do not retry. Ask the user.`;
    case 'unavailable':
      return `not paid: authorization service unavailable (${result.error}). Failing closed. Do not pay another way. Tell the user.`;
    case 'invalid_verdict':
      return `not paid: the approval did not verify (${result.error}). Do not retry. Tell the user.`;
    case 'invalid_request':
      return `not paid: invalid request (${result.error}). Do not retry. Tell the user.`;
    case 'pay_declined':
      return `not paid: the payment rail declined (${result.error}). No money moved. Tell the user.`;
    case 'pay_outcome_unknown':
      return `unknown: the payment failed mid-flight (${result.error}) and may have settled. Do not pay again. Tell the user it needs reconciling (key ${result.idempotencyKey}).`;
  }
}
