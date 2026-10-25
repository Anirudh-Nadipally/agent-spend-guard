// guardedPay: the one place a payment is allowed to happen.
//
// Rules (from https://docs.saifuro.com/reference/not-built-yet and /concepts/how-it-works):
// - Saifuro blocks nothing. In enforce mode the integration stops every non-allow.
// - There is no failure-mode setting. If Saifuro is unreachable we do NOT pay (fail closed).
// - An allow is only spent after its token verifies for this exact deal.
// - review: hold, hand to a human, never pay around it.
// - Any non-allow trips the circuit breaker for that recipient/category (anti-structuring).
// - observe mode: log what enforce would have done, and let the payment through.
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
  | { status: 'invalid_verdict'; error: string; decision: Decision };

export type PayFn<T> = (decision: Decision) => Promise<T>;

export async function guardedPay<T>(cfg: GuardConfig, req: AuthorizationRequest, pay: PayFn<T>): Promise<GuardResult<T>> {
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
    decision = await cfg.client.authorize(req);
  } catch (err) {
    const error = err instanceof SaifuroUnavailableError ? err.message : `authorization failed: ${(err as Error).message}`;
    emit('unavailable', error);
    return { status: 'unavailable', error };
  }

  // 3. Observe mode: Saifuro's verdict is informational; record it and pay.
  if (decision.mode === 'observe') {
    const wouldHaveBlocked = decision.verdict !== 'allow';
    emit('observe', { verdict: decision.verdict, wouldHaveBlocked });
    return { status: 'paid_in_observe', decision, receipt: await pay(decision), wouldHaveBlocked };
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
  return verifyThenPay(cfg, decision, req, pay);
}

/**
 * After a human approves a review, Saifuro issues a fresh allow (with `supersedes`).
 * Pay it through the same verification. The breaker is not consulted: a person approved
 * this exact deal, and the token proves it.
 */
export async function payApproved<T>(cfg: GuardConfig, approval: Decision, req: AuthorizationRequest, pay: PayFn<T>): Promise<GuardResult<T>> {
  if (approval.verdict !== 'allow') {
    return { status: 'denied', verdict: approval.verdict, reason: approval.reason, decision: approval };
  }
  return verifyThenPay(cfg, approval, req, pay);
}

async function verifyThenPay<T>(cfg: GuardConfig, decision: Decision, req: AuthorizationRequest, pay: PayFn<T>): Promise<GuardResult<T>> {
  try {
    await cfg.verify(decision.verdict_token, { amount: req.amount, currency: req.currency, recipient: req.recipient });
  } catch (err) {
    cfg.onEvent?.({ type: 'invalid_verdict', req, detail: (err as Error).message });
    return { status: 'invalid_verdict', error: (err as Error).message, decision };
  }
  const receipt = await pay(decision);
  cfg.onEvent?.({ type: 'paid', req, detail: decision.decision });
  return { status: 'paid', decision, receipt };
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
  }
}
