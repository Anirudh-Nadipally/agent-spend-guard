// A local mock of Saifuro's documented policy engine. It is NOT Saifuro: it reproduces
// the behaviour the public docs describe so the guard and evals can run without keys.
//
// Check order (https://docs.saifuro.com/concepts/decision-codes):
//   no_mandate -> revoked -> expired -> category -> limit (per_transaction, then rolling
//   30-day per_month) -> velocity (more than 10 decisions in 60 s) -> review -> allow
import { randomBytes } from 'node:crypto';
import { SignJWT, exportJWK, generateKeyPair, type JSONWebKeySet } from 'jose';
import {
  ISSUER,
  type AuthorizationRequest,
  type Decision,
  type Mandate,
  type Mode,
  type SaifuroClient,
  type Verdict,
} from './types.js';

export const SANDBOX_KID = 'sandbox-local';
const MINUTE = 60_000;
const DAY = 24 * 60 * MINUTE;
const ALLOW_TTL_MS = 5 * MINUTE; // allow expires five minutes after issue
const REVIEW_TTL_MS = DAY; // a review expires 24 hours after it is created
const VELOCITY_WINDOW_MS = MINUTE;
const VELOCITY_MAX = 10; // fixed rule: the 11th decision inside 60 s is denied

type Clock = () => number;
type CryptoKeyLike = CryptoKey;

interface PendingReview {
  id: string;
  decision: Decision;
  mandate: Mandate;
  createdAt: number;
  status: 'pending' | 'approved' | 'denied';
}

export interface MockEngineOptions {
  agent?: string; // the agent an "agent key" would identify
  mode?: Mode;
  policyVersion?: string;
  now?: Clock;
}

const id = (prefix: string) => `${prefix}_${randomBytes(4).toString('hex')}`;
const money = (n: number) => n.toFixed(2);

export class MockEngine implements SaifuroClient {
  readonly agent: string;
  mode: Mode;
  private readonly policyVersion: string;
  private readonly now: Clock;
  private mandates: Mandate[] = [];
  private disabledAgents = new Set<string>();
  private decisionTimes = new Map<string, number[]>(); // agent -> decision timestamps
  private allows: { mandate: string; amount: number; at: number }[] = [];
  private reviews = new Map<string, PendingReview>();
  private idempotency = new Map<string, Decision>();

  private constructor(
    private readonly privateKey: CryptoKeyLike,
    readonly jwks: JSONWebKeySet,
    opts: MockEngineOptions,
  ) {
    this.agent = opts.agent ?? 'agt_demo';
    this.mode = opts.mode ?? 'enforce';
    this.policyVersion = opts.policyVersion ?? 'pol_mock.1';
    this.now = opts.now ?? Date.now;
  }

  /** Generates a fresh ES256 key pair; the public half is exposed as a local JWKS. */
  static async create(opts: MockEngineOptions = {}): Promise<MockEngine> {
    const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
    const jwk = { ...(await exportJWK(publicKey)), kid: SANDBOX_KID, alg: 'ES256', use: 'sig' };
    return new MockEngine(privateKey, { keys: [jwk] }, opts);
  }

  // ---- mandate management (POST /v1/mandates, /revoke) ----

  addMandate(m: Omit<Mandate, 'mandate' | 'status' | 'created_at' | 'agent'> & { agent?: string }): Mandate {
    const mandate: Mandate = {
      ...m,
      agent: m.agent ?? this.agent,
      mandate: id('mnd'),
      status: 'active',
      created_at: new Date(this.now()).toISOString(),
    };
    this.mandates.push(mandate);
    return mandate;
  }

  revokeMandate(mandateId: string): void {
    const m = this.mandates.find((x) => x.mandate === mandateId);
    if (!m) throw new Error(`unknown mandate ${mandateId}`);
    m.status = 'revoked';
  }

  disableAgent(agent: string = this.agent): void {
    this.disabledAgents.add(agent);
  }

  // ---- POST /v1/authorizations ----

  async authorize(req: AuthorizationRequest, opts: { idempotencyKey?: string } = {}): Promise<Decision> {
    if (opts.idempotencyKey && this.idempotency.has(opts.idempotencyKey)) {
      return this.idempotency.get(opts.idempotencyKey)!;
    }
    const agent = this.agent; // agent key: the agent is taken from the key, req.agent is ignored
    const now = this.now();
    const velocityExceeded = this.recentDecisions(agent, now) >= VELOCITY_MAX;
    this.recordDecisionTime(agent, now);

    const { verdict, reason, mandate } = this.evaluate(agent, req, now, velocityExceeded);
    const decision = await this.issue({ agent, req, verdict, reason, mandate, now });
    if (opts.idempotencyKey) this.idempotency.set(opts.idempotencyKey, decision);
    return decision;
  }

  /** Runs the documented gates against every applicable mandate and picks the result. */
  private evaluate(agent: string, req: AuthorizationRequest, now: number, velocityExceeded: boolean) {
    const candidates = this.mandates.filter((m) => m.agent === agent && m.limits.currency === req.currency);
    if (this.disabledAgents.has(agent) || candidates.length === 0) {
      const reason = this.disabledAgents.has(agent)
        ? `agent ${agent} is disabled`
        : `no mandate for agent ${agent} in currency ${req.currency}`;
      return { verdict: 'deny_no_mandate' as Verdict, reason, mandate: undefined };
    }
    // Several mandates: evaluated in creation order; first allow, else first review, else the oldest's result.
    const results = candidates.map((m) => ({ mandate: m, ...this.checkMandate(m, req, now, velocityExceeded) }));
    return results.find((r) => r.verdict === 'allow') ?? results.find((r) => r.verdict === 'review') ?? results[0];
  }

  private checkMandate(m: Mandate, req: AuthorizationRequest, now: number, velocityExceeded: boolean): { verdict: Verdict; reason: string } {
    if (m.status === 'revoked') return { verdict: 'deny_revoked', reason: `mandate ${m.mandate} was revoked` };
    if (isExpired(m, now)) return { verdict: 'deny_expired', reason: `mandate ${m.mandate} expired on ${m.expires}` };
    if (!m.categories.includes(req.category)) {
      return { verdict: 'deny_category', reason: `category ${req.category} is not allowed by mandate ${m.mandate}` };
    }
    if (req.amount > m.limits.per_transaction) {
      return { verdict: 'deny_limit', reason: `amount ${money(req.amount)} exceeds per_transaction limit ${money(m.limits.per_transaction)}` };
    }
    if (m.limits.per_month !== undefined) {
      const spent = this.allowedLast30Days(m.mandate, now);
      if (spent + req.amount > m.limits.per_month) {
        return { verdict: 'deny_limit', reason: `amount ${money(req.amount)} plus ${money(spent)} in the last 30 days exceeds per_month limit ${money(m.limits.per_month)}` };
      }
    }
    if (velocityExceeded) return { verdict: 'deny_velocity', reason: `more than ${VELOCITY_MAX} decisions in 60 seconds` };
    if (m.review_above !== undefined && req.amount > m.review_above) {
      return { verdict: 'review', reason: `amount ${money(req.amount)} is above review_above ${money(m.review_above)}` };
    }
    return { verdict: 'allow', reason: `within mandate ${m.mandate}` };
  }

  // ---- reviews: POST /v1/reviews/{id}/approve and /deny ----

  /** Approval re-checks agent, mandate and per_month, then issues a fresh allow that supersedes the review. */
  async approveReview(reviewId: string): Promise<Decision> {
    const r = this.reviews.get(reviewId);
    const now = this.now();
    if (!r || r.status !== 'pending' || now > r.createdAt + REVIEW_TTL_MS) {
      throw new Error(`400 invalid_request: review ${reviewId} is not pending`);
    }
    const { mandate: m, decision } = r;
    if (this.disabledAgents.has(m.agent)) throw new Error('400 invalid_request: agent is disabled');
    if (m.status === 'revoked') throw new Error('400 invalid_request: mandate is revoked');
    if (isExpired(m, now)) throw new Error('400 invalid_request: mandate is expired');
    const amount = decision.request.amount;
    if (m.limits.per_month !== undefined && this.allowedLast30Days(m.mandate, now) + amount > m.limits.per_month) {
      throw new Error('400 invalid_request: approval would exceed per_month');
    }
    r.status = 'approved'; // a review yields at most one allow
    return this.issue({
      agent: decision.request.agent,
      req: decision.request,
      verdict: 'allow',
      reason: `review ${reviewId} approved under mandate ${m.mandate}`,
      mandate: m,
      now,
      supersedes: decision.decision,
    });
  }

  denyReview(reviewId: string): void {
    const r = this.reviews.get(reviewId);
    if (!r || r.status !== 'pending') throw new Error(`400 invalid_request: review ${reviewId} is not pending`);
    r.status = 'denied'; // closes in place, issues no decision
  }

  // ---- internals ----

  private async issue(args: {
    agent: string;
    req: AuthorizationRequest;
    verdict: Verdict;
    reason: string;
    mandate?: Mandate;
    now: number;
    supersedes?: string;
  }): Promise<Decision> {
    const { agent, req, verdict, reason, mandate, now, supersedes } = args;
    const decisionId = id('dec');
    const nonce = id('n');
    const request = { agent, amount: req.amount, currency: req.currency, recipient: req.recipient, category: req.category };
    const iat = Math.floor(now / 1000);

    const claims: Record<string, unknown> = { verdict, policy_version: this.policyVersion, nonce, request };
    if (mandate) claims.mandate = mandate.mandate;
    if (supersedes) claims.supersedes = supersedes;
    const verdict_token = await new SignJWT(claims)
      .setProtectedHeader({ alg: 'ES256', typ: 'JWT', kid: SANDBOX_KID })
      .setIssuer(ISSUER)
      .setJti(decisionId)
      .setIssuedAt(iat)
      .setExpirationTime(iat + ALLOW_TTL_MS / 1000) // every verdict carries a five-minute expiry
      .sign(this.privateKey);

    const decision: Decision = {
      decision: decisionId,
      request,
      verdict,
      reason,
      ...(mandate && { mandate: mandate.mandate }),
      policy_version: this.policyVersion,
      nonce,
      mode: this.mode,
      issued_at: new Date(iat * 1000).toISOString(),
      ...(verdict === 'allow' && { expires_at: new Date((iat * 1000) + ALLOW_TTL_MS).toISOString() }),
      verdict_token,
      ...(supersedes && { supersedes }),
      ...('metadata' in req && req.metadata && { metadata: req.metadata }),
    };

    if (verdict === 'allow' && mandate) this.allows.push({ mandate: mandate.mandate, amount: req.amount, at: now });
    if (verdict === 'review' && mandate) {
      const reviewId = id('rev');
      decision.review = { review: reviewId, waits_for: mandate.principal, expires_at: new Date(now + REVIEW_TTL_MS).toISOString() };
      this.reviews.set(reviewId, { id: reviewId, decision, mandate, createdAt: now, status: 'pending' });
    }
    return decision;
  }

  private recentDecisions(agent: string, now: number): number {
    return (this.decisionTimes.get(agent) ?? []).filter((t) => now - t < VELOCITY_WINDOW_MS).length;
  }

  private recordDecisionTime(agent: string, now: number): void {
    const times = (this.decisionTimes.get(agent) ?? []).filter((t) => now - t < VELOCITY_WINDOW_MS);
    times.push(now);
    this.decisionTimes.set(agent, times);
  }

  private allowedLast30Days(mandateId: string, now: number): number {
    return this.allows
      .filter((a) => a.mandate === mandateId && now - a.at < 30 * DAY)
      .reduce((sum, a) => sum + a.amount, 0);
  }
}

/** `expires` is a date; the mandate matches through the end of that day (UTC). Assumption: docs give no time of day. */
function isExpired(m: Mandate, now: number): boolean {
  return now >= Date.parse(`${m.expires}T00:00:00Z`) + DAY;
}
