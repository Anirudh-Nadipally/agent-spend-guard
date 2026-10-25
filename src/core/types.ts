// Types mirroring the decision object documented at
// https://docs.saifuro.com/api/authorizations (field names are canonical there).

/** The eight decision codes, https://docs.saifuro.com/concepts/decision-codes */
export type Verdict =
  | 'allow'
  | 'review'
  | 'deny_limit'
  | 'deny_velocity'
  | 'deny_category'
  | 'deny_expired'
  | 'deny_revoked'
  | 'deny_no_mandate';

export type Mode = 'observe' | 'enforce';

/** Body of POST /v1/authorizations. */
export interface AuthorizationRequest {
  amount: number;
  currency: string;
  recipient: string;
  category: string;
  protocol?: 'x402' | 'mpp' | 'acp' | 'ap2' | 'card' | string;
  /** Only honoured with an organization key; ignored on an agent key. */
  agent?: string;
  metadata?: Record<string, string>;
}

/** The request as echoed back in a decision and signed into the verdict token. */
export interface RequestEcho {
  agent: string;
  amount: number;
  currency: string;
  recipient: string;
  category: string;
}

export interface ReviewInfo {
  review: string;
  waits_for: string;
  expires_at: string;
}

/** Response of POST /v1/authorizations (201 for every verdict, including denials). */
export interface Decision {
  decision: string;
  request: RequestEcho;
  verdict: Verdict;
  reason: string;
  mandate?: string; // absent on deny_no_mandate
  policy_version: string;
  nonce: string;
  mode: Mode;
  issued_at: string;
  expires_at?: string; // allow only: issued_at + 5 minutes
  verdict_token: string;
  review?: ReviewInfo; // review only
  supersedes?: string; // review-approval allow only
  metadata?: Record<string, string>;
}

/** A mandate as documented at https://docs.saifuro.com/api/mandates */
export interface Mandate {
  mandate: string;
  principal: string;
  agent: string;
  limits: { per_transaction: number; per_month?: number; currency: string };
  categories: string[];
  review_above?: number;
  /** Date (YYYY-MM-DD) the mandate stops matching. */
  expires: string;
  status: 'active' | 'revoked';
  created_at: string;
}

/** Anything that can answer "may this agent spend this?" (the mock or the real API). */
export interface SaifuroClient {
  authorize(req: AuthorizationRequest, opts?: { idempotencyKey?: string }): Promise<Decision>;
}

/** Thrown when Saifuro cannot be reached or answers with a non-2xx. The guard fails closed on it. */
export class SaifuroUnavailableError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message);
    this.name = 'SaifuroUnavailableError';
  }
}

export const ISSUER = 'https://verdicts.saifuro.com';
export const PROD_JWKS_URL = 'https://verdicts.saifuro.com/.well-known/jwks.json';
