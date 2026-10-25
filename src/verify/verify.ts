// Verdict verification as described at https://docs.saifuro.com/reference/verify-a-verdict
//
// The signature proves the token came from the key set and was not changed. Whether it is
// good for THIS deal is a claims check, and the nonce store makes it single-use.
import { createLocalJWKSet, errors, jwtVerify, type JSONWebKeySet, type JWTPayload, type JWTVerifyGetKey } from 'jose';
import { ISSUER, PROD_JWKS_URL, type RequestEcho, type Verdict } from '../core/types.js';

export interface Deal {
  amount: number;
  currency: string;
  recipient: string;
}

export interface VerdictClaims extends JWTPayload {
  verdict: Verdict;
  mandate?: string;
  policy_version: string;
  nonce: string;
  request: RequestEcho;
  supersedes?: string;
}

export type VerdictErrorCode =
  | 'token_too_large'
  | 'malformed_token'
  | 'bad_signature'
  | 'unknown_kid'
  | 'expired'
  | 'claim_invalid'
  | 'iat_in_future'
  | 'unexpected_audience'
  | 'sandbox_kid_in_production'
  | 'production_kid_in_sandbox'
  | 'not_allow'
  | 'missing_mandate'
  | 'mandate_not_permitted'
  | 'deal_mismatch'
  | 'amount_too_large'
  | 'replayed_nonce'
  | 'supersedes_replayed';

export class VerdictError extends Error {
  constructor(readonly code: VerdictErrorCode, message: string = code) {
    super(message);
    this.name = 'VerdictError';
  }
}

/** Single-use nonces. `claim` must be atomic: true the first time, false on any replay. */
export interface NonceStore {
  claim(nonce: string, keepUntilMs: number): boolean | Promise<boolean>;
}

/** In-process store. In production this must be shared by every instance that accepts verdicts (e.g. Redis SET NX PX). */
export class InMemoryNonceStore implements NonceStore {
  private seen = new Map<string, number>();
  constructor(private readonly now: () => number = Date.now) {}
  claim(nonce: string, keepUntilMs: number): boolean {
    const t = this.now();
    for (const [n, until] of this.seen) if (until < t) this.seen.delete(n); // prune expired
    if (this.seen.has(nonce)) return false;
    this.seen.set(nonce, keepUntilMs);
    return true;
  }
}

export interface VerifyOptions {
  keys: JWTVerifyGetKey;
  /** production: reject `sandbox-` kids. sandbox: require them, so a production token in a test path is loud. */
  env: 'production' | 'sandbox';
  nonceStore: NonceStore;
  /** Operator check: accept only verdicts under these mandate ids (when the payment draws on one operator's funds). */
  allowedMandates?: string[];
  audience?: string;
  now?: () => number;
  clockSkewSec?: number;
  maxTokenBytes?: number;
}

const SEGMENT = /^[A-Za-z0-9_-]+$/; // base64url, no padding, no whitespace
const MAX_SAFE_AMOUNT = 1_000_000_000; // above this, float comparison is not exact (docs: compare as decimals)

export async function verifyVerdict(token: string, deal: Deal, opts: VerifyOptions): Promise<VerdictClaims> {
  const now = opts.now ?? Date.now;
  const skew = opts.clockSkewSec ?? 30;

  // 1. Structure: size limit, three clean base64url segments.
  if (Buffer.byteLength(token) > (opts.maxTokenBytes ?? 8192)) throw new VerdictError('token_too_large');
  const parts = token.split('.');
  if (parts.length !== 3 || !parts.every((p) => SEGMENT.test(p))) throw new VerdictError('malformed_token');

  // 2. Signature against the JWKS, issuer, expiry, required claims.
  let payload: VerdictClaims;
  let kid: string | undefined;
  try {
    const res = await jwtVerify(token, opts.keys, {
      issuer: ISSUER,
      algorithms: ['ES256'],
      requiredClaims: ['exp', 'iat', 'nonce', 'verdict', 'request'],
      currentDate: new Date(now()),
      clockTolerance: skew,
      ...(opts.audience && { audience: opts.audience }),
    });
    payload = res.payload as VerdictClaims;
    kid = res.protectedHeader.kid;
  } catch (err) {
    throw mapJoseError(err);
  }

  // 3. iat no more than 60 s in the future; aud only if it names us.
  if (payload.iat! * 1000 > now() + 60_000) throw new VerdictError('iat_in_future');
  if (payload.aud !== undefined && !opts.audience) throw new VerdictError('unexpected_audience');

  // 4. Sandbox kid policy.
  const isSandbox = (kid ?? '').startsWith('sandbox-');
  if (opts.env === 'production' && isSandbox) throw new VerdictError('sandbox_kid_in_production', 'sandbox verdict: never a production approval');
  if (opts.env === 'sandbox' && !isSandbox) throw new VerdictError('production_kid_in_sandbox');

  // 5. Structure of the verdict: an allow, naming a mandate (supersedes therefore only ever on an allow).
  if (payload.verdict !== 'allow') throw new VerdictError('not_allow', `not an approval: ${payload.verdict}`);
  if (!payload.mandate) throw new VerdictError('missing_mandate');
  if (opts.allowedMandates && !opts.allowedMandates.includes(payload.mandate)) throw new VerdictError('mandate_not_permitted');

  // 6. Deal match: amount, currency, recipient must be exactly the deal being settled.
  const r = payload.request;
  if (r.amount > MAX_SAFE_AMOUNT || deal.amount > MAX_SAFE_AMOUNT) throw new VerdictError('amount_too_large');
  if (r.amount !== deal.amount || r.currency !== deal.currency || r.recipient !== deal.recipient) {
    throw new VerdictError('deal_mismatch', 'approval is for a different transaction');
  }

  // 7. Single use. Recorded only after every other check passed; kept until exp + skew.
  const keepUntil = (payload.exp! + skew) * 1000;
  if (!(await opts.nonceStore.claim(payload.nonce, keepUntil))) throw new VerdictError('replayed_nonce');
  if (payload.supersedes && !(await opts.nonceStore.claim(`supersedes:${payload.supersedes}`, keepUntil))) {
    throw new VerdictError('supersedes_replayed');
  }
  return payload;
}

function mapJoseError(err: unknown): VerdictError {
  if (err instanceof errors.JWTExpired) return new VerdictError('expired', err.message);
  if (err instanceof errors.JWSSignatureVerificationFailed) return new VerdictError('bad_signature', err.message);
  if (err instanceof errors.JWKSNoMatchingKey) return new VerdictError('unknown_kid', err.message);
  if (err instanceof errors.JWTClaimValidationFailed) return new VerdictError('claim_invalid', err.message);
  return new VerdictError('malformed_token', (err as Error).message);
}

/** A key getter over a JWKS you hold, refusing a set in which a kid appears twice. */
export function localJwks(jwks: JSONWebKeySet): JWTVerifyGetKey {
  const kids = jwks.keys.map((k) => k.kid);
  if (new Set(kids).size !== kids.length) throw new Error('JWKS contains a duplicate kid');
  return createLocalJWKSet(jwks);
}

/** Remote JWKS with the set's own five-minute cache and the duplicate-kid check. */
export function remoteJwks(url: string = PROD_JWKS_URL, fetchImpl: typeof fetch = fetch): JWTVerifyGetKey {
  let cached: { getter: JWTVerifyGetKey; at: number } | undefined;
  return async (header, token) => {
    if (!cached || Date.now() - cached.at > 300_000) {
      const res = await fetchImpl(url);
      if (!res.ok) throw new Error(`JWKS fetch failed: HTTP ${res.status}`);
      cached = { getter: localJwks((await res.json()) as JSONWebKeySet), at: Date.now() };
    }
    return cached.getter(header, token);
  };
}
