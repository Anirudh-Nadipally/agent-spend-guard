import { MockEngine } from '../src/core/mock-engine.js';
import type { AuthorizationRequest, Mandate } from '../src/core/types.js';
import { InMemoryNonceStore, localJwks, verifyVerdict, type VerifyOptions } from '../src/verify/verify.js';

export const T0 = Date.parse('2026-10-25T12:00:00Z');

export function clock(start = T0) {
  let t = start;
  return { now: () => t, advance: (ms: number) => { t += ms; } };
}

export const procurement: Omit<Mandate, 'mandate' | 'status' | 'created_at' | 'agent'> = {
  principal: 'role:procurement_lead',
  limits: { per_transaction: 500, per_month: 5000, currency: 'USD' },
  categories: ['saas'],
  expires: '2099-12-31',
};

export const req = (amount: number, over: Partial<AuthorizationRequest> = {}): AuthorizationRequest => ({
  amount,
  currency: 'USD',
  recipient: 'vendor:acme_saas',
  category: 'saas',
  ...over,
});

export async function setup(mandate: Partial<typeof procurement> | null = {}) {
  const c = clock();
  const engine = await MockEngine.create({ now: c.now });
  const m = mandate === null ? undefined : engine.addMandate({ ...procurement, ...mandate });
  const verifyOpts = (over: Partial<VerifyOptions> = {}): VerifyOptions => ({
    keys: localJwks(engine.jwks),
    env: 'sandbox',
    nonceStore: new InMemoryNonceStore(c.now),
    now: c.now,
    ...over,
  });
  return { c, engine, mandate: m, verifyOpts, verify: (token: string, deal: any, over: Partial<VerifyOptions> = {}) => verifyVerdict(token, deal, verifyOpts(over)) };
}
