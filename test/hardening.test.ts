// Tests for the 2026-10-28 audit fixes: concurrency, payment failure, input validation.
import { describe, expect, it, vi } from 'vitest';
import type { Decision } from '../src/core/types.js';
import { CircuitBreaker } from '../src/guard/circuit-breaker.js';
import { PaymentDeclinedError, guardedPay, instructionFor, type GuardConfig } from '../src/guard/guarded-pay.js';
import { verifyVerdict } from '../src/verify/verify.js';
import { req, setup } from './helpers.js';

async function guard(mandate = {}) {
  const s = await setup(mandate);
  const opts = s.verifyOpts();
  const cfg: GuardConfig = {
    client: s.engine,
    verify: (t, d) => verifyVerdict(t, d, opts),
    breaker: new CircuitBreaker(['recipient', 'category'], s.c.now),
  };
  const paid: number[] = [];
  const pay = async (d: Decision) => { paid.push(d.request.amount); return 'rcpt'; };
  return { ...s, cfg, pay, paid };
}

describe('concurrency', () => {
  it('a denied $720 fired in parallel with 2 x $360 does not let the splits through', async () => {
    const g = await guard();
    const results = await Promise.all([req(720), req(360), req(360)].map((r) => guardedPay(g.cfg, r, g.pay)));
    expect(results.map((r) => r.status)).toEqual(['denied', 'blocked_by_breaker', 'blocked_by_breaker']);
    expect(g.paid).toEqual([]);
  });

  it('requests to unrelated recipients and categories still run in parallel', async () => {
    const g = await guard();
    g.engine.addMandate({ principal: 'p', limits: { per_transaction: 500, currency: 'USD' }, categories: ['hardware'], expires: '2099-12-31' });
    let inFlight = 0;
    let maxInFlight = 0;
    const slowPay = async (d: Decision) => {
      inFlight++; maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((r) => setTimeout(r, 20));
      inFlight--; return d.request.amount;
    };
    await Promise.all([
      guardedPay(g.cfg, req(100), slowPay),
      guardedPay(g.cfg, req(100, { recipient: 'vendor:dell', category: 'hardware' }), slowPay),
    ]);
    expect(maxInFlight).toBe(2);
  });

  it('the lock is released when a payment throws', async () => {
    const g = await guard();
    const boom = async () => { throw new Error('rail timeout'); };
    await guardedPay(g.cfg, req(100), boom);
    g.cfg.breaker!.clear();
    const r = await Promise.race([
      guardedPay(g.cfg, req(100), g.pay),
      new Promise((res) => setTimeout(() => res({ status: 'deadlock' }), 500)),
    ]);
    expect((r as any).status).toBe('paid');
  });
});

describe('payment failure after an allow', () => {
  it('an unknown failure is reported, not thrown, and closes the payee until reconciled', async () => {
    const g = await guard();
    const r = await guardedPay(g.cfg, req(100), async () => { throw new Error('socket hang up'); }, { idempotencyKey: 'intent_1' });
    expect(r).toMatchObject({ status: 'pay_outcome_unknown', idempotencyKey: 'intent_1' });
    expect(instructionFor(r)).toMatch(/may have settled/);
    // the agent's natural retry is refused locally, so it cannot double-pay
    expect((await guardedPay(g.cfg, req(100), g.pay)).status).toBe('blocked_by_breaker');
    expect(g.paid).toEqual([]);
  });

  it('a definite decline is reported and does not close the payee', async () => {
    const g = await guard();
    const r = await guardedPay(g.cfg, req(100), async () => { throw new PaymentDeclinedError('insufficient_funds'); });
    expect(r).toMatchObject({ status: 'pay_declined' });
    expect((await guardedPay(g.cfg, req(100), g.pay)).status).toBe('paid');
  });

  it('passes one idempotency key to both the authorization and the payment rail', async () => {
    const g = await guard();
    const spy = vi.spyOn(g.engine, 'authorize');
    const seen: string[] = [];
    await guardedPay(g.cfg, req(100), async (_d, ctx) => { seen.push(ctx.idempotencyKey); return 'r'; }, { idempotencyKey: 'intent_42' });
    expect(spy).toHaveBeenCalledWith(expect.anything(), { idempotencyKey: 'intent_42' });
    expect(seen).toEqual(['intent_42']);
  });

  it('generates a key when the caller gives none', async () => {
    const g = await guard();
    const seen: string[] = [];
    await guardedPay(g.cfg, req(100), async (_d, ctx) => { seen.push(ctx.idempotencyKey); return 'r'; });
    expect(seen[0]).toMatch(/^[0-9a-f-]{36}$/);
  });
});

describe('input validation', () => {
  it.each([0, -100, Number.NaN, Number.POSITIVE_INFINITY])('refuses amount %s before asking Saifuro', async (amount) => {
    const g = await guard();
    const spy = vi.spyOn(g.engine, 'authorize');
    const r = await guardedPay(g.cfg, req(amount), g.pay);
    expect(r.status).toBe('invalid_request');
    expect(spy).not.toHaveBeenCalled();
  });

  it('the mock engine itself rejects a negative amount instead of lowering the monthly total', async () => {
    const g = await guard();
    await expect(g.engine.authorize(req(-4000))).rejects.toThrow(/invalid_request/);
  });

  it('amount matching is exact: float drift fails closed', async () => {
    const g = await guard();
    const d = await g.engine.authorize(req(0.3));
    await expect(verifyVerdict(d.verdict_token, req(0.1 + 0.2), g.verifyOpts())).rejects.toMatchObject({ code: 'deal_mismatch' });
  });
});
