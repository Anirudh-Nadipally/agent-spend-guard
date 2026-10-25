import { describe, expect, it, vi } from 'vitest';
import { MockEngine } from '../src/core/mock-engine.js';
import { SaifuroUnavailableError, type Decision, type SaifuroClient } from '../src/core/types.js';
import { CircuitBreaker } from '../src/guard/circuit-breaker.js';
import { guardedPay, instructionFor, payApproved, type GuardConfig } from '../src/guard/guarded-pay.js';
import { verifyVerdict } from '../src/verify/verify.js';
import { procurement, req, setup } from './helpers.js';

async function guard(mandate: Partial<typeof procurement> = {}, withBreaker = true) {
  const s = await setup(mandate);
  const opts = s.verifyOpts(); // one nonce store for the session
  const onReview = vi.fn();
  const cfg: GuardConfig = {
    client: s.engine,
    verify: (t, d) => verifyVerdict(t, d, opts),
    breaker: withBreaker ? new CircuitBreaker(['recipient', 'category'], s.c.now) : undefined,
    onReview,
  };
  const paid: number[] = [];
  const pay = async (d: Decision) => { paid.push(d.request.amount); return `rcpt_${paid.length}`; };
  return { ...s, cfg, pay, paid, onReview };
}

describe('guardedPay', () => {
  it('pays once on a verified allow', async () => {
    const g = await guard();
    const r = await guardedPay(g.cfg, req(340), g.pay);
    expect(r.status).toBe('paid');
    expect(g.paid).toEqual([340]);
  });

  it('does not pay on a deny, and tells the model not to retry or split', async () => {
    const g = await guard();
    const r = await guardedPay(g.cfg, req(720), g.pay);
    expect(r).toMatchObject({ status: 'denied', verdict: 'deny_limit' });
    expect(g.paid).toEqual([]);
    expect(instructionFor(r)).toMatch(/Do not retry, split/);
  });

  it('fails closed when Saifuro is unreachable', async () => {
    const g = await guard();
    const down: SaifuroClient = { authorize: async () => { throw new SaifuroUnavailableError('ECONNREFUSED'); } };
    const r = await guardedPay({ ...g.cfg, client: down }, req(10), g.pay);
    expect(r.status).toBe('unavailable');
    expect(g.paid).toEqual([]);
  });

  it('does not pay when the allow does not verify for the deal', async () => {
    const g = await guard();
    // A client that returns a genuine allow for $10 when asked about $300.
    const swapping: SaifuroClient = { authorize: async (q) => g.engine.authorize({ ...q, amount: 10 }) };
    const r = await guardedPay({ ...g.cfg, client: swapping }, req(300), g.pay);
    expect(r.status).toBe('invalid_verdict');
    expect(g.paid).toEqual([]);
  });

  it('holds on review, routes it to a human, and pays the approval through verification', async () => {
    const g = await guard({ review_above: 250 });
    const r = await guardedPay(g.cfg, req(400), g.pay);
    expect(r.status).toBe('held_for_review');
    expect(g.onReview).toHaveBeenCalledOnce();
    expect(g.paid).toEqual([]);

    const approval = await g.engine.approveReview((r as any).review.review);
    const p = await payApproved(g.cfg, approval, req(400), g.pay);
    expect(p.status).toBe('paid');
    expect(g.paid).toEqual([400]);
    // the same approval cannot be spent twice
    expect((await payApproved(g.cfg, approval, req(400), g.pay)).status).toBe('invalid_verdict');
  });

  it('observe mode logs what enforce would do and lets the payment through', async () => {
    const g = await guard();
    g.engine.mode = 'observe';
    const r = await guardedPay(g.cfg, req(720), g.pay);
    expect(r).toMatchObject({ status: 'paid_in_observe', wouldHaveBlocked: true });
    expect(g.paid).toEqual([720]);
  });
});

describe('circuit breaker (split retries)', () => {
  it('the structuring observation: without the breaker, 2 x $360 after a denied $720 both pay', async () => {
    const g = await guard({}, false);
    expect((await guardedPay(g.cfg, req(720), g.pay)).status).toBe('denied');
    expect((await guardedPay(g.cfg, req(360), g.pay)).status).toBe('paid');
    expect((await guardedPay(g.cfg, req(360), g.pay)).status).toBe('paid');
    expect(g.paid).toEqual([360, 360]);
  });

  it('with the breaker, the splits are refused before reaching the engine', async () => {
    const g = await guard();
    const spy = vi.spyOn(g.engine, 'authorize');
    await guardedPay(g.cfg, req(720), g.pay);
    const r = await guardedPay(g.cfg, req(360), g.pay);
    expect(r.status).toBe('blocked_by_breaker');
    expect(instructionFor(r)).toMatch(/until a human clears it/);
    expect(spy).toHaveBeenCalledTimes(1);
    expect(g.paid).toEqual([]);
  });

  it('blocks a relabelled category to the same recipient, and the same category to another recipient', async () => {
    const g = await guard();
    await guardedPay(g.cfg, req(120, { recipient: 'vendor:dell', category: 'hardware' }), g.pay);
    expect((await guardedPay(g.cfg, req(120, { recipient: 'vendor:dell', category: 'saas' }), g.pay)).status).toBe('blocked_by_breaker');
    expect((await guardedPay(g.cfg, req(120, { recipient: 'vendor:other', category: 'hardware' }), g.pay)).status).toBe('blocked_by_breaker');
    expect((await guardedPay(g.cfg, req(120, { recipient: 'vendor:acme_saas', category: 'saas' }), g.pay)).status).toBe('paid');
  });

  it('blocks splitting around a pending review', async () => {
    const g = await guard({ review_above: 250 });
    await guardedPay(g.cfg, req(400), g.pay);
    expect((await guardedPay(g.cfg, req(200), g.pay)).status).toBe('blocked_by_breaker');
    expect(g.paid).toEqual([]);
  });

  it('a human clear reopens the recipient and category', async () => {
    const g = await guard();
    await guardedPay(g.cfg, req(720), g.pay);
    g.cfg.breaker!.clear('recipient:vendor:acme_saas');
    expect((await guardedPay(g.cfg, req(360), g.pay)).status).toBe('blocked_by_breaker'); // category still tripped
    g.cfg.breaker!.clear('category:saas');
    expect((await guardedPay(g.cfg, req(360), g.pay)).status).toBe('paid');
  });

  it('does not trip in observe mode, and a recipient-only scope leaves categories open', async () => {
    const engine = await MockEngine.create({ mode: 'observe' });
    engine.addMandate(procurement);
    const b = new CircuitBreaker(['recipient']);
    const cfg: GuardConfig = { client: engine, verify: async () => ({}) as any, breaker: b };
    await guardedPay(cfg, req(720), async () => 'r');
    expect(b.list()).toEqual([]);
    b.trip(req(1), 'deny_limit', 'x');
    expect(b.check(req(1, { recipient: 'vendor:b' }))).toBeUndefined();
  });
});
