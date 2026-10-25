import { decodeJwt, decodeProtectedHeader } from 'jose';
import { describe, expect, it } from 'vitest';
import { SANDBOX_KID } from '../src/core/mock-engine.js';
import { procurement, req, setup } from './helpers.js';

const MIN = 60_000;
const DAY = 24 * 60 * MIN;

describe('MockEngine: every decision code', () => {
  it('allow: inside the mandate, with a 5-minute expiry and a mandate id', async () => {
    const { engine, mandate } = await setup();
    const d = await engine.authorize(req(340));
    expect(d.verdict).toBe('allow');
    expect(d.reason).toBe(`within mandate ${mandate!.mandate}`);
    expect(d.mandate).toBe(mandate!.mandate);
    expect(d.mode).toBe('enforce');
    expect(Date.parse(d.expires_at!) - Date.parse(d.issued_at)).toBe(5 * MIN);
  });

  it('review: above review_above, with a review object waiting 24h for the principal', async () => {
    const { engine } = await setup({ review_above: 250 });
    const d = await engine.authorize(req(400));
    expect(d.verdict).toBe('review');
    expect(d.review?.waits_for).toBe('role:procurement_lead');
    expect(Date.parse(d.review!.expires_at) - Date.parse(d.issued_at)).toBe(DAY);
    expect(d.expires_at).toBeUndefined();
  });

  it('deny_limit: per_transaction, with the documented reason wording', async () => {
    const { engine } = await setup();
    const d = await engine.authorize(req(720));
    expect(d.verdict).toBe('deny_limit');
    expect(d.reason).toBe('amount 720.00 exceeds per_transaction limit 500.00');
    expect(d.expires_at).toBeUndefined();
  });

  it('deny_limit: rolling 30-day per_month counts only allows, and rolls off after 30 days', async () => {
    const { engine, c } = await setup({ limits: { per_transaction: 500, per_month: 1000, currency: 'USD' } });
    expect((await engine.authorize(req(500))).verdict).toBe('allow');
    expect((await engine.authorize(req(720))).verdict).toBe('deny_limit'); // denies do not count toward the month
    expect((await engine.authorize(req(500))).verdict).toBe('allow'); // 1000 total
    expect((await engine.authorize(req(1))).verdict).toBe('deny_limit');
    c.advance(30 * DAY);
    expect((await engine.authorize(req(500))).verdict).toBe('allow');
  });

  it('deny_velocity: the 11th decision inside 60 s, recovering after the window', async () => {
    const { engine, c } = await setup();
    for (let i = 0; i < 10; i++) expect((await engine.authorize(req(1))).verdict).toBe('allow');
    expect((await engine.authorize(req(1))).verdict).toBe('deny_velocity');
    c.advance(60_000);
    expect((await engine.authorize(req(1))).verdict).toBe('allow');
  });

  it('deny_category: names the category', async () => {
    const { engine } = await setup();
    const d = await engine.authorize(req(10, { category: 'hardware' }));
    expect(d.verdict).toBe('deny_category');
    expect(d.reason).toContain('hardware');
  });

  it('deny_expired: after the mandate date has passed', async () => {
    const { engine } = await setup({ expires: '2026-10-24' });
    expect((await engine.authorize(req(10))).verdict).toBe('deny_expired');
  });

  it('deny_revoked: effective on the next request', async () => {
    const { engine, mandate } = await setup();
    expect((await engine.authorize(req(10))).verdict).toBe('allow');
    engine.revokeMandate(mandate!.mandate);
    expect((await engine.authorize(req(10))).verdict).toBe('deny_revoked');
  });

  it('deny_no_mandate: no mandate at all, wrong currency, or agent disabled; no mandate field', async () => {
    const none = await setup(null);
    const d = await none.engine.authorize(req(10));
    expect(d.verdict).toBe('deny_no_mandate');
    expect(d.mandate).toBeUndefined();

    const { engine } = await setup();
    expect((await engine.authorize(req(10, { currency: 'usd' }))).verdict).toBe('deny_no_mandate'); // case-sensitive
    engine.disableAgent();
    expect((await engine.authorize(req(10))).verdict).toBe('deny_no_mandate');
  });
});

describe('MockEngine: documented check order', () => {
  it('revoked beats expired, category and limit', async () => {
    const { engine, mandate } = await setup({ expires: '2026-10-24' });
    engine.revokeMandate(mandate!.mandate);
    expect((await engine.authorize(req(9999, { category: 'hardware' }))).verdict).toBe('deny_revoked');
  });

  it('expired beats category', async () => {
    const { engine } = await setup({ expires: '2026-10-24' });
    expect((await engine.authorize(req(10, { category: 'hardware' }))).verdict).toBe('deny_expired');
  });

  it('category beats limit', async () => {
    const { engine } = await setup();
    expect((await engine.authorize(req(9999, { category: 'hardware' }))).verdict).toBe('deny_category');
  });

  it('limit beats velocity, velocity beats review', async () => {
    const { engine } = await setup({ review_above: 250 });
    for (let i = 0; i < 10; i++) await engine.authorize(req(1));
    expect((await engine.authorize(req(720))).verdict).toBe('deny_limit');
    expect((await engine.authorize(req(400))).verdict).toBe('deny_velocity');
  });

  it('several mandates: first allow, else first review, else the oldest result', async () => {
    const { engine } = await setup({ categories: ['travel'] }); // oldest: would deny_category
    engine.addMandate({ ...procurement, review_above: 100 }); // would review
    engine.addMandate({ ...procurement }); // would allow
    expect((await engine.authorize(req(200))).verdict).toBe('allow');

    const two = await setup({ categories: ['travel'] });
    two.engine.addMandate({ ...procurement, review_above: 100 });
    expect((await two.engine.authorize(req(200))).verdict).toBe('review');
    expect((await two.engine.authorize(req(10, { category: 'food' }))).verdict).toBe('deny_category');
  });
});

describe('MockEngine: reviews', () => {
  it('approve issues a fresh allow with a new nonce, its own expiry and supersedes', async () => {
    const { engine, c, verify } = await setup({ review_above: 250 });
    const r = await engine.authorize(req(400));
    c.advance(10 * MIN);
    const a = await engine.approveReview(r.review!.review);
    expect(a.verdict).toBe('allow');
    expect(a.supersedes).toBe(r.decision);
    expect(a.nonce).not.toBe(r.nonce);
    expect(Date.parse(a.expires_at!) - Date.parse(a.issued_at)).toBe(5 * MIN);
    const claims = await verify(a.verdict_token, req(400));
    expect(claims.supersedes).toBe(r.decision);
  });

  it('a review yields at most one allow, and deny closes it', async () => {
    const { engine } = await setup({ review_above: 250 });
    const r1 = await engine.authorize(req(400));
    await engine.approveReview(r1.review!.review);
    await expect(engine.approveReview(r1.review!.review)).rejects.toThrow(/invalid_request/);
    const r2 = await engine.authorize(req(400));
    engine.denyReview(r2.review!.review);
    await expect(engine.approveReview(r2.review!.review)).rejects.toThrow(/invalid_request/);
  });

  it('approval expires after 24h and re-checks revocation', async () => {
    const { engine, c } = await setup({ review_above: 250 });
    const r1 = await engine.authorize(req(400));
    c.advance(DAY + 1);
    await expect(engine.approveReview(r1.review!.review)).rejects.toThrow(/not pending/);

    const fresh = await setup({ review_above: 250 });
    const r2 = await fresh.engine.authorize(req(400));
    fresh.engine.revokeMandate(fresh.mandate!.mandate);
    await expect(fresh.engine.approveReview(r2.review!.review)).rejects.toThrow(/revoked/);
  });

  it('approval re-checks per_month', async () => {
    const { engine } = await setup({ review_above: 250, limits: { per_transaction: 500, per_month: 600, currency: 'USD' } });
    const r = await engine.authorize(req(400));
    expect((await engine.authorize(req(250))).verdict).toBe('allow'); // 250 spent
    await expect(engine.approveReview(r.review!.review)).rejects.toThrow(/per_month/);
  });
});

describe('MockEngine: tokens and idempotency', () => {
  it('signs ES256 with kid sandbox-local; the token carries request, verdict, mandate, nonce, exp = iat + 300', async () => {
    const { engine, mandate } = await setup();
    const d = await engine.authorize(req(340));
    const h = decodeProtectedHeader(d.verdict_token);
    expect(h).toMatchObject({ alg: 'ES256', kid: SANDBOX_KID });
    const p = decodeJwt(d.verdict_token) as any;
    expect(p).toMatchObject({ iss: 'https://verdicts.saifuro.com', jti: d.decision, verdict: 'allow', mandate: mandate!.mandate, nonce: d.nonce });
    expect(p.request).toEqual(d.request);
    expect(p.exp - p.iat).toBe(300);
    expect(p.reason).toBeUndefined(); // reason and mode are not signed
    expect(engine.jwks.keys[0]).toMatchObject({ kid: SANDBOX_KID, alg: 'ES256', kty: 'EC', crv: 'P-256' });
  });

  it('same Idempotency-Key returns the same decision and is not evaluated twice', async () => {
    const { engine } = await setup({ limits: { per_transaction: 500, per_month: 500, currency: 'USD' } });
    const a = await engine.authorize(req(500), { idempotencyKey: 'k1' });
    const b = await engine.authorize(req(500), { idempotencyKey: 'k1' });
    expect(b).toBe(a);
    expect((await engine.authorize(req(1))).verdict).toBe('deny_limit');
  });
});
