import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import { describe, expect, it } from 'vitest';
import { InMemoryNonceStore, VerdictError, localJwks, verifyVerdict } from '../src/verify/verify.js';
import { T0, req, setup } from './helpers.js';

async function expectCode(p: Promise<unknown>, code: string) {
  await expect(p).rejects.toBeInstanceOf(VerdictError);
  await expect(p).rejects.toMatchObject({ code });
}

/** Signs an arbitrary verdict with a fresh key and kid, for cases the engine never produces. */
async function forge(claims: Record<string, unknown>, opts: { kid?: string; iat?: number } = {}) {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const kid = opts.kid ?? 'verdict-2026-10';
  const iat = opts.iat ?? Math.floor(T0 / 1000);
  const token = await new SignJWT({ verdict: 'allow', mandate: 'mnd_x', policy_version: 'p', nonce: 'n_1', request: { agent: 'a', ...req(100) }, ...claims })
    .setProtectedHeader({ alg: 'ES256', kid })
    .setIssuer('https://verdicts.saifuro.com')
    .setIssuedAt(iat)
    .setExpirationTime(iat + 300)
    .sign(privateKey);
  const jwks = { keys: [{ ...(await exportJWK(publicKey)), kid, alg: 'ES256' }] };
  return { token, jwks };
}

describe('verifyVerdict', () => {
  it('accepts a fresh allow for exactly the deal', async () => {
    const { engine, verify } = await setup();
    const d = await engine.authorize(req(340));
    const claims = await verify(d.verdict_token, req(340));
    expect(claims.nonce).toBe(d.nonce);
  });

  it('rejects a tampered token (payload edited, signature kept)', async () => {
    const { engine, verify } = await setup();
    const d = await engine.authorize(req(340));
    const [h, p, s] = d.verdict_token.split('.');
    const payload = JSON.parse(Buffer.from(p, 'base64url').toString());
    payload.request.amount = 3400;
    const tampered = [h, Buffer.from(JSON.stringify(payload)).toString('base64url'), s].join('.');
    await expectCode(verify(tampered, req(3400)), 'bad_signature');
  });

  it('rejects a signature from another key under the same kid', async () => {
    const { verifyOpts } = await setup();
    const { token } = await forge({}, { kid: 'sandbox-local' });
    await expectCode(verifyVerdict(token, req(100), verifyOpts()), 'bad_signature');
  });

  it('rejects the wrong amount, currency or recipient', async () => {
    const { engine, verify } = await setup();
    const d = await engine.authorize(req(340));
    await expectCode(verify(d.verdict_token, req(341)), 'deal_mismatch');
    await expectCode(verify(d.verdict_token, req(340, { currency: 'USDC' })), 'deal_mismatch');
    await expectCode(verify(d.verdict_token, req(340, { recipient: 'vendor:evil' })), 'deal_mismatch');
  });

  it('rejects a replayed nonce, and only records it after every other check passed', async () => {
    const { engine, verifyOpts } = await setup();
    const opts = verifyOpts();
    const d = await engine.authorize(req(340));
    await expectCode(verifyVerdict(d.verdict_token, req(999), opts), 'deal_mismatch'); // failed check: nonce not burnt
    await verifyVerdict(d.verdict_token, req(340), opts);
    await expectCode(verifyVerdict(d.verdict_token, req(340), opts), 'replayed_nonce');
  });

  it('rejects an expired approval (after 5 minutes plus skew)', async () => {
    const { engine, verify, c } = await setup();
    const d = await engine.authorize(req(340));
    c.advance(5 * 60_000 + 31_000);
    await expectCode(verify(d.verdict_token, req(340)), 'expired');
  });

  it('rejects a sandbox kid in production mode', async () => {
    const { engine, verify } = await setup();
    const d = await engine.authorize(req(340));
    await expectCode(verify(d.verdict_token, req(340), { env: 'production' }), 'sandbox_kid_in_production');
  });

  it('rejects a production kid in sandbox mode', async () => {
    const { token, jwks } = await forge({});
    const opts = { keys: localJwks(jwks), env: 'sandbox' as const, nonceStore: new InMemoryNonceStore(), now: () => T0 };
    await expectCode(verifyVerdict(token, req(100), opts), 'production_kid_in_sandbox');
    await expect(verifyVerdict(token, req(100), { ...opts, env: 'production' })).resolves.toBeTruthy();
  });

  it('rejects a deny verdict token (signed, but not an approval)', async () => {
    const { engine, verify } = await setup();
    const d = await engine.authorize(req(720));
    await expectCode(verify(d.verdict_token, req(720)), 'not_allow');
  });

  it('rejects an allow without a mandate, and a mandate the operator did not give', async () => {
    const noMandate = await forge({ mandate: undefined });
    const opts = { keys: localJwks(noMandate.jwks), env: 'production' as const, nonceStore: new InMemoryNonceStore(), now: () => T0 };
    await expectCode(verifyVerdict(noMandate.token, req(100), opts), 'missing_mandate');
    const other = await forge({});
    await expectCode(verifyVerdict(other.token, req(100), { ...opts, keys: localJwks(other.jwks), allowedMandates: ['mnd_mine'] }), 'mandate_not_permitted');
  });

  it('rejects a second allow superseding a review already accepted', async () => {
    const a = await forge({ supersedes: 'dec_rev1', nonce: 'n_a' });
    const store = new InMemoryNonceStore(() => T0);
    const opts = { keys: localJwks(a.jwks), env: 'production' as const, nonceStore: store, now: () => T0 };
    await verifyVerdict(a.token, req(100), opts);
    const b = await forge({ supersedes: 'dec_rev1', nonce: 'n_b' });
    await expectCode(verifyVerdict(b.token, req(100), { ...opts, keys: localJwks(b.jwks) }), 'supersedes_replayed');
  });

  it('rejects iat more than 60 s in the future, and an aud that does not name us', async () => {
    const future = await forge({}, { iat: Math.floor(T0 / 1000) + 120 });
    const opts = { keys: localJwks(future.jwks), env: 'production' as const, nonceStore: new InMemoryNonceStore(), now: () => T0 };
    await expectCode(verifyVerdict(future.token, req(100), opts), 'iat_in_future');
    const aud = await forge({ aud: 'someone-else' });
    await expectCode(verifyVerdict(aud.token, req(100), { ...opts, keys: localJwks(aud.jwks) }), 'unexpected_audience');
  });

  it('rejects malformed, padded or oversized tokens, and a JWKS with a duplicate kid', async () => {
    const { engine, verify } = await setup();
    const d = await engine.authorize(req(340));
    await expectCode(verify('a.b', req(340)), 'malformed_token');
    await expectCode(verify(d.verdict_token.replace('.', '=.'), req(340)), 'malformed_token');
    await expectCode(verify(d.verdict_token.replace('.', ' .'), req(340)), 'malformed_token');
    await expectCode(verify('a'.repeat(9000), req(340)), 'token_too_large');
    expect(() => localJwks({ keys: [engine.jwks.keys[0], engine.jwks.keys[0]] })).toThrow(/duplicate kid/);
  });
});
