// Opt-in: NETWORK_TESTS=1 npx vitest run test/docs-token.network.test.ts
// Checks our verifier against Saifuro's REAL published JWKS using the sample token printed on
// https://docs.saifuro.com/reference/verify-a-verdict (signed by a docs script, not issued by the API).
// Per the docs it verifies with the clock pinned to 2026-09-03T08:45Z, then fails the currency
// comparison because it predates signed currency. Skipped in CI so CI stays offline and deterministic.
import { describe, expect, it } from 'vitest';
import { InMemoryNonceStore, remoteJwks, verifyVerdict } from '../src/verify/verify.js';

const DOCS_TOKEN =
  'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InZlcmRpY3QtMjAyNi0wOSJ9.eyJpc3MiOiJodHRwczovL3ZlcmRpY3RzLnNhaWZ1cm8uY29tIiwianRpIjoiZGVjXzViMmUiLCJpYXQiOjE3ODg0MjQ5ODAsImV4cCI6MTc4ODQyNTI4MCwidmVyZGljdCI6ImFsbG93IiwibWFuZGF0ZSI6Im1uZF83ZjNhIiwicG9saWN5X3ZlcnNpb24iOiJwb2xfMjAyNi0wOC0xMi4zIiwibm9uY2UiOiJuXzlkMDJjNmU0IiwicmVxdWVzdCI6eyJhZ2VudCI6ImFndF9wcm9jdXJlbWVudF8wMSIsImFtb3VudCI6MzQwLCJyZWNpcGllbnQiOiJ2ZW5kb3I6YWNtZV9zYWFzIiwiY2F0ZWdvcnkiOiJzYWFzIn19.oV4a02jtE2oEKvnSXxQ-YqJcpp8UvFZiuh3AeTb5Iy5Ony9jC1AA7EX-YPSKDuSFPxSNS4SlXLtU9-j0J36cbQ';

describe.skipIf(!process.env.NETWORK_TESTS)('docs sample token against the real JWKS', () => {
  const opts = (now: number) => ({ keys: remoteJwks(), env: 'production' as const, nonceStore: new InMemoryNonceStore(), now: () => now });

  it('signature verifies (clock pinned), then the deal check rejects it for missing currency', async () => {
    const p = verifyVerdict(DOCS_TOKEN, { amount: 340, currency: 'USD', recipient: 'vendor:acme_saas' }, opts(Date.parse('2026-09-03T08:45:00Z')));
    await expect(p).rejects.toMatchObject({ code: 'deal_mismatch' });
  });

  it('fails on exp today', async () => {
    const p = verifyVerdict(DOCS_TOKEN, { amount: 340, currency: 'USD', recipient: 'vendor:acme_saas' }, opts(Date.now()));
    await expect(p).rejects.toMatchObject({ code: 'expired' });
  });
});
