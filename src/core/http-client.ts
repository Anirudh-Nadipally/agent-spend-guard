// HttpClient for the documented endpoint POST https://api.saifuro.com/v1/authorizations.
//
// UNTESTED AGAINST THE REAL API. Saifuro issues keys only at onboarding and there is no
// public sandbox, so this file has only been exercised against a fake fetch in the tests.
// It follows https://docs.saifuro.com/api/authorizations and nothing more.
import { randomUUID } from 'node:crypto';
import { SaifuroUnavailableError, type AuthorizationRequest, type Decision, type SaifuroClient } from './types.js';

export interface HttpClientOptions {
  apiKey: string; // ak_live_..., ak_sandbox_..., or an org key
  baseUrl?: string;
  timeoutMs?: number;
  fetch?: typeof fetch;
}

export class HttpClient implements SaifuroClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly opts: HttpClientOptions) {
    this.baseUrl = opts.baseUrl ?? 'https://api.saifuro.com';
    this.timeoutMs = opts.timeoutMs ?? 10_000;
    this.fetchImpl = opts.fetch ?? fetch;
  }

  async authorize(req: AuthorizationRequest, opts: { idempotencyKey?: string } = {}): Promise<Decision> {
    let res: Response;
    try {
      res = await this.fetchImpl(`${this.baseUrl}/v1/authorizations`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.opts.apiKey}`,
          'Idempotency-Key': opts.idempotencyKey ?? randomUUID(),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(req),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (err) {
      throw new SaifuroUnavailableError(`saifuro unreachable: ${(err as Error).message}`);
    }
    // A decision is 201 whatever the verdict; anything else means we have no verdict.
    if (res.status !== 201 && res.status !== 200) {
      throw new SaifuroUnavailableError(`saifuro returned HTTP ${res.status}`, res.status);
    }
    return (await res.json()) as Decision;
  }
}
