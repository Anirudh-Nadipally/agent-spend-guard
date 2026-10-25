import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { tool } from 'ai';
import { describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import { withSpendGuard } from '../src/adapters/vercel-ai.js';
import { HttpClient } from '../src/core/http-client.js';
import { SaifuroUnavailableError } from '../src/core/types.js';
import { CircuitBreaker } from '../src/guard/circuit-breaker.js';
import { createSpendGuardMcpServer } from '../src/mcp/server.js';
import { verifyVerdict } from '../src/verify/verify.js';
import { req, setup } from './helpers.js';

describe('Vercel AI SDK adapter: withSpendGuard', () => {
  async function wrapped() {
    const s = await setup();
    const opts = s.verifyOpts();
    const charge = vi.fn(async (input: any) => ({ charged: input.amount }));
    const pay = tool({
      description: 'pay a vendor',
      inputSchema: z.object({ amount: z.number(), currency: z.string(), recipient: z.string(), category: z.string() }),
      execute: charge,
    });
    const guarded = withSpendGuard(pay, { client: s.engine, verify: (t, d) => verifyVerdict(t, d, opts), breaker: new CircuitBreaker() });
    const call = (input: any) => guarded.execute!(input, { toolCallId: 'c', messages: [] } as any) as Promise<any>;
    return { guarded, call, charge };
  }

  it('keeps the original description and schema, and executes on allow', async () => {
    const { guarded, call, charge } = await wrapped();
    expect(guarded.description).toBe('pay a vendor');
    const r = await call(req(340));
    expect(r).toMatchObject({ status: 'paid', result: { charged: 340 } });
    expect(charge).toHaveBeenCalledOnce();
  });

  it('returns a readable refusal on deny and on a split retry, never executing', async () => {
    const { call, charge } = await wrapped();
    const d = await call(req(720));
    expect(d).toMatchObject({ status: 'denied', verdict: 'deny_limit' });
    expect(d.instruction).toMatch(/^denied: deny_limit .*Do not retry, split/);
    const s = await call(req(360));
    expect(s).toMatchObject({ status: 'blocked_by_breaker', verdict: 'deny_limit' });
    expect(charge).not.toHaveBeenCalled();
  });
});

describe('MCP server: request_spend_authorization', () => {
  async function connect(client?: any) {
    const s = await setup();
    const server = createSpendGuardMcpServer(client ?? s.engine);
    const [a, b] = InMemoryTransport.createLinkedPair();
    const mcp = new Client({ name: 'test', version: '0' });
    await Promise.all([server.connect(a), mcp.connect(b)]);
    const call = async (args: any) => JSON.parse(((await mcp.callTool({ name: 'request_spend_authorization', arguments: args })) as any).content[0].text);
    return { mcp, call };
  }

  it('lists the tool and returns a signed allow', async () => {
    const { mcp, call } = await connect();
    expect((await mcp.listTools()).tools.map((t) => t.name)).toEqual(['request_spend_authorization']);
    const r = await call(req(340));
    expect(r.verdict).toBe('allow');
    expect(r.verdict_token.split('.')).toHaveLength(3);
  });

  it('denies $720 and refuses the 2 x $360 split', async () => {
    const { call } = await connect();
    expect((await call(req(720))).verdict).toBe('deny_limit');
    expect((await call(req(360))).verdict).toBe('blocked_by_guard');
  });

  it('reports unavailable as an error with no verdict', async () => {
    const { call } = await connect({ authorize: async () => { throw new SaifuroUnavailableError('down'); } });
    expect((await call(req(10))).verdict).toBe('unavailable');
  });
});

describe('HttpClient (fake fetch only; untested against the real API)', () => {
  it('POSTs the documented body with Bearer and Idempotency-Key, and returns the 201 decision', async () => {
    const fetch = vi.fn(async () => new Response(JSON.stringify({ verdict: 'deny_limit' }), { status: 201 }));
    const c = new HttpClient({ apiKey: 'ak_sandbox_x', fetch: fetch as any });
    const d = await c.authorize(req(720), { idempotencyKey: 'order-1' });
    expect(d.verdict).toBe('deny_limit');
    const [url, init] = fetch.mock.calls[0] as any;
    expect(url).toBe('https://api.saifuro.com/v1/authorizations');
    expect(init.method).toBe('POST');
    expect(init.headers).toMatchObject({ Authorization: 'Bearer ak_sandbox_x', 'Idempotency-Key': 'order-1' });
    expect(JSON.parse(init.body)).toEqual(req(720));
  });

  it('maps non-2xx and network errors to SaifuroUnavailableError', async () => {
    const c500 = new HttpClient({ apiKey: 'k', fetch: (async () => new Response('', { status: 503 })) as any });
    await expect(c500.authorize(req(1))).rejects.toBeInstanceOf(SaifuroUnavailableError);
    const cNet = new HttpClient({ apiKey: 'k', fetch: (async () => { throw new TypeError('fetch failed'); }) as any });
    await expect(cNet.authorize(req(1))).rejects.toBeInstanceOf(SaifuroUnavailableError);
  });
});
