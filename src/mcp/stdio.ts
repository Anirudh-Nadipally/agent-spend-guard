#!/usr/bin/env node
// stdio entry for MCP clients (Claude Desktop, Cursor, etc.).
// With SAIFURO_API_KEY set it uses the (untested) HttpClient; otherwise a local MockEngine
// with one demo mandate: USD, saas, per_transaction 500, per_month 5000, review_above 250.
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { HttpClient } from '../core/http-client.js';
import { MockEngine } from '../core/mock-engine.js';
import type { SaifuroClient } from '../core/types.js';
import { createSpendGuardMcpServer } from './server.js';

async function main() {
  let client: SaifuroClient;
  if (process.env.SAIFURO_API_KEY) {
    client = new HttpClient({ apiKey: process.env.SAIFURO_API_KEY, baseUrl: process.env.SAIFURO_BASE_URL });
    console.error('[agent-spend-guard] using HttpClient (UNTESTED against the real API)');
  } else {
    const engine = await MockEngine.create();
    engine.addMandate({
      principal: 'role:procurement_lead',
      limits: { per_transaction: 500, per_month: 5000, currency: 'USD' },
      categories: ['saas'],
      review_above: 250,
      expires: '2099-12-31',
    });
    client = engine;
    console.error('[agent-spend-guard] using local MockEngine (not Saifuro)');
  }
  await createSpendGuardMcpServer(client).connect(new StdioServerTransport());
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
