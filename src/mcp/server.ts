// MCP server exposing one tool, `request_spend_authorization`, usable from any MCP client.
// It asks the configured SaifuroClient (mock or HTTP) and applies the same circuit breaker,
// so an agent cannot structure a denied amount into smaller requests through MCP either.
// It does not move money: the caller presents the returned verdict_token to whoever settles.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { SaifuroUnavailableError, type SaifuroClient } from '../core/types.js';
import { CircuitBreaker } from '../guard/circuit-breaker.js';

export function createSpendGuardMcpServer(client: SaifuroClient, breaker = new CircuitBreaker()): McpServer {
  const server = new McpServer({ name: 'agent-spend-guard', version: '0.0.1' });

  server.registerTool(
    'request_spend_authorization',
    {
      description:
        'Ask for authorization before spending. Pay only if verdict is "allow", and only the exact amount, currency and recipient approved. ' +
        'On any other verdict: stop, do not retry, split or relabel, and ask the user.',
      inputSchema: {
        amount: z.number().positive(),
        currency: z.string().max(128),
        recipient: z.string().max(1024),
        category: z.string().max(128),
        protocol: z.string().optional(),
        metadata: z.record(z.string(), z.string()).optional(),
      },
    },
    async (req) => {
      const reply = (body: object, isError = false) => ({
        content: [{ type: 'text' as const, text: JSON.stringify(body) }],
        structuredContent: body as Record<string, unknown>,
        isError,
      });

      const trip = breaker.check(req);
      if (trip) {
        return reply({ verdict: 'blocked_by_guard', reason: `earlier ${trip.verdict} on ${trip.key}: ${trip.reason}`, instruction: 'Do not retry. Ask the user.' });
      }
      try {
        const d = await client.authorize(req);
        if (d.verdict !== 'allow' && d.mode === 'enforce') breaker.trip(req, d.verdict, d.reason);
        const instruction =
          d.verdict === 'allow'
            ? `Approved for exactly ${d.request.amount} ${d.request.currency} to ${d.request.recipient}, until ${d.expires_at}.`
            : d.verdict === 'review'
              ? `Held for human review (${d.review?.review}). Do not pay, retry or split. Tell the user.`
              : `Denied (${d.verdict}). Do not retry, split or relabel. Ask the user.`;
        return reply({
          verdict: d.verdict,
          reason: d.reason,
          decision: d.decision,
          mandate: d.mandate,
          mode: d.mode,
          expires_at: d.expires_at,
          review: d.review,
          verdict_token: d.verdict_token,
          instruction,
        });
      } catch (err) {
        const msg = err instanceof SaifuroUnavailableError ? err.message : (err as Error).message;
        return reply({ verdict: 'unavailable', reason: msg, instruction: 'No verdict: do not pay. Tell the user.' }, true);
      }
    },
  );

  return server;
}
