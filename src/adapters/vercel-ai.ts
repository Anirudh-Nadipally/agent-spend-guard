// Vercel AI SDK adapter: wrap any payment tool so it can only execute through guardedPay.
//
//   const pay = tool({ description, inputSchema, execute: async (input) => rail.charge(input) });
//   const tools = { pay: withSpendGuard(pay, guardConfig) };
//
// The model never sees an exception. A non-allow comes back as a structured result whose
// `instruction` tells it plainly to stop, not retry or split, and ask the user.
import type { Tool } from 'ai';
import type { AuthorizationRequest } from '../core/types.js';
import { guardedPay, instructionFor, type GuardConfig } from '../guard/guarded-pay.js';

export interface SpendGuardToolResult {
  status: string;
  verdict?: string;
  reason?: string;
  review?: string;
  instruction: string;
  result?: unknown;
}

/** Default mapping: the tool input already carries amount, currency, recipient, category. */
const defaultToRequest = (input: any): AuthorizationRequest => ({
  amount: input.amount,
  currency: input.currency,
  recipient: input.recipient,
  category: input.category,
});

export function withSpendGuard<INPUT, OUTPUT>(
  original: Tool<INPUT, OUTPUT>,
  cfg: GuardConfig,
  toRequest: (input: INPUT) => AuthorizationRequest = defaultToRequest,
): Tool<INPUT, SpendGuardToolResult> {
  const execute = original.execute;
  if (!execute) throw new Error('withSpendGuard needs a tool with an execute function');

  return {
    ...original,
    execute: async (input: INPUT, options: any): Promise<SpendGuardToolResult> => {
      const result = await guardedPay(cfg, toRequest(input), async () => execute(input, options) as Promise<OUTPUT>);
      const base = { status: result.status, instruction: instructionFor(result) };
      switch (result.status) {
        case 'paid':
        case 'paid_in_observe':
          return { ...base, result: result.receipt };
        case 'denied':
          return { ...base, verdict: result.verdict, reason: result.reason };
        case 'held_for_review':
          return { ...base, verdict: 'review', reason: result.reason, review: result.review.review };
        case 'blocked_by_breaker':
          return { ...base, verdict: result.trip.verdict, reason: result.trip.reason };
        default:
          return base;
      }
    },
  } as Tool<INPUT, SpendGuardToolResult>;
}
