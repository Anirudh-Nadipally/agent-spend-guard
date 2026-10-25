// Session-level circuit breaker against structuring ("split retries").
//
// Why: per_transaction is checked per request. A denied $720 against a $500 cap can be
// re-asked as 2 x $360 and both pass every documented check (per_month and velocity
// permitting). Saifuro cannot know the second request is the first one in pieces; the
// integration can. After a non-allow for a recipient or category, every further pay to
// that recipient or category is refused locally until a human clears it.

export type BreakerScope = 'recipient' | 'category';

export interface Trip {
  key: string;
  verdict: string;
  reason: string;
  at: number;
}

export class CircuitBreaker {
  private trips = new Map<string, Trip>();

  constructor(
    private readonly scopes: BreakerScope[] = ['recipient', 'category'],
    private readonly now: () => number = Date.now,
  ) {}

  private keys(req: { recipient: string; category: string }): string[] {
    return this.scopes.map((s) => (s === 'recipient' ? `recipient:${req.recipient}` : `category:${req.category}`));
  }

  /** Returns the trip that blocks this request, if any. */
  check(req: { recipient: string; category: string }): Trip | undefined {
    for (const key of this.keys(req)) {
      const trip = this.trips.get(key);
      if (trip) return trip;
    }
    return undefined;
  }

  trip(req: { recipient: string; category: string }, verdict: string, reason: string): void {
    for (const key of this.keys(req)) {
      if (!this.trips.has(key)) this.trips.set(key, { key, verdict, reason, at: this.now() });
    }
  }

  /** Human action: clear one key (e.g. "recipient:vendor:acme_saas"), or everything. */
  clear(key?: string): void {
    if (key) this.trips.delete(key);
    else this.trips.clear();
  }

  list(): Trip[] {
    return [...this.trips.values()];
  }
}
