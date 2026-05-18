// Shared JSON helpers for the simulation layer.
//
// `safeStringify` is JSON.stringify with bigint support. Verifier evidence
// frequently includes bigints (totalSupply, balances, allowances, calldata
// sizes); without coercion the cache write throws
// `TypeError: Do not know how to serialize a BigInt`, drops the cache entry,
// and forces the heavy verifier to re-run on every poll.

export function safeStringify(value: unknown): string {
  return JSON.stringify(value, (_k, v) => (typeof v === "bigint" ? v.toString() : v));
}
