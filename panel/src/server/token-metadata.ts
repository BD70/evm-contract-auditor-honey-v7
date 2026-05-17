// ERC-20 metadata cache: (chainId, tokenAddress) → { symbol, name, decimals }.
//
// Why: ERC-20 metadata is immutable for the lifetime of the contract, so
// after warmup this cache covers ~all common tokens (USDC, USDT, WETH,
// WBNB, ...) for zero RPC across all contracts that hold them. This is the
// largest single contributor to "don't spam requests" — without it every
// new finding would re-fetch the same USDC metadata over and over.
//
// Storage: `token_metadata` table in findings.db, primary key
// (chain_id, token_address). Schema in db/client.ts.

import { rawDb } from "@/src/db/client";
import { rpcBatch, decodeAbiString, decodeUint8 } from "./rpc-batch";

export interface TokenMetadata {
  chainId: number;
  address: string;
  symbol: string;
  name: string;
  decimals: number;
}

const ZERO_ADDR = "0x0000000000000000000000000000000000000000";

// 4-byte selectors for ERC-20 metadata. Keccak-256 of:
//   symbol() / name() / decimals()
const SEL_SYMBOL = "0x95d89b41";
const SEL_NAME = "0x06fdde03";
const SEL_DECIMALS = "0x313ce567";

function selectMany(chainId: number, addresses: string[]): TokenMetadata[] {
  if (addresses.length === 0) return [];
  const placeholders = addresses.map(() => "?").join(",");
  const rows = rawDb
    .prepare(
      `SELECT chain_id AS chainId, token_address AS address, symbol, name, decimals
       FROM token_metadata
       WHERE chain_id = ? AND token_address IN (${placeholders})`,
    )
    .all(chainId, ...addresses.map((a) => a.toLowerCase())) as TokenMetadata[];
  return rows;
}

function upsertOne(row: TokenMetadata, now: number) {
  rawDb
    .prepare(
      `INSERT OR REPLACE INTO token_metadata
         (chain_id, token_address, symbol, name, decimals, fetched_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    )
    .run(row.chainId, row.address, row.symbol, row.name, row.decimals, now);
}

/** Fetch metadata for a set of tokens. Returns cached entries instantly,
 * fetches missing ones via batched eth_call, and persists the results
 * permanently (ERC-20 metadata is immutable so we never TTL these). */
export async function getTokenMetadata(
  rpcUrl: string,
  chainId: number,
  addresses: string[],
): Promise<Map<string, TokenMetadata>> {
  const out = new Map<string, TokenMetadata>();
  const norm = Array.from(new Set(addresses.map((a) => a.toLowerCase()).filter((a) => /^0x[0-9a-f]{40}$/.test(a) && a !== ZERO_ADDR)));
  if (norm.length === 0) return out;

  // 1. Pull whatever's in the cache.
  const cached = selectMany(chainId, norm);
  for (const r of cached) out.set(r.address.toLowerCase(), r);

  const missing = norm.filter((a) => !out.has(a));
  if (missing.length === 0) return out;

  // 2. Batch fetch symbol/name/decimals for the misses.
  // Layout: per token we issue 3 sub-calls; the response is in input order.
  const calls = missing.flatMap((addr) => [
    { method: "eth_call", params: [{ to: addr, data: SEL_SYMBOL }, "latest"] },
    { method: "eth_call", params: [{ to: addr, data: SEL_NAME }, "latest"] },
    { method: "eth_call", params: [{ to: addr, data: SEL_DECIMALS }, "latest"] },
  ]);
  const results = await rpcBatch<string>(rpcUrl, calls);

  const now = Date.now();
  const tx = rawDb.transaction((rows: TokenMetadata[]) => {
    for (const r of rows) upsertOne(r, now);
  });
  const toWrite: TokenMetadata[] = [];
  for (let i = 0; i < missing.length; i++) {
    const addr = missing[i];
    const sym = results[i * 3]?.ok ? decodeAbiString(results[i * 3].value as string) : null;
    const nam = results[i * 3 + 1]?.ok ? decodeAbiString(results[i * 3 + 1].value as string) : null;
    const dec = results[i * 3 + 2]?.ok ? decodeUint8(results[i * 3 + 2].value as string) : null;
    // Skip if we couldn't determine decimals — almost certainly not a valid
    // ERC-20 (could be an NFT or random contract logging Transfer-shaped
    // events). We don't want bogus rows polluting the price step.
    if (dec == null) continue;
    const row: TokenMetadata = {
      chainId,
      address: addr,
      symbol: sym ?? `TKN-${addr.slice(2, 6)}`,
      name: nam ?? "Unknown Token",
      decimals: dec,
    };
    out.set(addr, row);
    toWrite.push(row);
  }
  if (toWrite.length > 0) tx(toWrite);
  return out;
}
