// ERC-20 token-discovery for a contract via a SINGLE eth_getLogs call
// followed by ONE batched balanceOf round-trip.
//
// Why this exists: the user's QuickNode plan doesn't have the
// `qn_getWalletTokenBalance` add-on enabled, so `exposure.ts` was
// falling back to native-only data and the token column was always
// empty in the UI. We replace the fallback path with an RPC-only
// discovery flow that works on every chain we have an endpoint for.
//
// Rate budget per cold contract:
//   1 × eth_getLogs    (one chunk; fromBlock = deploymentBlock if known,
//                       else `latest - DISCOVERY_WINDOW_BLOCKS`)
//   1 × eth_call batch (balanceOf for every unique token; bounded to
//                       MAX_TOKENS_PER_CONTRACT)
//   1 × eth_call batch (metadata for tokens we haven't seen yet, via
//                       token-metadata.ts — cached forever after warmup)
//
// Cache hits (TTL ≈ 30 min via contract_token_holdings) cost ZERO network.

import { rawDb } from "@/src/db/client";
import { rpcSingle, rpcBatch, addressToTopic, topicToAddress, decodeUint256 } from "./rpc-batch";
import { getTokenMetadata, type TokenMetadata } from "./token-metadata";

const DISCOVERY_WINDOW_BLOCKS = Number(process.env.EXPOSURE_DISCOVERY_WINDOW ?? 5_000_000);
const HOLDINGS_TTL_MS = Number(process.env.EXPOSURE_HOLDINGS_TTL_MS ?? 30 * 60_000);
const MAX_TOKENS_PER_CONTRACT = Number(process.env.EXPOSURE_MAX_TOKENS_PER_CONTRACT ?? 40);

const TOPIC_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

// 0x70a08231 = balanceOf(address)
const SEL_BALANCE_OF = "0x70a08231";

function balanceOfData(holder: string): string {
  return SEL_BALANCE_OF + holder.replace(/^0x/, "").toLowerCase().padStart(64, "0");
}

export interface DiscoveredHolding {
  tokenAddress: string;
  balance: string;        // base units, decimal string
  metadata: TokenMetadata; // symbol / name / decimals
}

interface CachedRow {
  token_address: string;
  balance_base: string;
  discovered_at: number;
}

function readCache(chainId: number, contract: string): { rows: CachedRow[]; freshAt: number } | null {
  const rows = rawDb
    .prepare(
      `SELECT token_address, balance_base, discovered_at
       FROM contract_token_holdings
       WHERE chain_id = ? AND contract_address = ?
       ORDER BY discovered_at DESC`,
    )
    .all(chainId, contract.toLowerCase()) as CachedRow[];
  if (rows.length === 0) return null;
  const freshAt = rows[0].discovered_at;
  if (Date.now() - freshAt > HOLDINGS_TTL_MS) return null;
  return { rows, freshAt };
}

function writeCache(chainId: number, contract: string, holdings: DiscoveredHolding[], block: number | null) {
  const now = Date.now();
  const del = rawDb.prepare(`DELETE FROM contract_token_holdings WHERE chain_id = ? AND contract_address = ?`);
  const ins = rawDb.prepare(
    `INSERT INTO contract_token_holdings
       (chain_id, contract_address, token_address, balance_base, last_seen_block, discovered_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
  );
  const tx = rawDb.transaction(() => {
    del.run(chainId, contract.toLowerCase());
    for (const h of holdings) {
      ins.run(chainId, contract.toLowerCase(), h.tokenAddress.toLowerCase(), h.balance, block, now);
    }
    if (holdings.length === 0) {
      // Insert a sentinel so a contract with NO tokens doesn't keep
      // re-running the log scan on every exposure check. Sentinel uses
      // the zero token address with balance "0".
      ins.run(chainId, contract.toLowerCase(), "0x0000000000000000000000000000000000000000", "0", block, now);
    }
  });
  tx();
}

async function deploymentBlockOf(chainId: number, contract: string): Promise<number | null> {
  // We persist deployment info in the `deployments` table when the runner
  // observes a creation tx. Use it as the eth_getLogs fromBlock so we
  // never scan more history than necessary.
  const row = rawDb
    .prepare(
      `SELECT block_number AS bn FROM deployments
       WHERE chain_id = ? AND lower(contract_address) = ?
       ORDER BY block_number ASC LIMIT 1`,
    )
    .get(chainId, contract.toLowerCase()) as { bn: number | null } | undefined;
  return row?.bn ?? null;
}

/**
 * Discover all ERC-20s the contract has received tokens of, then snapshot
 * each balance. Returns the live holdings (balance > 0) plus the metadata.
 *
 * Pass `force=true` to bypass the 30-min cache.
 */
export async function discoverHoldings(
  rpcUrl: string,
  chainId: number,
  contract: string,
  options: { force?: boolean } = {},
): Promise<{
  holdings: DiscoveredHolding[];
  fromBlock: number | null;
  cached: boolean;
  scannedChunks: number;
  source: "log-scan" | "cache" | "no-rpc";
}> {
  if (!rpcUrl) return { holdings: [], fromBlock: null, cached: false, scannedChunks: 0, source: "no-rpc" };

  // Cache hit.
  if (!options.force) {
    const c = readCache(chainId, contract);
    if (c) {
      const tokenAddrs = c.rows.map((r) => r.token_address).filter((a) => a !== "0x0000000000000000000000000000000000000000");
      const meta = await getTokenMetadata(rpcUrl, chainId, tokenAddrs);
      const holdings: DiscoveredHolding[] = [];
      for (const r of c.rows) {
        if (r.token_address === "0x0000000000000000000000000000000000000000") continue;
        const m = meta.get(r.token_address);
        if (!m) continue;
        if (r.balance_base === "0") continue;
        holdings.push({ tokenAddress: r.token_address, balance: r.balance_base, metadata: m });
      }
      return { holdings, fromBlock: null, cached: true, scannedChunks: 0, source: "cache" };
    }
  }

  // 1. Resolve fromBlock.
  let fromBlock = await deploymentBlockOf(chainId, contract);
  if (fromBlock == null) {
    const head = await rpcSingle<string>(rpcUrl, "eth_blockNumber", []);
    if (head.ok && head.value) {
      const headN = Number(BigInt(head.value));
      fromBlock = Math.max(0, headN - DISCOVERY_WINDOW_BLOCKS);
    } else {
      fromBlock = 0;
    }
  }

  // 2. ONE eth_getLogs call. Topic[2] = padded contract address (recipient).
  const logsRes = await rpcSingle<Array<{ address: string; blockNumber: string }>>(rpcUrl, "eth_getLogs", [
    {
      fromBlock: "0x" + fromBlock.toString(16),
      toBlock: "latest",
      topics: [TOPIC_TRANSFER, null, addressToTopic(contract)],
    },
  ]);

  if (!logsRes.ok || !Array.isArray(logsRes.value)) {
    // Persist an empty sentinel so we don't keep retrying every refresh —
    // this typically fires when an RPC rejects unbounded eth_getLogs.
    writeCache(chainId, contract, [], null);
    return { holdings: [], fromBlock, cached: false, scannedChunks: 0, source: "log-scan" };
  }

  // 3. Deduplicate token addresses (capped).
  const unique = new Set<string>();
  let lastBlock: number | null = null;
  for (const log of logsRes.value) {
    if (!log?.address) continue;
    unique.add(log.address.toLowerCase());
    if (log.blockNumber) lastBlock = Number(BigInt(log.blockNumber));
    if (unique.size >= MAX_TOKENS_PER_CONTRACT) break;
  }

  if (unique.size === 0) {
    writeCache(chainId, contract, [], lastBlock);
    return { holdings: [], fromBlock, cached: false, scannedChunks: 1, source: "log-scan" };
  }

  // 4. Batched balanceOf for each unique token.
  const tokens = Array.from(unique);
  const balanceCalls = tokens.map((t) => ({
    method: "eth_call",
    params: [{ to: t, data: balanceOfData(contract) }, "latest"],
  }));
  const balRes = await rpcBatch<string>(rpcUrl, balanceCalls);

  const nonZero: { addr: string; bal: bigint }[] = [];
  for (let i = 0; i < tokens.length; i++) {
    const r = balRes[i];
    if (!r?.ok) continue;
    const bal = decodeUint256(r.value as string);
    if (bal > 0n) nonZero.push({ addr: tokens[i], bal });
  }

  if (nonZero.length === 0) {
    writeCache(chainId, contract, [], lastBlock);
    return { holdings: [], fromBlock, cached: false, scannedChunks: 1, source: "log-scan" };
  }

  // 5. Fetch metadata (cached forever).
  const meta = await getTokenMetadata(rpcUrl, chainId, nonZero.map((x) => x.addr));
  const holdings: DiscoveredHolding[] = nonZero
    .map(({ addr, bal }) => {
      const m = meta.get(addr);
      if (!m) return null;
      return { tokenAddress: addr, balance: bal.toString(), metadata: m };
    })
    .filter((x): x is DiscoveredHolding => x != null)
    // Sort by raw balance desc as a coarse proxy until pricing layer reorders
    .sort((a, b) => (BigInt(b.balance) > BigInt(a.balance) ? 1 : -1));

  writeCache(chainId, contract, holdings, lastBlock);
  return { holdings, fromBlock, cached: false, scannedChunks: 1, source: "log-scan" };
}

/** Used by /api/exposure/refresh to manually invalidate the cache. */
export function invalidateHoldings(chainId: number, contract: string): void {
  rawDb
    .prepare(`DELETE FROM contract_token_holdings WHERE chain_id = ? AND contract_address = ?`)
    .run(chainId, contract.toLowerCase());
}

/** Topic helper re-exported for use elsewhere in the panel. */
export { topicToAddress };
