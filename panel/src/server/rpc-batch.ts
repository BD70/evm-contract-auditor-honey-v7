// Shared JSON-RPC helpers for the exposure pipeline (token-discovery,
// token-metadata, token-pricing).
//
// Why this file exists: the existing `panel/src/server/exposure.ts` has a
// private `rpcCall` for single requests, but the exposure-accuracy pipeline
// (token-discovery + metadata + pricing) batches dozens of `eth_call` per
// contract and benefits from JSON-RPC's batch-array support — one HTTP
// round-trip instead of N. We also need a strict request budget to honour
// the user's "don't spam" constraint:
//
//   - eth_getLogs   : 1 per cold contract discovery
//   - eth_call      : 1 batch per cold contract (balanceOf for all candidates)
//   - eth_call      : 1 batch per cold token (symbol/name/decimals, 3 sub-calls)
//   - coingecko     : 1 batch per chain per 60 min (price for all live tokens)
//
// Numbers stay in the single digits per fresh contract; cache hits cost ZERO
// network. See docs/UPDATES_2026-05-17-part3.md for the rate-budget math.

const RPC_TIMEOUT_MS = Number(process.env.EXPOSURE_RPC_TIMEOUT_MS ?? 8_000);
const MAX_BATCH_SIZE = Number(process.env.EXPOSURE_RPC_BATCH_SIZE ?? 50);

export interface JsonRpcCall {
  method: string;
  params: unknown[];
}

export interface JsonRpcSingleResult<T> {
  ok: boolean;
  value?: T;
  error?: string;
}

/** Single JSON-RPC call. Returns parsed result OR an error string. */
export async function rpcSingle<T>(
  url: string,
  method: string,
  params: unknown[],
  timeoutMs: number = RPC_TIMEOUT_MS,
): Promise<JsonRpcSingleResult<T>> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      signal: ac.signal,
    });
    if (!r.ok) return { ok: false, error: `HTTP ${r.status}` };
    const j: any = await r.json();
    if (j.error) return { ok: false, error: j.error?.message ?? "rpc error" };
    return { ok: true, value: j.result as T };
  } catch (err: any) {
    return { ok: false, error: String(err?.message ?? err) };
  } finally {
    clearTimeout(t);
  }
}

/** Batched JSON-RPC. Splits into MAX_BATCH_SIZE chunks. Returns per-call
 * results in input order. Network/parse failure for the WHOLE batch
 * surfaces as individual errors so the caller can degrade gracefully. */
export async function rpcBatch<T>(
  url: string,
  calls: JsonRpcCall[],
  timeoutMs: number = RPC_TIMEOUT_MS,
): Promise<JsonRpcSingleResult<T>[]> {
  if (calls.length === 0) return [];
  const out: JsonRpcSingleResult<T>[] = new Array(calls.length);
  for (let off = 0; off < calls.length; off += MAX_BATCH_SIZE) {
    const slice = calls.slice(off, off + MAX_BATCH_SIZE);
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), timeoutMs);
    try {
      const body = slice.map((c, i) => ({
        jsonrpc: "2.0",
        id: off + i,
        method: c.method,
        params: c.params,
      }));
      const r = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: ac.signal,
      });
      if (!r.ok) {
        for (let i = 0; i < slice.length; i++) out[off + i] = { ok: false, error: `HTTP ${r.status}` };
        continue;
      }
      const j: any = await r.json();
      const arr = Array.isArray(j) ? j : [j];
      // Map id → batch result (some providers don't preserve order)
      const byId = new Map<number, any>();
      for (const item of arr) byId.set(Number(item?.id ?? -1), item);
      for (let i = 0; i < slice.length; i++) {
        const id = off + i;
        const item = byId.get(id);
        if (!item) {
          out[id] = { ok: false, error: "no response for id" };
          continue;
        }
        if (item.error) {
          out[id] = { ok: false, error: item.error?.message ?? "rpc error" };
        } else {
          out[id] = { ok: true, value: item.result as T };
        }
      }
    } catch (err: any) {
      for (let i = 0; i < slice.length; i++) {
        out[off + i] = { ok: false, error: String(err?.message ?? err) };
      }
    } finally {
      clearTimeout(t);
    }
  }
  return out;
}

/** Hex-encode an address as 32-byte topic (zero-padded). */
export function addressToTopic(addr: string): string {
  const clean = addr.replace(/^0x/, "").toLowerCase();
  return "0x" + clean.padStart(64, "0");
}

/** Decode a topic-encoded address (last 20 bytes). */
export function topicToAddress(topic: string): string {
  return "0x" + topic.replace(/^0x/, "").slice(-40).toLowerCase();
}

/** Decode an ABI-encoded uint256 from a hex string. Returns 0n on error. */
export function decodeUint256(hex: string | null | undefined): bigint {
  if (!hex || typeof hex !== "string") return 0n;
  try {
    const s = hex.startsWith("0x") ? hex : "0x" + hex;
    return BigInt(s);
  } catch {
    return 0n;
  }
}

/** Decode an ABI-encoded string from a hex word (handles both packed-bytes32
 * and dynamic-string variants — older tokens like MKR pack the symbol). */
export function decodeAbiString(hex: string | null | undefined): string | null {
  if (!hex || typeof hex !== "string") return null;
  const raw = hex.replace(/^0x/, "");
  if (raw.length === 0) return null;
  // Dynamic string: [offset 32B][length 32B][data...]
  if (raw.length >= 128) {
    try {
      const lenHex = raw.slice(64, 128);
      const len = Number(BigInt("0x" + lenHex));
      if (len > 0 && len <= 256 && raw.length >= 128 + len * 2) {
        const dataHex = raw.slice(128, 128 + len * 2);
        const bytes = Buffer.from(dataHex, "hex");
        const s = bytes.toString("utf8").replace(/\0+$/, "").trim();
        if (s && /^[\x20-\x7E]+$/.test(s)) return s;
      }
    } catch {
      /* fall through to bytes32 path */
    }
  }
  // Packed bytes32 (e.g. MKR, REP). Strip trailing zeros.
  try {
    const bytes = Buffer.from(raw.slice(0, 64), "hex");
    const s = bytes.toString("utf8").replace(/\0+$/, "").trim();
    if (s && /^[\x20-\x7E]+$/.test(s)) return s;
  } catch {
    /* ignore */
  }
  return null;
}

/** Decode a uint8 (decimals). Returns null on failure. */
export function decodeUint8(hex: string | null | undefined): number | null {
  const v = decodeUint256(hex);
  if (v < 0n || v > 64n) return null;
  return Number(v);
}
