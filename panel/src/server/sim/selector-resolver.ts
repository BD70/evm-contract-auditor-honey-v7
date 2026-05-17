// Selector → signature resolver.
//
// The decompiler can't always extract argument types from stripped bytecode,
// so we frequently end up with `argTypes=[]` and our calldata is just N
// zero-padded uint256 slots. That works for primitive forwarders, but it
// catastrophically fails for any function with a DYNAMIC argument (`bytes`,
// `address[]`, structs): the ABI decoder reads the zero slot as an OFFSET,
// follows it to invalid memory, and reverts with empty `0x` — BEFORE the
// function body runs. We never reach the auth check, never reach the call
// site, and the verifier records a vague "execution reverted" with no
// insight. This was the #1 source of false negatives on real-world
// vulnerable contracts (e.g. Symbiosis MetaRouter externalCall).
//
// We resolve the selector against:
//   1. A local SQLite cache (panel/data/findings.db.selector_signatures).
//   2. openchain.xyz signature database (public, no auth, ~1k req/min).
//   3. 4byte.directory (fallback; same data, slower).
//
// Each result is cached for 30 days. Misses are also cached (negative cache,
// 7 days) so we don't hammer the API on every verifier run for the same
// unknown selectors.

import { rawDb } from "@/src/db/client";

const POSITIVE_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const NEGATIVE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const FETCH_TIMEOUT_MS = 5_000;

interface Row {
  selector: string;
  signatures_json: string | null;
  fetched_at: number;
  source: string | null;
}

let installed = false;
function ensureTable() {
  if (installed) return;
  rawDb.exec(
    `CREATE TABLE IF NOT EXISTS selector_signatures (
       selector TEXT PRIMARY KEY,
       signatures_json TEXT,
       fetched_at INTEGER NOT NULL,
       source TEXT
     )`,
  );
  installed = true;
}

export interface ResolvedSignature {
  selector: string;            // 0x-prefixed, 10 chars total
  name: string;                 // e.g. "externalCall"
  argTypes: string[];           // e.g. ["address","uint256","address","bytes","uint256","address"]
  raw: string;                  // e.g. "externalCall(address,uint256,address,bytes,uint256,address)"
  source: "cache" | "openchain" | "4byte";
}

/**
 * Look up signatures for a 4-byte selector. Returns ALL matches (a selector
 * is just keccak[:4]; collisions exist), sorted with the most specific
 * (most arg types resolved) first. Returns empty array if the selector is
 * truly unknown.
 */
export async function resolveSelector(selector: string): Promise<ResolvedSignature[]> {
  ensureTable();
  const sel = normalize(selector);
  if (!sel) return [];

  const cached = readCache(sel);
  if (cached && Date.now() - cached.fetched_at < (cached.signatures_json ? POSITIVE_TTL_MS : NEGATIVE_TTL_MS)) {
    return parseCached(cached);
  }

  let sigs: string[] = [];
  let source: "openchain" | "4byte" = "openchain";
  try {
    sigs = await fetchOpenchain(sel);
  } catch {
    /* fall back to 4byte */
  }
  if (sigs.length === 0) {
    try {
      sigs = await fetch4byte(sel);
      source = "4byte";
    } catch {
      /* both failed */
    }
  }

  // Write to cache (positive OR negative).
  try {
    rawDb
      .prepare(
        `INSERT OR REPLACE INTO selector_signatures
           (selector, signatures_json, fetched_at, source)
         VALUES (?, ?, ?, ?)`,
      )
      .run(sel, sigs.length > 0 ? JSON.stringify(sigs) : null, Date.now(), source);
  } catch {
    /* cache write failure is non-fatal */
  }

  return sigs.map((sig) => parseSignature(sel, sig, source)).filter((x): x is ResolvedSignature => x !== null);
}

/**
 * Bulk resolver: takes many selectors at once and returns a map.
 * Internally batched (chunks of 8) to keep concurrency bounded.
 */
export async function resolveSelectors(selectors: string[]): Promise<Map<string, ResolvedSignature[]>> {
  const out = new Map<string, ResolvedSignature[]>();
  const unique = Array.from(new Set(selectors.map(normalize).filter(Boolean) as string[]));
  const CHUNK = 8;
  for (let i = 0; i < unique.length; i += CHUNK) {
    const chunk = unique.slice(i, i + CHUNK);
    await Promise.all(
      chunk.map(async (sel) => {
        try {
          out.set(sel, await resolveSelector(sel));
        } catch {
          out.set(sel, []);
        }
      }),
    );
  }
  return out;
}

function readCache(sel: string): Row | undefined {
  try {
    return rawDb
      .prepare(`SELECT selector, signatures_json, fetched_at, source FROM selector_signatures WHERE selector = ?`)
      .get(sel) as Row | undefined;
  } catch {
    return undefined;
  }
}

function parseCached(row: Row): ResolvedSignature[] {
  if (!row.signatures_json) return [];
  try {
    const arr = JSON.parse(row.signatures_json) as string[];
    return arr
      .map((s) => parseSignature(row.selector, s, "cache"))
      .filter((x): x is ResolvedSignature => x !== null);
  } catch {
    return [];
  }
}

async function fetchOpenchain(sel: string): Promise<string[]> {
  const url = `https://api.openchain.xyz/signature-database/v1/lookup?function=${sel}`;
  const res = await fetchWithTimeout(url);
  if (!res.ok) throw new Error(`openchain ${res.status}`);
  const j: any = await res.json();
  if (!j?.ok) return [];
  const matches = j?.result?.function?.[sel];
  if (!Array.isArray(matches)) return [];
  return matches.map((m) => String(m?.name ?? "")).filter(Boolean);
}

async function fetch4byte(sel: string): Promise<string[]> {
  const url = `https://www.4byte.directory/api/v1/signatures/?hex_signature=${sel}&format=json`;
  const res = await fetchWithTimeout(url);
  if (!res.ok) throw new Error(`4byte ${res.status}`);
  const j: any = await res.json();
  const results = Array.isArray(j?.results) ? j.results : [];
  return results
    .sort((a: any, b: any) => (a?.id ?? 0) - (b?.id ?? 0))
    .map((r: any) => String(r?.text_signature ?? ""))
    .filter(Boolean);
}

async function fetchWithTimeout(url: string): Promise<Response> {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), FETCH_TIMEOUT_MS);
  try {
    return await fetch(url, { signal: c.signal, headers: { Accept: "application/json" } });
  } finally {
    clearTimeout(t);
  }
}

function normalize(s: string): string | null {
  const c = (s || "").trim().toLowerCase();
  if (!c) return null;
  const hex = c.startsWith("0x") ? c.slice(2) : c;
  if (!/^[0-9a-f]{8}$/.test(hex)) return null;
  return "0x" + hex;
}

/**
 * Parse a canonical signature string like `transfer(address,uint256)` into
 * its name and argument-type list. Handles tuple types `(a,b)` by collapsing
 * to a single `(a,b)` string in the list — the verifier expands tuples to
 * their leaves before encoding.
 */
export function parseSignature(selector: string, raw: string, source: "cache" | "openchain" | "4byte"): ResolvedSignature | null {
  const r = String(raw || "").trim();
  if (!r) return null;
  const m = /^([A-Za-z_][A-Za-z0-9_$]*)\s*\((.*)\)$/.exec(r);
  if (!m) return null;
  const name = m[1];
  const inner = m[2];
  const argTypes = splitTopLevel(inner);
  return { selector, name, argTypes, raw: r, source };
}

/**
 * Split a comma-separated arg list at top-level (not inside parens / brackets).
 * `(a,b),uint256[3],bytes` -> ["(a,b)", "uint256[3]", "bytes"]
 */
function splitTopLevel(s: string): string[] {
  if (!s.trim()) return [];
  const out: string[] = [];
  let depth = 0;
  let buf = "";
  for (const ch of s) {
    if (ch === "(" || ch === "[") depth++;
    else if (ch === ")" || ch === "]") depth--;
    if (ch === "," && depth === 0) {
      if (buf.trim()) out.push(buf.trim());
      buf = "";
      continue;
    }
    buf += ch;
  }
  if (buf.trim()) out.push(buf.trim());
  return out;
}
