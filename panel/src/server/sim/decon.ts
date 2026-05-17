// Wraps the `evm-decon` Go binary to extract per-function entry selectors and
// argument counts from runtime bytecode. Cached by bytecode hash since the
// result is purely a function of the bytecode.

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { resolveAuditorBin } from "../auditor-bin";

const DECON_TIMEOUT_MS = Number(process.env.SIM_DECON_TIMEOUT_MS ?? 30_000);

export interface DeconFunction {
  selector: string | null;
  name: string | null;
  argCount: number;
  argTypes: string[];
  mutability: string | null;
  behaviorTags: string[];
}

export interface DeconResult {
  bytecodeHash: string;
  functions: DeconFunction[];
  contractFamily: string | null;
  globalTags: string[];
}

type Globals = { __deconCache?: Map<string, DeconResult>; __deconInflight?: Map<string, Promise<DeconResult>> };
const g = globalThis as unknown as Globals;
if (!g.__deconCache) g.__deconCache = new Map();
if (!g.__deconInflight) g.__deconInflight = new Map();
const cache = g.__deconCache!;
const inflight = g.__deconInflight!;

function bytecodeKey(bytecodeHex: string): string {
  // hash of the bytecode itself rather than relying on caller-supplied hash —
  // we want decon results keyed independently of how the runner labels them.
  return createHash("sha256").update(bytecodeHex.toLowerCase()).digest("hex");
}

export async function deconBytecode(bytecodeHex: string): Promise<DeconResult> {
  const key = bytecodeKey(bytecodeHex);
  const cached = cache.get(key);
  if (cached) return cached;
  const pending = inflight.get(key);
  if (pending) return pending;
  const p = runDecon(bytecodeHex, key);
  inflight.set(key, p);
  try {
    const res = await p;
    cache.set(key, res);
    return res;
  } finally {
    inflight.delete(key);
  }
}

async function runDecon(bytecodeHex: string, key: string): Promise<DeconResult> {
  if (!bytecodeHex || bytecodeHex === "0x" || bytecodeHex === "0x0") {
    return { bytecodeHash: key, functions: [], contractFamily: null, globalTags: [] };
  }
  const bin = resolveAuditorBin("evm-decon");
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "evm-decon-"));
  const hexPath = path.join(tempDir, "runtime.hex");
  await writeFile(hexPath, bytecodeHex);
  try {
    const out = await new Promise<string>((resolve, reject) => {
      const proc = spawn(bin, ["--file", hexPath, "--format", "json", "--no-resolve", "--no-profiles"], {
        stdio: ["ignore", "pipe", "pipe"],
      });
      let stdout = "";
      let stderr = "";
      const t = setTimeout(() => {
        try { proc.kill("SIGKILL"); } catch {}
        reject(new Error(`decon timeout after ${DECON_TIMEOUT_MS}ms`));
      }, DECON_TIMEOUT_MS);
      proc.stdout?.on("data", (b) => (stdout += b.toString("utf8")));
      proc.stderr?.on("data", (b) => (stderr += b.toString("utf8")));
      proc.once("error", (e) => {
        clearTimeout(t);
        reject(e);
      });
      proc.once("exit", (code) => {
        clearTimeout(t);
        if (code !== 0) {
          reject(new Error(`decon exit ${code}; stderr=${stderr.slice(0, 400)}`));
        } else {
          resolve(stdout);
        }
      });
    });
    return parseDeconOutput(out, key);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

function parseDeconOutput(stdout: string, key: string): DeconResult {
  let parsed: any;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return { bytecodeHash: key, functions: [], contractFamily: null, globalTags: [] };
  }
  const rawFns = Array.isArray(parsed?.functions) ? parsed.functions : [];
  const functions: DeconFunction[] = [];
  const seen = new Set<string>();
  for (const fn of rawFns) {
    const identity = fn?.identity ?? {};
    const sel = typeof identity.selector === "string" ? identity.selector.toLowerCase() : null;
    if (!sel) continue;
    if (seen.has(sel)) continue;
    seen.add(sel);
    const argTypes: string[] = Array.isArray(identity.arg_types) ? identity.arg_types.map(String) : [];
    const argCount = typeof identity.arg_count === "number" ? identity.arg_count : argTypes.length;
    const tags = Array.isArray(fn?.behavior_tags) ? fn.behavior_tags.map(String) : [];
    functions.push({
      selector: sel,
      name: typeof identity.name === "string" ? identity.name : null,
      argCount,
      argTypes,
      mutability: typeof identity.mutability === "string" ? identity.mutability : null,
      behaviorTags: tags,
    });
  }
  const family = typeof parsed?.contract?.family === "string" ? parsed.contract.family : null;
  const globalTags = Array.isArray(parsed?.global_tags) ? parsed.global_tags.map(String) : [];
  return {
    bytecodeHash: key,
    functions,
    contractFamily: family,
    globalTags,
  };
}

/**
 * Heuristic ranking of candidate entry selectors most likely to expose the
 * arbitrary-call vulnerability. Higher score = try first.
 *
 * We do NOT filter out functions with `argCount == 0` because evm-decon
 * cannot reliably recover arg counts from raw bytecode (it commonly reports
 * 0 even for functions with multiple parameters). Instead we enrich each
 * function with a "tryArgCount" used by the driver — extracted from the
 * resolved name signature when present, otherwise defaulting to a 4-arg
 * probe with the candidate address swept across every position.
 */
export function rankExploitCandidates(fns: DeconFunction[]): DeconFunction[] {
  return [...fns]
    .map(enrichFromName)
    .filter((fn) => fn.mutability !== "view" && fn.mutability !== "pure")
    .sort((a, b) => score(b) - score(a));
}

/**
 * If the resolved name contains a signature `foo(uint256,address)`, parse
 * out the types and update argCount/argTypes. evm-decon emits names from
 * its bundled 4byte database when resolution succeeds, so this recovers the
 * real ABI for ~70% of selectors on mainstream contracts. Falls back to a
 * generic 4-arg probe when the name is missing or anonymous.
 */
function enrichFromName(fn: DeconFunction): DeconFunction {
  if (fn.argCount > 0 && fn.argTypes.length > 0) return fn;
  const name = fn.name ?? "";
  const m = /^[A-Za-z0-9_$]+\(([^)]*)\)$/.exec(name);
  if (m) {
    const inside = m[1].trim();
    if (inside === "") return fn; // truly 0-arg
    const types = inside.split(",").map((s) => s.trim());
    return { ...fn, argCount: types.length, argTypes: types };
  }
  // Unknown signature: assume up to 4 args, address candidate swept across.
  return { ...fn, argCount: Math.max(fn.argCount, 4), argTypes: fn.argTypes.length ? fn.argTypes : [] };
}

function score(fn: DeconFunction): number {
  let s = 0;
  if (fn.argCount >= 2) s += 10;
  if (fn.argCount >= 3) s += 2;
  if (fn.argTypes.includes("address")) s += 5;
  if (fn.argTypes.includes("bytes")) s += 6;
  if (fn.mutability === "payable") s += 1;
  // Heuristic boost: function names that look like forwarders/executors are
  // the most likely culprits. We use the resolved name when present.
  const lname = (fn.name ?? "").toLowerCase();
  if (/(execute|forward|call|relay|invoke|delegate|dispatch|aggregate|proxy|multicall)/.test(lname)) s += 8;
  // Bias against known-safe selectors (transferOwnership, approve, etc.) — they
  // take an address but don't forward calls.
  const SAFE_SELECTORS = new Set([
    "0xf2fde38b", // transferOwnership(address)
    "0x095ea7b3", // approve(address,uint256)
    "0xa9059cbb", // transfer(address,uint256)
    "0x23b872dd", // transferFrom(address,address,uint256)
    "0x40c10f19", // mint(address,uint256)
    "0x9dc29fac", // burn(address,uint256)
    "0x01ffc9a7", // supportsInterface(bytes4)
    "0x150b7a02", // onERC721Received
    "0x1626ba7e", // isValidSignature
    "0x70a08231", // balanceOf
    "0x06fdde03", // name()
    "0x95d89b41", // symbol()
    "0x313ce567", // decimals()
    "0x18160ddd", // totalSupply()
  ]);
  if (fn.selector && SAFE_SELECTORS.has(fn.selector)) s -= 20;
  return s;
}
