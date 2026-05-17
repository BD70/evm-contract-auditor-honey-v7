// debug_traceCall integration. Anvil supports the `callTracer` tracer which
// returns a nested tree of every CALL/DELEGATECALL/STATICCALL/CREATE inside
// a hypothetical transaction. We use it for witness detection (find any
// inner CALL whose `to == probeAddress`) so the verifier can:
//
//   1. Detect the witness in ONE RPC round-trip instead of three
//      (eth_sendTransaction + eth_getTransactionReceipt + eth_getStorageAt).
//   2. Capture the precise revert reason on the top-level call when the
//      vulnerable function never reaches the call site (auth check, value
//      check, etc.). This is the single biggest UX win for true positives:
//      instead of "no forward observed" users see "execution reverted:
//      Ownable: caller is not the owner" and know to retry as owner.
//   3. Distinguish CALL vs DELEGATECALL at the witness site so the worker
//      can label evidence accurately.
//
// We don't mine a transaction, so there's no state mutation across
// attempts — no need to snapshot/revert.

import { rpcRequest, ATTACKER_ADDRESS } from "./anvil-pool";

export interface CallNode {
  type: string; // CALL | DELEGATECALL | STATICCALL | CREATE | CREATE2 | SELFDESTRUCT
  from: string;
  to?: string;
  gas?: string;
  gasUsed?: string;
  input?: string;
  output?: string;
  value?: string;
  error?: string;
  revertReason?: string;
  calls?: CallNode[];
}

export interface TraceCallOpts {
  from?: string;
  to: string;
  data: string;
  value?: string; // hex
  gas?: string; // hex
}

export interface TraceCallResult {
  ok: boolean;
  root: CallNode | null;
  revertReason: string | null;
  error: string | null;
}

/**
 * Run `debug_traceCall` with the callTracer. Returns the parsed root node
 * and bubbles up any revert reason on the outer call. When the top-level
 * call reverted but the callTracer didn't decode a reason (custom errors,
 * Solidity 0.8 panics, etc.), we fall back to a parallel `eth_call` whose
 * RPC-level error payload carries the raw revert bytes — usually decodable.
 *
 * Never throws on execution-level errors (revert/oog/etc); only throws for
 * RPC transport failures.
 */
export async function debugTraceCall(rpcUrl: string, opts: TraceCallOpts): Promise<TraceCallResult> {
  const txArg: Record<string, string> = {
    from: opts.from ?? ATTACKER_ADDRESS,
    to: opts.to,
    data: opts.data,
    value: opts.value ?? "0x0",
    gas: opts.gas ?? "0x500000",
  };
  let raw: any;
  try {
    raw = await rpcRequest(rpcUrl, "debug_traceCall", [
      txArg,
      "latest",
      { tracer: "callTracer", tracerConfig: { withLog: false } },
    ]);
  } catch (err: any) {
    return { ok: false, root: null, revertReason: null, error: String(err?.message ?? err) };
  }
  const root: CallNode | null = isCallNode(raw) ? raw : null;
  let revertReason = extractRevertReason(root);
  // If callTracer didn't decode a reason for the top-level revert, try
  // eth_call — anvil's RPC error includes the raw revert payload.
  if (root?.error && (!revertReason || revertReason === "execution reverted")) {
    const callReason = await ethCallRevertReason(rpcUrl, txArg).catch(() => null);
    if (callReason) revertReason = callReason;
  }
  return {
    ok: !root?.error,
    root,
    revertReason,
    error: root?.error ?? null,
  };
}

/**
 * Run an eth_call and, if it reverts, decode the revert reason from the
 * RPC error payload. Returns null on success or undecodable revert.
 */
async function ethCallRevertReason(rpcUrl: string, txArg: Record<string, string>): Promise<string | null> {
  try {
    await rpcRequest(rpcUrl, "eth_call", [txArg, "latest"]);
    return null; // didn't revert
  } catch (err: any) {
    // anvil packs the revert data in err.data; sometimes also in err.message.
    const data = err?.data;
    if (typeof data === "string" && data.startsWith("0x")) {
      return decodeRevertOutput(data) ?? data;
    }
    if (typeof data === "object" && data?.data && typeof data.data === "string") {
      return decodeRevertOutput(data.data) ?? data.data;
    }
    // anvil sometimes embeds the revert string directly in the message:
    // "execution reverted: Ownable: caller is not the owner"
    const msg: string = String(err?.message ?? "");
    const m = /execution reverted:\s*(.+)$/i.exec(msg);
    if (m) return m[1].trim();
    return null;
  }
}

function isCallNode(x: any): x is CallNode {
  return !!x && typeof x === "object" && typeof x.type === "string" && typeof x.from === "string";
}

/**
 * Pull the most informative revert reason out of a call tree. callTracer
 * sometimes attaches `revertReason` on the root, other times only `output`
 * containing the encoded Error(string). We try both.
 */
export function extractRevertReason(node: CallNode | null): string | null {
  if (!node) return null;
  if (node.revertReason) return node.revertReason;
  if (node.error && node.output) {
    const decoded = decodeRevertOutput(node.output);
    if (decoded) return decoded;
  }
  return null;
}

/**
 * Decode an Error(string) ABI-encoded payload. The output of a reverting
 * call is typically `0x08c379a0` + abi.encode(string) — that is, the
 * Error(string) selector followed by the offset (32), the length, and the
 * UTF-8 bytes padded to 32 bytes.
 */
export function decodeRevertOutput(output: string): string | null {
  if (!output) return null;
  let hex = output.startsWith("0x") ? output.slice(2) : output;
  if (hex.length < 8) return null;
  const selector = hex.slice(0, 8).toLowerCase();
  // 0x08c379a0 = Error(string)
  if (selector === "08c379a0") {
    try {
      // offset (32), length (32), data
      if (hex.length < 8 + 64 + 64) return null;
      const lenHex = hex.slice(8 + 64, 8 + 128);
      const len = parseInt(lenHex, 16);
      if (!Number.isFinite(len) || len <= 0 || len > 4096) return null;
      const dataHex = hex.slice(8 + 128, 8 + 128 + len * 2);
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) {
        bytes[i] = parseInt(dataHex.slice(i * 2, i * 2 + 2), 16);
      }
      const txt = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
      return txt.trim() || null;
    } catch {
      return null;
    }
  }
  // 0x4e487b71 = Panic(uint256)
  if (selector === "4e487b71") {
    const code = parseInt(hex.slice(8, 8 + 64), 16);
    return `panic(${"0x" + code.toString(16)})`;
  }
  // Custom error: return the selector so the user can grep for it.
  return `custom error ${"0x" + selector}`;
}

export interface ProbeWitness {
  hit: boolean;
  kind?: "CALL" | "DELEGATECALL" | "STATICCALL" | "CREATE" | "CREATE2";
  depth?: number;
  innerFromVictim?: boolean;
}

/**
 * Walk a call trace looking for any node whose `to` matches `probeAddr`
 * (case-insensitive). Returns the FIRST hit, with the call type recorded
 * so the verifier can distinguish CALL (arbitrary forward) vs DELEGATECALL
 * (controlled delegatecall — much more severe).
 */
export function findProbeWitness(
  root: CallNode | null,
  probeAddr: string,
  victimAddr: string,
): ProbeWitness {
  if (!root) return { hit: false };
  const probe = probeAddr.toLowerCase();
  const victim = victimAddr.toLowerCase();
  const stack: Array<{ node: CallNode; depth: number; parentFrom: string }> = [
    { node: root, depth: 0, parentFrom: root.from?.toLowerCase() ?? "" },
  ];
  while (stack.length > 0) {
    const { node, depth } = stack.pop()!;
    if (
      node.to &&
      node.to.toLowerCase() === probe &&
      depth > 0 // top-level call is by the attacker, not a witness
    ) {
      return {
        hit: true,
        kind: (node.type ?? "CALL") as ProbeWitness["kind"],
        depth,
        innerFromVictim: node.from?.toLowerCase() === victim,
      };
    }
    if (Array.isArray(node.calls)) {
      for (const c of node.calls) {
        stack.push({ node: c, depth: depth + 1, parentFrom: node.from?.toLowerCase() ?? "" });
      }
    }
  }
  return { hit: false };
}

/**
 * Heuristic: does the revert reason look like an auth/access-control gate
 * we could bypass by impersonating the owner?
 *
 * Covers two families:
 *   1. Solidity revert strings (`Ownable: caller is not the owner`, etc.)
 *   2. OpenZeppelin v5 custom errors. These come through as
 *      `custom error 0xXXXXXXXX` because callTracer doesn't decode them.
 *      We hardcode the known auth-related selectors below.
 */
const AUTH_CUSTOM_ERROR_SELECTORS = new Set<string>([
  "0x118cdaa7", // OwnableUnauthorizedAccount(address)        (OZ v5 Ownable)
  "0xe2517d3f", // AccessControlUnauthorizedAccount(address,bytes32)
  "0x82b42900", // Unauthorized()
  "0x06d919f2", // CallerNotOwner()
  "0x30cd7471", // NotOwner()
  "0x584a7938", // NotAuthorized()
  "0xea8e4eb5", // OnlyAdmin()
  "0x5fc483c5", // OnlyOwner()
  "0x1648fd01", // OwnableInvalidOwner(address)
  "0x4ca88867", // CallerIsNotAdmin()
  "0x1e4fbdf7", // OwnableInvalidOwner(address) variant
]);

export function isAuthRevert(reason: string | null): boolean {
  if (!reason) return false;
  if (
    /(\bowner\b|\bownable\b|access ?control|caller is not|not authorized|not the admin|onlyowner|onlyadmin|permission denied|forbidden|unauthorized|UNAUTH)/i.test(
      reason,
    )
  ) {
    return true;
  }
  // Match "custom error 0xXXXXXXXX" emitted by decodeRevertOutput.
  const m = /custom error\s+(0x[0-9a-f]{8})/i.exec(reason);
  if (m && AUTH_CUSTOM_ERROR_SELECTORS.has(m[1].toLowerCase())) return true;
  return false;
}

const OWNER_SELECTORS = [
  "0x8da5cb5b", // owner()
  "0xf851a440", // admin()
  "0xa3f8eace", // _admin()  (rare)
];

/** Read a contract's `owner()` (or `admin()`) on the fork. */
export async function readContractOwner(rpcUrl: string, contract: string): Promise<string | null> {
  for (const sel of OWNER_SELECTORS) {
    try {
      const ret = await rpcRequest<string>(rpcUrl, "eth_call", [{ to: contract, data: sel }, "latest"]);
      if (!ret || ret === "0x" || ret === "0x" + "0".repeat(64)) continue;
      const hex = ret.replace(/^0x/, "").padStart(64, "0");
      const addr = "0x" + hex.slice(24).toLowerCase();
      if (addr === "0x" + "0".repeat(40)) continue;
      return addr;
    } catch {
      /* try next */
    }
  }
  return null;
}

/** Fund + impersonate an account on anvil so subsequent eth_sendTransaction /
 *  debug_traceCall calls from that address succeed. Idempotent. */
export async function impersonate(rpcUrl: string, address: string): Promise<void> {
  await rpcRequest(rpcUrl, "anvil_impersonateAccount", [address]).catch(() => {});
  await rpcRequest(rpcUrl, "anvil_setBalance", [address, "0xde0b6b3a7640000" /* 1 ETH */]).catch(() => {});
}

export type OwnerKind =
  | "zero" // 0x000...0 — renounced
  | "eoa" // no bytecode — single private key controls
  | "safe" // Gnosis/Safe multisig (responds to getOwners() + getThreshold())
  | "timelock" // OpenZeppelin TimelockController (responds to getMinDelay())
  | "multisig_other" // contract that responds to some multisig-like selector but not Safe
  | "contract" // unknown contract (could be DAO/governor/custom)
  | "unknown"; // failed to inspect

export interface OwnerClassification {
  kind: OwnerKind;
  address: string;
  /** Human-readable details that contextualise the kind. */
  details: string;
  /** Multisig threshold (if Safe) — useful for severity scoring. */
  threshold?: number;
  /** Multisig owner count (if Safe). */
  ownerCount?: number;
}

const SAFE_GET_OWNERS_SEL = "0xa0e67e2b"; // getOwners() returns (address[])
const SAFE_GET_THRESHOLD_SEL = "0xe75235b8"; // getThreshold() returns (uint256)
const TIMELOCK_MIN_DELAY_SEL = "0xd33219b4"; // getMinDelay() returns (uint256)

async function ethCallOrNull(rpcUrl: string, to: string, data: string): Promise<string | null> {
  try {
    const ret = await rpcRequest<string>(rpcUrl, "eth_call", [{ to, data }, "latest"]);
    return typeof ret === "string" && ret !== "0x" ? ret : null;
  } catch {
    return null;
  }
}

/**
 * Classify an owner address so the verifier can decide whether the owner-only
 * path matters. The classifier is best-effort — when in doubt we return
 * "contract" or "unknown" and let the caller decide a conservative verdict.
 *
 * Detection order:
 *   1. zero address (renounced)
 *   2. no bytecode -> EOA
 *   3. responds to getOwners() AND getThreshold() -> Gnosis Safe
 *   4. responds to getMinDelay() -> Timelock
 *   5. has bytecode -> generic contract
 */
export async function classifyOwner(rpcUrl: string, address: string): Promise<OwnerClassification> {
  const lower = address.toLowerCase();
  if (lower === "0x0000000000000000000000000000000000000000") {
    return { kind: "zero", address: lower, details: "owner renounced (zero address)" };
  }
  let code: string;
  try {
    code = await rpcRequest<string>(rpcUrl, "eth_getCode", [address, "latest"]);
  } catch {
    return { kind: "unknown", address: lower, details: "eth_getCode failed" };
  }
  if (!code || code === "0x" || code === "0x0") {
    return { kind: "eoa", address: lower, details: "owner is an EOA — single key has full control" };
  }
  // Probe for Gnosis Safe first (most common DAO/treasury setup).
  const ownersHex = await ethCallOrNull(rpcUrl, address, SAFE_GET_OWNERS_SEL);
  const thresholdHex = await ethCallOrNull(rpcUrl, address, SAFE_GET_THRESHOLD_SEL);
  if (ownersHex && thresholdHex) {
    // owners is address[] returned starting at offset 0x20; we extract length at
    // word 1 of the payload (which equals the array length).
    const ownersCount = (() => {
      try {
        const h = ownersHex.replace(/^0x/, "");
        if (h.length < 128) return undefined;
        return parseInt(h.slice(64, 128), 16);
      } catch {
        return undefined;
      }
    })();
    const threshold = (() => {
      try {
        return parseInt(thresholdHex.replace(/^0x/, ""), 16);
      } catch {
        return undefined;
      }
    })();
    if (ownersCount != null && threshold != null && threshold > 0 && ownersCount >= threshold) {
      return {
        kind: "safe",
        address: lower,
        details: `Gnosis Safe ${threshold}/${ownersCount} multisig`,
        threshold,
        ownerCount: ownersCount,
      };
    }
  }
  // Probe for OZ TimelockController.
  const minDelay = await ethCallOrNull(rpcUrl, address, TIMELOCK_MIN_DELAY_SEL);
  if (minDelay) {
    try {
      const seconds = parseInt(minDelay.replace(/^0x/, ""), 16);
      if (Number.isFinite(seconds) && seconds >= 0 && seconds < 365 * 24 * 3600 * 10) {
        return {
          kind: "timelock",
          address: lower,
          details: `OpenZeppelin TimelockController (min delay ${seconds}s ≈ ${(seconds / 3600).toFixed(1)}h)`,
        };
      }
    } catch {
      /* fall through */
    }
  }
  return {
    kind: "contract",
    address: lower,
    details: "owner is a contract (governance/DAO/custom) — manual review of its logic required",
  };
}
