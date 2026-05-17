// Approval-surface scanner.
//
// When a contract is a router/vault that users approved (`token.approve(
// router, max)`), the exploit is `router.transferFrom(victim, attacker,
// allowance)` — the contract's OWN balance may be zero but it controls
// huge balances of EVERY user who approved it.
//
// Critical policy notes:
//   1. Funds drained this way are NOT the contract's funds — they belong to
//      the victims. Rescuing them WITHOUT explicit per-victim off-chain
//      consent is at best ethically dubious and at worst legally indistin-
//      guishable from theft. We default to "scan-and-surface-only" mode
//      (the operator sees the at-risk victims and total exposure, but no
//      drain plan is auto-generated for live broadcast).
//   2. With `RESCUE_APPROVAL_CONSENT_MODE=auto`, the scanner DOES emit
//      drain plans. The broadcaster still refuses live mode unless EACH
//      victim is listed in `RESCUE_APPROVAL_CONSENT_VICTIMS` (comma-
//      separated lowercase addresses). This enforces consent-per-address.
//   3. PoE verdict for this class is `victim_approval_rescue` (separate
//      from `true_positive_drained`), and the UI surfaces it with an
//      explicit "VICTIMS' FUNDS — REQUIRES CONSENT" warning banner.
//
// How we scan:
//   1. Pull recent `Approval(address indexed owner, address indexed
//      spender, uint256 value)` logs where `spender == contractAddress`,
//      for each token in exposure.tokens.
//   2. For each (owner, token) pair found, call `allowance(owner,
//      contract)` and `balanceOf(owner)` on the fork.
//   3. The drainable amount per victim is `min(allowance, balance)`.
//   4. Sort victims by drainable USD descending; bound by MAX_VICTIMS.
//
// Optionally we extend (1) by also scanning Approval logs where the SPENDER
// is the contract itself — covers contracts that re-emit approvals on the
// user's behalf.

import { rpcRequest } from "../anvil-pool";
import { rawDb } from "@/src/db/client";

const APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";
const ALLOWANCE_SELECTOR = "0xdd62ed3e";
const BALANCE_OF_SELECTOR = "0x70a08231";

export type ApprovalConsentMode = "off" | "scan-only" | "auto";

export function approvalConsentMode(): ApprovalConsentMode {
  const v = String(process.env.RESCUE_APPROVAL_CONSENT_MODE ?? "scan-only").toLowerCase();
  if (v === "auto" || v === "off" || v === "scan-only") return v;
  return "scan-only";
}

export function consentVictims(findingId?: string): Set<string> {
  // Merge env-var consents with DB consents (from /confirmrescue TG command)
  const envVictims = (process.env.RESCUE_APPROVAL_CONSENT_VICTIMS ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter((s) => /^0x[0-9a-f]{40}$/.test(s));
  const set = new Set(envVictims);
  try {
    const hasTable = rawDb
      .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='victim_consents'")
      .get();
    if (hasTable) {
      const query = findingId
        ? rawDb.prepare(
            "SELECT victim_address FROM victim_consents WHERE status='approved' AND finding_id=?",
          )
        : rawDb.prepare("SELECT victim_address FROM victim_consents WHERE status='approved'");
      const rows = findingId ? query.all(findingId) : query.all();
      for (const r of rows as any[]) {
        set.add(String(r.victim_address).toLowerCase());
      }
    }
  } catch {}
  return set;
}

export interface VictimEntry {
  victim: string;
  token: string;
  tokenSymbol: string;
  tokenDecimals: number;
  allowance: string;
  balance: string;
  drainable: string;
  drainableUsd: number | null;
  consented: boolean;
}

export interface ApprovalScanResult {
  victims: VictimEntry[];
  totalDrainableUsd: number | null;
  scannedTokens: number;
  approvalLogsFound: number;
  /** When mode === "off" we don't even scan. */
  mode: ApprovalConsentMode;
  notes: string[];
}

const MAX_VICTIMS = Number(process.env.RESCUE_APPROVAL_MAX_VICTIMS ?? 50);
const LOOKBACK_BLOCKS = Number(process.env.RESCUE_APPROVAL_LOOKBACK ?? 200_000);

/** Scan Approval logs for each token in exposure, build the at-risk
 *  victim table. */
export async function scanApprovals(args: {
  url: string;
  chainRpcUrl?: string | null;
  contractAddress: string;
  findingId?: string;
  tokens: Array<{ address: string; symbol: string; decimals: number; usdPerToken: number | null }>;
}): Promise<ApprovalScanResult> {
  const mode = approvalConsentMode();
  const result: ApprovalScanResult = {
    victims: [],
    totalDrainableUsd: null,
    scannedTokens: 0,
    approvalLogsFound: 0,
    mode,
    notes: [],
  };
  if (mode === "off") {
    result.notes.push("approval-surface scanning disabled (RESCUE_APPROVAL_CONSENT_MODE=off)");
    return result;
  }
  if (args.tokens.length === 0) {
    result.notes.push("no exposure tokens to scan for approvals");
    return result;
  }

  const consented = consentVictims(args.findingId);
  const queryUrl = args.chainRpcUrl ?? args.url;
  const latestHex = await rpcRequest<string>(args.url, "eth_blockNumber", []).catch(() => "0x0");
  const latest = BigInt(latestHex ?? "0x0");
  const fromBlock = latest > BigInt(LOOKBACK_BLOCKS) ? latest - BigInt(LOOKBACK_BLOCKS) : 0n;
  const contractTopic = "0x" + args.contractAddress.replace(/^0x/, "").toLowerCase().padStart(64, "0");

  const seenOwners = new Map<string, Set<string>>(); // token -> set of owners
  for (const t of args.tokens) {
    result.scannedTokens++;
    try {
      const logs = await rpcRequest<any[]>(queryUrl, "eth_getLogs", [
        {
          address: t.address,
          fromBlock: "0x" + fromBlock.toString(16),
          toBlock: "latest",
          // Approval(owner, spender, value) — filter by spender = contract
          topics: [APPROVAL_TOPIC, null, contractTopic],
        },
      ]).catch(() => []);
      result.approvalLogsFound += logs.length;
      if (!seenOwners.has(t.address)) seenOwners.set(t.address, new Set());
      const set = seenOwners.get(t.address)!;
      for (const log of logs) {
        const ownerTopic = log?.topics?.[1];
        if (typeof ownerTopic === "string" && ownerTopic.length === 66) {
          const owner = "0x" + ownerTopic.slice(-40).toLowerCase();
          set.add(owner);
        }
      }
    } catch (e) {
      result.notes.push(
        `eth_getLogs failed for ${t.symbol} (${t.address.slice(0, 8)}…): ${String((e as any)?.message ?? e).slice(0, 100)}`,
      );
    }
  }

  // For each (owner, token), read current allowance + balance on the FORK
  // (not on live chain — the live chain may have moved since logs were
  // captured, and we want the snapshot that matches our drain attempt).
  for (const [token, owners] of seenOwners) {
    const meta = args.tokens.find((x) => x.address === token);
    if (!meta) continue;
    for (const owner of owners) {
      if (result.victims.length >= MAX_VICTIMS) break;
      const [allowance, balance] = await Promise.all([
        readAllowance(args.url, token, owner, args.contractAddress),
        readBalance(args.url, token, owner),
      ]);
      const allowanceBN = allowance;
      const balanceBN = balance;
      if (allowanceBN === 0n || balanceBN === 0n) continue;
      const drainable = allowanceBN < balanceBN ? allowanceBN : balanceBN;
      const human = Number(drainable) / Math.pow(10, meta.decimals);
      const usd =
        meta.usdPerToken != null && Number.isFinite(human) ? human * meta.usdPerToken : null;
      result.victims.push({
        victim: owner,
        token,
        tokenSymbol: meta.symbol,
        tokenDecimals: meta.decimals,
        allowance: allowanceBN.toString(),
        balance: balanceBN.toString(),
        drainable: drainable.toString(),
        drainableUsd: usd,
        consented: consented.has(owner),
      });
    }
    if (result.victims.length >= MAX_VICTIMS) break;
  }
  result.victims.sort((a, b) => (b.drainableUsd ?? 0) - (a.drainableUsd ?? 0));
  result.totalDrainableUsd = result.victims.reduce(
    (acc, v) => (v.drainableUsd != null ? acc + v.drainableUsd : acc),
    0,
  );
  if (result.totalDrainableUsd === 0) result.totalDrainableUsd = null;

  if (mode === "scan-only") {
    result.notes.push(
      `scan-only mode: ${result.victims.length} victim(s) at risk, total ` +
        `$${(result.totalDrainableUsd ?? 0).toFixed(2)}. Drain plan NOT generated. ` +
        `To enable, set RESCUE_APPROVAL_CONSENT_MODE=auto AND list each consenting victim ` +
        `address in RESCUE_APPROVAL_CONSENT_VICTIMS.`,
    );
  } else {
    const consentedCount = result.victims.filter((v) => v.consented).length;
    result.notes.push(
      `auto mode: ${consentedCount}/${result.victims.length} victims have consent (env: ` +
        `RESCUE_APPROVAL_CONSENT_VICTIMS). Drain plan will include ONLY consented victims.`,
    );
  }
  return result;
}

async function readAllowance(url: string, token: string, owner: string, spender: string): Promise<bigint> {
  const data =
    ALLOWANCE_SELECTOR +
    owner.replace(/^0x/, "").toLowerCase().padStart(64, "0") +
    spender.replace(/^0x/, "").toLowerCase().padStart(64, "0");
  try {
    const r = await rpcRequest<string>(url, "eth_call", [{ to: token, data }, "latest"]);
    return r && r !== "0x" ? BigInt(r) : 0n;
  } catch {
    return 0n;
  }
}

async function readBalance(url: string, token: string, holder: string): Promise<bigint> {
  const data =
    BALANCE_OF_SELECTOR + holder.replace(/^0x/, "").toLowerCase().padStart(64, "0");
  try {
    const r = await rpcRequest<string>(url, "eth_call", [{ to: token, data }, "latest"]);
    return r && r !== "0x" ? BigInt(r) : 0n;
  } catch {
    return 0n;
  }
}
