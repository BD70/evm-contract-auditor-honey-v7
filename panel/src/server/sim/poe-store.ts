// Proof-of-Exploit (PoE) persistence layer.
//
// A PoE is a structured JSON artifact produced by `rescue-prove.ts` whenever
// the rescue-prove simulator successfully drains a contract on a fork. The
// artifact carries everything a third party needs to (a) independently
// reproduce the drain on their own fork, and (b) broadcast the same calldata
// against mainnet to actually rescue the funds:
//
//   - chain + contract + finding context
//   - the contract's balance breakdown (native + per-token) BEFORE the drain
//   - the same breakdown AFTER the drain (proves the contract was emptied)
//   - the escrow's gained balance AFTER (proves where the funds went)
//   - the exact `drainPlan` (sequence of {to, calldata, value}) that performed
//     the drain — this is what gets re-broadcast against mainnet during the
//     "rescue" step
//   - chain block number at which the fork ran (so the drain is reproducible
//     bit-for-bit)
//
// The verdict is one of:
//
//   - "true_positive_drained"   : the simulator moved real value to escrow
//   - "true_positive_partial"   : some assets moved, some couldn't be drained
//   - "no_rescue_possible"      : sim ran but couldn't extract anything;
//                                 the finding might still be a real bug
//                                 (e.g. an economic attack we can't yet sim
//                                 end-to-end) but is NOT auto-rescuable
//   - "skipped"                 : prereqs missing (e.g. no chain context)
//   - "error"                   : simulator crashed before completing
//
// "no_rescue_possible" does NOT downgrade the underlying finding — it just
// tells the UI/TG bot "don't ship a rescue tx for this one". Only
// "true_positive_drained" / "true_positive_partial" trigger the TG notify.

import { rawDb } from "@/src/db/client";
import { randomBytes } from "node:crypto";

export type PoeVerdict =
  | "true_positive_drained"
  | "true_positive_partial"
  | "no_rescue_possible"
  | "skipped"
  | "error";

export interface PoeAssetRescued {
  /** null = native asset (ETH/BNB/MATIC/…); otherwise lowercased ERC-20 address */
  token: string | null;
  /** raw base-unit amount, decimal string */
  amountBase: string;
  symbol: string;
  decimals: number;
  /** USD value at fork-time price; null when we couldn't price it */
  usdValue: number | null;
}

export interface PoeDrainStep {
  /** Sequence index in the drain plan; 0-based */
  index: number;
  /** Target contract for the call (usually the vulnerable contract itself) */
  to: string;
  /** Calldata to send to `to`; this is the EXACT bytes that performed the
   *  drain on the fork and that should be broadcast for the real rescue */
  data: string;
  /** msg.value in wei, decimal string */
  value: string;
  /** Human description: which token (or native) this step extracts */
  asset: string;
  /** Gas used on the fork; the real broadcast will likely cost similar */
  gasUsed?: string | null;
  /** Whether this step succeeded on the fork */
  success: boolean;
  /** When success=false, the revert reason (if any) */
  revertReason?: string | null;
  /** v2: which executor sent this tx — "attacker" or "owner". When "owner"
   *  the live broadcaster MUST have the owner's signing key. */
  executor?: "attacker" | "owner";
  /** v2: actual sender address on the fork (attacker EOA or owner). */
  from?: string;
  /** v2: short tag describing the strategy that produced this step
   *  (e.g. "witnessed-arbitrary-call", "weth-unwrap", "admin-heuristic:rescueERC20"). */
  strategy?: string;
}

export interface PoeArtifact {
  /** Stable id for this PoE attempt */
  attemptId: string;
  findingId: string;
  chainId: number;
  contractAddress: string;
  /** "any" (permissionless) or "owner" (privileged) — copied from the
   *  underlying finding's simulation evidence */
  attackerKind: "any" | "owner" | "unknown";
  /** Where the drain delivered the funds on the fork (and where the real
   *  rescue would send them). Loaded from RESCUE_ESCROW_ADDR env at sim
   *  time. */
  escrowAddress: string;
  /** Anvil-attacker EOA used as msg.sender during the drain — purely a
   *  simulation detail; the real rescue uses RESCUER_PRIVATE_KEY */
  attackerEoa: string;
  verdict: PoeVerdict;
  /** Fork block at which the drain was simulated */
  blockNumber: number | null;
  rescuedAssets: PoeAssetRescued[];
  drainPlan: PoeDrainStep[];
  /** Sum of usdValue across rescuedAssets (null when ALL were unpriced) */
  totalRescuedUsd: number | null;
  /** Pre-drain contract balance (native + tokens) — same shape as exposure
   *  so the UI can render a before/after diff */
  preState: {
    nativeWei: string;
    nativeUsd: number | null;
    tokens: Array<{ address: string; symbol: string; decimals: number; balance: string; usdValue: number | null }>;
  };
  /** Post-drain contract balance */
  postState: {
    nativeWei: string;
    nativeUsd: number | null;
    tokens: Array<{ address: string; symbol: string; decimals: number; balance: string; usdValue: number | null }>;
  };
  /** Free-form notes the prover wants to surface (e.g. "rescue cannot include
   *  tax-token X because every transfer slips 5% to the marketing wallet"). */
  notes: string[];
  engine: string;
  engineVersion: string;
  createdAt: number;
  durationMs: number;
  /** Set when verdict='error'; otherwise null. */
  error?: string | null;
  /** v2: owner address impersonated on the fork (if any). When non-null AND
   *  at least one drainPlan step has executor="owner", the live broadcaster
   *  refuses to send those steps unless RESCUE_OWNER_PRIVATE_KEY is also
   *  configured. */
  executorOwner?: string | null;
}

export function newAttemptId(): string {
  return "poe-" + randomBytes(12).toString("hex");
}

export function persistPoe(p: PoeArtifact): void {
  const rescuedTokens = p.rescuedAssets.filter((a) => a.token != null).length;
  const rescuedNative = p.rescuedAssets.find((a) => a.token == null)?.amountBase ?? null;
  rawDb
    .prepare(
      `INSERT OR REPLACE INTO proofs_of_exploit (
         attempt_id, finding_id, chain_id, contract_address, attacker_kind,
         escrow_address, verdict, rescued_native_wei, rescued_tokens_count,
         rescued_usd, drain_plan_count, engine, engine_version, block_number,
         duration_ms, created_at, artifact_json, error
       ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    )
    .run(
      p.attemptId,
      p.findingId,
      p.chainId,
      p.contractAddress.toLowerCase(),
      p.attackerKind,
      p.escrowAddress.toLowerCase(),
      p.verdict,
      rescuedNative,
      rescuedTokens,
      p.totalRescuedUsd,
      p.drainPlan.length,
      p.engine,
      p.engineVersion,
      p.blockNumber,
      p.durationMs,
      p.createdAt,
      JSON.stringify(p),
      p.error ?? null,
    );
}

export function loadLatestPoe(findingId: string): PoeArtifact | null {
  const row = rawDb
    .prepare(
      `SELECT artifact_json FROM proofs_of_exploit
       WHERE finding_id = ?
       ORDER BY created_at DESC LIMIT 1`,
    )
    .get(findingId) as { artifact_json: string } | undefined;
  if (!row) return null;
  try {
    return JSON.parse(row.artifact_json) as PoeArtifact;
  } catch {
    return null;
  }
}

export function loadAllPoeForFinding(findingId: string): PoeArtifact[] {
  const rows = rawDb
    .prepare(
      `SELECT artifact_json FROM proofs_of_exploit
       WHERE finding_id = ?
       ORDER BY created_at DESC`,
    )
    .all(findingId) as Array<{ artifact_json: string }>;
  return rows
    .map((r) => {
      try {
        return JSON.parse(r.artifact_json) as PoeArtifact;
      } catch {
        return null;
      }
    })
    .filter((p): p is PoeArtifact => p != null);
}

export interface RescueActionRow {
  id: number;
  finding_id: string;
  attempt_id: string | null;
  kind: string;
  actor: string | null;
  detail_json: string | null;
  at: number;
}

export function logRescueAction(args: {
  findingId: string;
  attemptId?: string | null;
  kind:
    | "poe-generated"
    | "tg-notified"
    | "identity-challenge"
    | "identity-verified"
    | "rescue-requested"
    | "rescue-dry-run"
    | "rescue-broadcasted"
    | "rescue-mined"
    | "rescue-failed";
  actor?: string | null;
  detail?: Record<string, unknown>;
}): void {
  rawDb
    .prepare(
      `INSERT INTO rescue_actions (finding_id, attempt_id, kind, actor, detail_json, at)
       VALUES (?,?,?,?,?,?)`,
    )
    .run(
      args.findingId,
      args.attemptId ?? null,
      args.kind,
      args.actor ?? null,
      args.detail ? JSON.stringify(args.detail) : null,
      Date.now(),
    );
}

export function loadActionsForFinding(findingId: string): RescueActionRow[] {
  return rawDb
    .prepare(
      `SELECT id, finding_id, attempt_id, kind, actor, detail_json, at
       FROM rescue_actions WHERE finding_id = ?
       ORDER BY at ASC`,
    )
    .all(findingId) as RescueActionRow[];
}
