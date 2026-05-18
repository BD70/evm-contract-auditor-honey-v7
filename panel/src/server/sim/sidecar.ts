// Generic sidecar runner.
//
// A "sidecar" is a TS verifier that runs on every contract receiving any
// finding (or any manual audit), independent of whether the upstream Go
// analyzer matched the verifier's target rule. This bridges the gap where
// the Go fact engine can't produce certain semantic facts (e.g. bridge
// proof binding, ERC-4626 caller authorization checks) but a dynamic fork
// probe can definitively confirm or refute the bug.
//
// Each sidecar registers a SidecarSpec that describes the rule it
// synthesises (rule_id, severity, category, …) and an optional cheap
// gate (`shouldRun`) that examines the audit's fingerprint to decide
// whether the verifier's heavy anvil work is worth doing.
//
// Sidecars are idempotent: a previously-materialised finding for the same
// (chain, address, rule) is detected up-front and skipped. The simulation
// cache is keyed by (bytecode_hash, rule_id, engine, engine_version) so
// the same bytecode is verified exactly once across all its clones.

import { createHash } from "node:crypto";
import { rawDb } from "@/src/db/client";
import { findVerifier, verifyFinding } from "./exploits";
import type { VerifyResult, VerdictStatus } from "./types";

export interface SidecarSpec {
  /** Canonical rule_id this sidecar materialises. MUST exist as a rule in
   *  `rules/core/` so the rest of the pipeline (UI, surface mapping, rescue
   *  prove) treats it consistently. */
  ruleId: string;
  /** Stable identifier for the internal name column (matches Go convention). */
  internalName: string;
  /** Sidecar source tag used to distinguish materialised findings from
   *  upstream Go findings. */
  source: string;
  severity: "critical" | "high" | "medium" | "low";
  status: string;
  category: string;
  /** Human-readable summary stored in raw_json.summary. */
  summary: string;
  /** Title for the finding. May depend on verifier evidence. */
  titleFor(evidence: any): string;
  /** Confidence value (string) — default depends on attackerKind. Override
   *  if you want a custom rule. */
  confidenceFor?: (evidence: any) => string;
  /** Cheap pre-check: examine an audit JSON's fingerprint to decide if the
   *  sidecar is worth running. Return `false` to skip the expensive anvil
   *  verify. When omitted, the sidecar runs unconditionally. */
  shouldRun?: (audit: AuditContext) => boolean;
  /** Env var name to disable this specific sidecar at runtime. */
  envFlag?: string;
}

export interface AuditContext {
  /** Global tags emitted by the Go fingerprint, e.g. ['ERC20', 'ERC4626']. */
  globalTags: string[];
  /** Bytecode fingerprint map (the `bytecode_fingerprint` field). */
  fingerprint: Record<string, unknown>;
  /** Available facts on the contract (subset of `available_facts` from
   *  any checker_trace entry). */
  facts: string[];
}

export const SIDECARS: SidecarSpec[] = [
  {
    ruleId: "economic.unguarded_amm_action",
    internalName: "sidecar_economic_unguarded_amm_action_v1",
    source: "sidecar-economic-attack",
    severity: "critical",
    status: "probable_vulnerability",
    category: "access_control",
    summary:
      "Sidecar verifier (anvil-fork-economic) confirmed this contract exposes a " +
      "permissionless function that reaches an AMM router swap. Vulnerable to flash-loan " +
      "price manipulation.",
    titleFor(evidence) {
      const sigKind: string | undefined = evidence?.staticSignatureKind;
      const viaStatic = Boolean(evidence?.viaStaticEvidence);
      if (sigKind === "pair-direct")
        return "Permissionless pair-direct manipulation (sync/skim/burn) — deflationary-burn / flash-loan exploitable";
      if (sigKind === "both")
        return "Permissionless function with router swap AND pair-direct manipulation — flash-loan exploitable";
      if (viaStatic) return "Permissionless function triggers AMM swap (static evidence) — flash-loan exploitable";
      return "Permissionless function triggers AMM swap — flash-loan exploitable";
    },
    confidenceFor(evidence) {
      return (evidence?.attackerKind ?? "any") === "any" ? "0.85" : "0.65";
    },
    envFlag: "SIM_SIDECAR_ECONOMIC",
  },
  {
    ruleId: "defi.erc4626.withdraw.missing_caller_authorization",
    internalName: "sidecar_erc4626_withdraw_missing_caller_authorization_v1",
    source: "sidecar-erc4626-withdraw",
    severity: "critical",
    status: "probable_vulnerability",
    category: "access_control",
    summary:
      "Sidecar verifier confirmed this ERC-4626 vault allows any external EOA to call " +
      "withdraw/redeem with arbitrary `owner` and `receiver` arguments, draining victim " +
      "shares without an allowance.",
    titleFor(evidence) {
      const victim = evidence?.victimAddress;
      return victim
        ? `ERC-4626 vault drains victim ${String(victim).slice(0, 10)}… without authorization`
        : "ERC-4626 vault allows unauthorized withdraw/redeem of arbitrary owner";
    },
    shouldRun(audit) {
      // Only run on contracts that look like ERC-4626 vaults.
      return (
        audit.globalTags.includes("ERC4626") ||
        audit.globalTags.includes("erc4626_vault_trait") ||
        Boolean(audit.fingerprint.has_erc4626_pattern)
      );
    },
    envFlag: "SIM_SIDECAR_ERC4626_WITHDRAW",
  },
  {
    ruleId: "bridge.forged_cross_chain_proof",
    internalName: "sidecar_bridge_forged_cross_chain_proof_v1",
    source: "sidecar-bridge-proof",
    severity: "critical",
    status: "probable_vulnerability",
    category: "bridge",
    summary:
      "Sidecar verifier confirmed this bridge contract accepts caller-supplied proof " +
      "payloads at an import/relay surface and reaches asset-transfer effects from the " +
      "decoded payload without sufficient root verification.",
    titleFor(_evidence) {
      return "Cross-chain bridge import surface accepts caller-supplied proof without sufficient verification";
    },
    shouldRun(audit) {
      return (
        audit.globalTags.includes("BRIDGE_PATTERN") ||
        audit.globalTags.includes("bridge_import_surface") ||
        Boolean(audit.fingerprint.has_bridge_pattern)
      );
    },
    envFlag: "SIM_SIDECAR_BRIDGE",
  },
  {
    ruleId: "oracle.chainlink_staleness_unchecked",
    internalName: "sidecar_oracle_chainlink_staleness_v1",
    source: "sidecar-oracle-staleness",
    severity: "high",
    status: "probable_vulnerability",
    category: "oracle",
    summary:
      "Sidecar verifier confirmed this contract makes economic decisions based on a " +
      "Chainlink price feed without checking `updatedAt` for staleness. Stale prices " +
      "can be exploited by waiting for feed degradation.",
    titleFor(_evidence) {
      return "Chainlink price feed consumed without staleness check";
    },
    // No cheap gate yet — the Go side doesn't fingerprint Chainlink usage.
    // The verifier itself does a quick storage-slot probe and returns
    // `not_exploitable` if no aggregator is found.
    envFlag: "SIM_SIDECAR_ORACLE_STALENESS",
  },
  {
    ruleId: "defi.swap.missing_slippage_or_deadline",
    internalName: "sidecar_swap_slippage_deadline_v1",
    source: "sidecar-swap-slippage",
    severity: "medium",
    status: "suspicious_behavior",
    category: "defi_logic",
    summary:
      "Sidecar verifier confirmed this contract exposes a swap function that lacks " +
      "`minAmountOut` or `deadline` parameters, enabling sandwich attacks.",
    titleFor(_evidence) {
      return "Swap function lacks slippage / deadline protection — sandwichable";
    },
    envFlag: "SIM_SIDECAR_SWAP_SLIPPAGE",
  },
  {
    ruleId: "token.unsafe_erc20_assumption",
    internalName: "sidecar_unsafe_erc20_assumption_v1",
    source: "sidecar-unsafe-erc20",
    severity: "medium",
    status: "suspicious_behavior",
    category: "token",
    summary:
      "Sidecar verifier confirmed this contract calls ERC-20 transfer/transferFrom without " +
      "checking the boolean return value. A malicious or buggy token returning `false` " +
      "would be silently accepted as successful.",
    titleFor(_evidence) {
      return "ERC-20 transfer return value not checked — unsafe for non-reverting tokens";
    },
    envFlag: "SIM_SIDECAR_UNSAFE_ERC20",
  },
];

/**
 * Run every applicable sidecar on the given contract. Existing findings for
 * each sidecar's rule are detected up-front and skipped (idempotent). Returns
 * per-sidecar result so callers can log or surface them.
 */
export async function runAllSidecars(args: {
  chainId: number;
  contractAddress: string;
  bytecodeHash?: string | null;
  sourceFindingId?: string;
  runId?: string;
  /** Optional audit context used by each sidecar's `shouldRun` gate. When
   *  omitted, every sidecar without an explicit gate runs unconditionally. */
  audit?: AuditContext;
  /** When set, skip sidecars whose `ruleId` matches the current primary
   *  verifier's rule to avoid duplicating the same verifier's work. */
  excludeRuleId?: string;
}): Promise<Array<{ ruleId: string; ran: boolean; status?: string; findingId?: string }>> {
  const results: Array<{ ruleId: string; ran: boolean; status?: string; findingId?: string }> = [];
  for (const spec of SIDECARS) {
    if (spec.envFlag) {
      const v = process.env[spec.envFlag];
      if (typeof v === "string" && v.toLowerCase() === "false") {
        results.push({ ruleId: spec.ruleId, ran: false });
        continue;
      }
    }
    if (args.excludeRuleId === spec.ruleId) {
      results.push({ ruleId: spec.ruleId, ran: false });
      continue;
    }
    if (spec.shouldRun && args.audit) {
      try {
        if (!spec.shouldRun(args.audit)) {
          results.push({ ruleId: spec.ruleId, ran: false });
          continue;
        }
      } catch {
        // Gate evaluation failure shouldn't block the sidecar — run it.
      }
    }
    try {
      const r = await runOneSidecar(spec, args);
      results.push({ ruleId: spec.ruleId, ...r });
    } catch (err) {
      console.warn(`[sim] sidecar ${spec.ruleId} failed`, err);
      results.push({ ruleId: spec.ruleId, ran: false });
    }
  }
  return results;
}

async function runOneSidecar(
  spec: SidecarSpec,
  args: {
    chainId: number;
    contractAddress: string;
    bytecodeHash?: string | null;
    sourceFindingId?: string;
    runId?: string;
  },
): Promise<{ ran: boolean; status?: string; findingId?: string; cached?: boolean }> {
  const verifier = findVerifier(spec.ruleId);
  if (!verifier) return { ran: false };
  const engine = verifier.id;
  const version = verifier.version;

  // Idempotent: if a sidecar finding for this (chain, address, rule) already
  // exists, attach the new runId for UI association and bail.
  const existing = rawDb
    .prepare(
      `SELECT id FROM findings
       WHERE rule_id = ?
         AND lower(contract_address) = lower(?)
         AND chain_id = ?
       LIMIT 1`,
    )
    .get(spec.ruleId, args.contractAddress, args.chainId) as { id: string } | undefined;
  if (existing) {
    if (args.runId) {
      try {
        rawDb
          .prepare(`UPDATE findings SET run_id = ? WHERE id = ? AND (run_id IS NULL OR run_id = '')`)
          .run(args.runId, existing.id);
      } catch {}
    }
    return { ran: false, findingId: existing.id, cached: true };
  }

  // Simulation cache: replay a previous verdict if the bytecode is unchanged.
  let result: VerifyResult | null = null;
  let cachedHit = false;
  if (args.bytecodeHash) {
    const cached = rawDb
      .prepare(
        `SELECT status, verdict, evidence_json, duration_ms
         FROM simulation_cache
         WHERE bytecode_hash = ? AND rule_id = ? AND engine = ? AND engine_version = ?`,
      )
      .get(args.bytecodeHash, spec.ruleId, engine, version) as
      | { status: string; verdict: string | null; evidence_json: string | null; duration_ms: number }
      | undefined;
    if (cached) {
      cachedHit = true;
      result = {
        status: cached.status as VerdictStatus,
        verdict: cached.verdict ?? undefined,
        engine,
        engineVersion: version,
        evidence: cached.evidence_json ? safeParse(cached.evidence_json) : {},
        durationMs: cached.duration_ms,
      };
    }
  }

  if (!result) {
    result = await verifyFinding({
      chainId: args.chainId,
      contractAddress: args.contractAddress,
      ruleId: spec.ruleId,
    });
    if (args.bytecodeHash) {
      try {
        rawDb
          .prepare(
            `INSERT OR REPLACE INTO simulation_cache
               (bytecode_hash, rule_id, engine, engine_version, status, verdict, evidence_json, simulated_at, duration_ms)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          )
          .run(
            args.bytecodeHash,
            spec.ruleId,
            engine,
            version,
            result.status,
            result.verdict ?? null,
            JSON.stringify(result.evidence),
            Date.now(),
            result.durationMs,
          );
      } catch (err) {
        console.warn(`[sim] sidecar ${spec.ruleId} cache write failed`, err);
      }
    }
  }

  if (result.status !== "verified") {
    return { ran: true, status: result.status, cached: cachedHit };
  }

  // Materialise a finding row.
  const id = `sidecar-${spec.ruleId.split(".").slice(-1)[0]}-${createHash("sha1")
    .update(`${args.chainId}:${args.contractAddress.toLowerCase()}:${spec.ruleId}`)
    .digest("hex")
    .slice(0, 24)}`;
  const now = Date.now();
  const evidence: any = result.evidence ?? {};
  const confidence = spec.confidenceFor ? spec.confidenceFor(evidence) : "0.80";
  const raw = {
    sidecar: true,
    source_finding_id: args.sourceFindingId,
    cached: cachedHit,
    attackerKind: evidence?.attackerKind ?? "any",
    summary: spec.summary,
  };
  try {
    rawDb
      .prepare(
        `INSERT OR IGNORE INTO findings
           (id, run_id, rule_id, internal_name, severity, status, confidence, title, category,
            bytecode_hash, contract_address, chain_id, discovered_at, source,
            affected_functions_json, raw_json,
            simulation_status, simulation_verdict, simulation_evidence_json,
            simulation_engine, simulated_at)
         VALUES
           (?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?,
            ?, ?, ?,
            ?, ?)`,
      )
      .run(
        id,
        args.runId ?? null,
        spec.ruleId,
        spec.internalName,
        spec.severity,
        spec.status,
        confidence,
        spec.titleFor(evidence),
        spec.category,
        args.bytecodeHash ?? null,
        args.contractAddress,
        args.chainId,
        now,
        spec.source,
        JSON.stringify([]),
        JSON.stringify(raw),
        result.status,
        result.verdict ?? null,
        JSON.stringify(evidence),
        `${engine}@${version}`,
        now,
      );
    console.info(
      `[sim] sidecar ${spec.ruleId} verified for chain=${args.chainId} addr=${args.contractAddress}; finding=${id}`,
    );
    return { ran: true, status: "verified", findingId: id, cached: cachedHit };
  } catch (err) {
    console.warn(`[sim] sidecar ${spec.ruleId} insert failed`, err);
    return { ran: true, status: "verified", cached: cachedHit };
  }
}

function safeParse(json: string): any {
  try {
    return JSON.parse(json);
  } catch {
    return {};
  }
}
