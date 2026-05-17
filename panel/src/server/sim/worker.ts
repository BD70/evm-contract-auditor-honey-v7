// Background simulation worker. Polls the findings DB for unverified findings
// in the supported rule set, dedupes by (bytecode_hash, rule_id), runs the
// verification driver under a bounded concurrency, and persists the verdict
// back to the findings table + simulation_cache.
//
// Cache strategy: most flagged contracts on chain share runtime bytecode with
// many other contracts (clones, factory-deployed instances). We simulate once
// per (bytecode_hash, rule_id, engine, engine_version) and copy the verdict
// to every finding sharing that pair. This collapses a typical batch of
// ~800 findings to a much smaller number of unique bytecode/rule pairs.
//
// Each rule may be handled by a different verifier (see ./exploits/index.ts
// for the registry). The cache key includes the engine identifier so old
// verdicts produced by previous engine versions are not reused after a
// driver upgrade.

import { rawDb } from "@/src/db/client";
import { anvilPool } from "./anvil-pool";
import {
  verifyFinding,
  canVerifyRule,
  engineForRule,
  findVerifier,
  SUPPORTED_RULES,
  VERIFIERS,
} from "./exploits";
import type { VerifyResult, VerdictStatus } from "./types";
import { batchExposure, type Exposure } from "../exposure";
import { exposureSurfaceForRule, surfaceLabel, type ExposureSurface } from "./rule-surface";
import { createHash } from "node:crypto";

// Sidecar verifier setup. The economic-attack verifier catches a bug class
// that the upstream Go static analyzer can't always detect via its standard
// predicate set (e.g. it doesn't always emit SWAP_OR_LIQUIDITY_PATTERN for
// contracts that DO call AMM routers). To bridge that gap, the worker runs
// the economic-attack verifier as a SIDECAR for every contract that gets a
// primary finding — if it returns "verified", we materialise a new finding
// row for the new rule so the UI shows it alongside the original ones.
//
// This is opt-in via env (SIM_SIDECAR_ECONOMIC), default ON, because:
//   - cost is bounded (one extra anvil call per UNIQUE bytecode_hash, cached
//     in simulation_cache so the same bytecode gets verified once across all
//     its clones)
//   - false positive risk is low (verifier has both dynamic + static gates)
//   - the alternative is silently missing the bug class on contracts where
//     the static analyzer's swap-detector underfits
const SIDECAR_ECON_ENABLED = (process.env.SIM_SIDECAR_ECONOMIC ?? "true").toLowerCase() !== "false";
const SIDECAR_ECON_RULE = "economic.unguarded_amm_action";
const SIDECAR_ECON_SOURCE = "sidecar-economic-attack";

// Rescue-prove pass (rescue-prove.ts) runs after a verifier produces a
// "verified" verdict and attempts an actual drain on the fork. It only
// makes sense for rule families whose vulnerability has a directly-
// constructible drain shape (arbitrary-call, selfdestruct). Other classes
// (economic AMM attack, public initializer takeover) rely on the
// heuristic verdict for now. Gated by env so operators can disable on
// resource-constrained boxes.
const RESCUE_PROVE_ENABLED =
  String(process.env.RESCUE_PROVE_ENABLED ?? "true").toLowerCase() !== "false";

function rescueProveEligible(ruleId: string): boolean {
  if (!RESCUE_PROVE_ENABLED) return false;
  return (
    ruleId.startsWith("call.") ||
    ruleId.startsWith("control.unguarded_selfdestruct") ||
    ruleId.startsWith("init.") ||
    ruleId.startsWith("economic.")
  );
}

async function maybeRunRescueProve(input: {
  findingId: string;
  chainId: number;
  contractAddress: string;
  ruleId: string;
  evidence: unknown;
}): Promise<void> {
  // Lazy import keeps the worker's cold-start small and avoids pulling the
  // exposure pipeline into hot paths that don't need it.
  const { rescueProve } = await import("./rescue-prove");
  await rescueProve({
    findingId: input.findingId,
    chainId: input.chainId,
    contractAddress: input.contractAddress,
    ruleId: input.ruleId,
    evidence: (input.evidence as any) ?? {},
  });
}

const POLL_INTERVAL_MS = Number(process.env.SIM_POLL_INTERVAL_MS ?? 15_000);
const CONCURRENCY = Math.max(1, Number(process.env.SIM_CONCURRENCY ?? 1));
const BATCH_SIZE = Math.max(1, Number(process.env.SIM_BATCH_SIZE ?? 12));
const MIN_SEVERITIES = (process.env.SIM_SEVERITIES ?? "critical,high")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
// Exposure gating. When enabled (default), the worker fetches native+token
// balances for each contract in the batch and SKIPS simulation for contracts
// with $0 exposure. This is the dominant speedup: most flagged contracts
// hold zero value, and there's no point burning fork+rpc cycles to verify
// exploitability on something that has nothing to exploit. Remaining
// contracts are processed in exposure-descending order so the most valuable
// targets get verified first.
const REQUIRE_EXPOSURE = (process.env.SIM_REQUIRE_EXPOSURE ?? "true").toLowerCase() !== "false";
const EXPOSURE_GRACE_ON_ERROR = (process.env.SIM_EXPOSURE_GRACE_ON_ERROR ?? "true").toLowerCase() !== "false";

type Globals = { __simWorker?: SimWorker };

interface PendingFinding {
  id: string;
  rule_id: string;
  severity: string;
  contract_address: string | null;
  chain_id: number | null;
  bytecode_hash: string | null;
  source: string | null;
}

class SimWorker {
  private started = false;
  private timer: NodeJS.Timeout | null = null;
  private tickRunning = false;
  private installed: boolean | null = null;
  private stats = {
    ticks: 0,
    verified: 0,
    refuted: 0,
    inconclusive: 0,
    skipped: 0,
    skippedNoExposure: 0,
    errored: 0,
    cacheHits: 0,
    backfilled: 0,
    lastTickAt: 0 as number,
    lastError: null as string | null,
    inFlight: 0,
  };

  async startIfNeeded() {
    if (this.started) return;
    this.started = true;
    this.installed = await anvilPool.isAvailable();
    if (!this.installed) {
      console.warn("[sim] anvil not on PATH (or ANVIL_BIN unset). Simulation worker disabled.");
      return;
    }
    console.info(
      `[sim] worker enabled. verifiers=[${VERIFIERS.map((v) => `${v.id}@${v.version}`).join(",")}] ` +
        `rules=${SUPPORTED_RULES.length} severities=${MIN_SEVERITIES.join(",")} ` +
        `concurrency=${CONCURRENCY} batch=${BATCH_SIZE}`,
    );
    // Boot-time cache backfill: apply any previously-cached verdicts to
    // findings that haven't been verified yet. Cheap (one SQL pass).
    try {
      const n = this.backfillFromCache();
      if (n > 0) {
        this.stats.backfilled += n;
        console.info(`[sim] backfilled ${n} findings from simulation_cache`);
      }
    } catch (err) {
      console.warn("[sim] cache backfill failed", err);
    }
    this.schedule(POLL_INTERVAL_MS);
  }

  stop() {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    this.started = false;
  }

  getStats() {
    return { ...this.stats, enabled: !!this.installed };
  }

  /**
   * Copy verdicts from simulation_cache onto every unverified finding that
   * shares (bytecode_hash, rule_id). Idempotent: a finding that already has
   * a verdict is untouched.
   */
  private backfillFromCache(): number {
    const stmt = rawDb.prepare(
      `UPDATE findings
       SET simulation_status = (
             SELECT sc.status FROM simulation_cache sc
             WHERE sc.bytecode_hash = findings.bytecode_hash
               AND sc.rule_id = findings.rule_id
             ORDER BY sc.simulated_at DESC LIMIT 1
           ),
           simulation_verdict = (
             SELECT sc.verdict FROM simulation_cache sc
             WHERE sc.bytecode_hash = findings.bytecode_hash
               AND sc.rule_id = findings.rule_id
             ORDER BY sc.simulated_at DESC LIMIT 1
           ),
           simulation_evidence_json = (
             SELECT sc.evidence_json FROM simulation_cache sc
             WHERE sc.bytecode_hash = findings.bytecode_hash
               AND sc.rule_id = findings.rule_id
             ORDER BY sc.simulated_at DESC LIMIT 1
           ),
           simulation_engine = (
             SELECT sc.engine || '@' || sc.engine_version FROM simulation_cache sc
             WHERE sc.bytecode_hash = findings.bytecode_hash
               AND sc.rule_id = findings.rule_id
             ORDER BY sc.simulated_at DESC LIMIT 1
           ),
           simulated_at = (
             SELECT sc.simulated_at FROM simulation_cache sc
             WHERE sc.bytecode_hash = findings.bytecode_hash
               AND sc.rule_id = findings.rule_id
             ORDER BY sc.simulated_at DESC LIMIT 1
           )
       WHERE simulation_status IS NULL
         AND bytecode_hash IS NOT NULL
         AND EXISTS (
           SELECT 1 FROM simulation_cache sc2
           WHERE sc2.bytecode_hash = findings.bytecode_hash
             AND sc2.rule_id = findings.rule_id
         )`,
    );
    const info = stmt.run();
    return info.changes ?? 0;
  }

  private schedule(delay: number) {
    if (!this.started) return;
    this.timer = setTimeout(() => {
      this.tick().catch((err) => {
        this.stats.lastError = String(err?.message ?? err);
        console.warn("[sim] tick error", err);
      });
    }, delay);
    this.timer.unref?.();
  }

  private async tick() {
    if (this.tickRunning) {
      this.schedule(POLL_INTERVAL_MS);
      return;
    }
    this.tickRunning = true;
    this.stats.ticks++;
    this.stats.lastTickAt = Date.now();
    try {
      const batch = this.pickBatch();
      if (batch.length === 0) {
        this.schedule(POLL_INTERVAL_MS);
        return;
      }

      // Exposure gating + priority sort. We fetch exposure for each unique
      // (chainId, address) in the batch and:
      //   1. SKIP findings whose contract holds zero native + zero tokens.
      //      Persisted as `skipped:no_exposure` so subsequent ticks don't
      //      re-process them. On-demand re-verification via the UI still
      //      works (calls verifyFinding directly).
      //   2. Sort the remaining findings by exposure DESC so high-value
      //      contracts are processed first.
      // Exposure errors / unsupported chains are treated as "unknown" and
      // simulated normally (don't skip on transient RPC issues).
      // Exposure-gate runner findings; manual findings always run because the
      // user explicitly asked about THIS contract — they want a verdict, not
      // a "skipped because zero balance" cop-out.
      const runnerBatch = batch.filter((r) => r.source !== "manual");
      const manualBatch = batch.filter((r) => r.source === "manual");
      const exposureByKey =
        REQUIRE_EXPOSURE && runnerBatch.length > 0 ? await this.lookupExposureForBatch(runnerBatch) : null;
      const survivors: PendingFinding[] = [...manualBatch];
      const skipNoExposure: Array<{ row: PendingFinding; surface: ExposureSurface }> = [];
      for (const r of runnerBatch) {
        if (!exposureByKey || !r.contract_address || r.chain_id == null) {
          survivors.push(r);
          continue;
        }
        const k = `${r.chain_id}:${r.contract_address.toLowerCase()}`;
        const exp = exposureByKey.get(k);
        if (!exp) {
          survivors.push(r);
          continue;
        }
        if (exp.error && EXPOSURE_GRACE_ON_ERROR) {
          // RPC failure — don't punish the finding, simulate anyway.
          survivors.push(r);
          continue;
        }
        const surface = exposureSurfaceForRule(r.rule_id);
        if (hasRelevantExposure(exp, surface)) {
          survivors.push(r);
        } else {
          skipNoExposure.push({ row: r, surface });
        }
      }

      if (skipNoExposure.length > 0) {
        this.markNoExposure(skipNoExposure);
        this.stats.skippedNoExposure += skipNoExposure.length;
      }
      void surfaceLabel; // imported for use in markNoExposure
      const manualCt = manualBatch.length;
      if (exposureByKey || manualCt > 0) {
        console.info(
          `[sim] tick batch=${batch.length} manual=${manualCt} ` +
            `expKeys=${exposureByKey?.size ?? 0} noExposureSkipped=${skipNoExposure.length} ` +
            `survivors=${survivors.length}`,
        );
      } else {
        console.info(`[sim] tick batch=${batch.length} exposureGating=off survivors=${survivors.length}`);
      }
      if (survivors.length === 0) {
        this.schedule(POLL_INTERVAL_MS);
        return;
      }

      // Sort by AT-RISK exposure DESC. A finding that's drains-relevant for
      // (e.g.) native ETH is scored by its native balance only; ERC-20s on
      // the same address don't bubble it up for a selfdestruct-class rule.
      survivors.sort((a, b) => {
        const ea = relevantExposureValue(exposureByKey, a);
        const eb = relevantExposureValue(exposureByKey, b);
        if (eb !== ea) return eb - ea;
        return 0;
      });

      // Dedupe by (bytecode_hash || contract_address, rule_id).
      const seen = new Map<string, PendingFinding[]>();
      for (const r of survivors) {
        const key = `${r.bytecode_hash ?? r.contract_address ?? r.id}:${r.rule_id}`;
        const arr = seen.get(key) ?? [];
        arr.push(r);
        seen.set(key, arr);
      }
      const groups = Array.from(seen.values());

      await runWithConcurrency(groups, CONCURRENCY, async (group) => {
        await this.handleGroup(group);
      });
    } finally {
      this.tickRunning = false;
      this.schedule(POLL_INTERVAL_MS);
    }
  }

  /**
   * Bulk-fetch exposure data for every unique (chainId, address) pair in the
   * batch. Returns a map keyed by `${chainId}:${addressLower}`. Returns null
   * if nothing in the batch has a usable address.
   */
  private async lookupExposureForBatch(batch: PendingFinding[]): Promise<Map<string, Exposure> | null> {
    const seen = new Set<string>();
    const reqs: { chainId: number; address: string }[] = [];
    for (const r of batch) {
      if (!r.contract_address || r.chain_id == null) continue;
      const k = `${r.chain_id}:${r.contract_address.toLowerCase()}`;
      if (seen.has(k)) continue;
      seen.add(k);
      reqs.push({ chainId: r.chain_id, address: r.contract_address });
    }
    if (reqs.length === 0) return null;
    try {
      const obj = await batchExposure(reqs);
      const m = new Map<string, Exposure>();
      for (const [k, v] of Object.entries(obj)) m.set(k, v);
      return m;
    } catch (err) {
      console.warn("[sim] exposure lookup failed; simulating without exposure gating", err);
      return null;
    }
  }

  /**
   * Persist a `skipped:no_exposure` verdict for findings whose contract
   * holds nothing of value AT THE AT-RISK SURFACE for the rule. We don't
   * write to simulation_cache because exposure is per-contract and changes
   * over time; on-demand re-verification via the UI still runs the
   * verifier directly.
   */
  private markNoExposure(items: Array<{ row: PendingFinding; surface: ExposureSurface }>) {
    const stmt = rawDb.prepare(
      `UPDATE findings
       SET simulation_status = 'skipped',
           simulation_verdict = ?,
           simulation_evidence_json = ?,
           simulation_engine = 'exposure-gate@2',
           simulated_at = ?
       WHERE id = ?`,
    );
    const at = Date.now();
    const tx = rawDb.transaction((rows: typeof items) => {
      for (const r of rows) {
        const verdict = `no relevant exposure for this rule (target holds none of: ${surfaceLabel(r.surface)})`;
        const evidence = JSON.stringify({
          skippedReason: "no_exposure",
          ruleSurface: r.surface,
          surfaceLabel: surfaceLabel(r.surface),
        });
        stmt.run(verdict, evidence, at, r.row.id);
      }
    });
    tx(items);
  }

  /**
   * Pull the next batch of findings to verify. We prefer:
   *   1. simulation_status IS NULL (never simulated)
   *   2. rule_id in supported set
   *   3. severity in MIN_SEVERITIES
   *   4. contract_address + chain_id are usable
   * Most-recent first to prioritise live audit results.
   */
  private pickBatch(): PendingFinding[] {
    if (SUPPORTED_RULES.length === 0) return [];
    const sevPlaceholders = MIN_SEVERITIES.map(() => "?").join(",");
    const rules = SUPPORTED_RULES;
    // ORDER BY source='manual' first so user-initiated audits get verified
    // ahead of background runner findings, then most-recent.
    const rows = rawDb
      .prepare(
        `SELECT id, rule_id, severity, contract_address, chain_id, bytecode_hash, source
         FROM findings
         WHERE simulation_status IS NULL
           AND rule_id IN (${rules.map(() => "?").join(",")})
           AND severity IN (${sevPlaceholders})
           AND contract_address IS NOT NULL
           AND chain_id IS NOT NULL
         ORDER BY (CASE WHEN source = 'manual' THEN 0 ELSE 1 END), discovered_at DESC
         LIMIT ?`,
      )
      .all(...rules, ...MIN_SEVERITIES, BATCH_SIZE) as PendingFinding[];
    return rows;
  }

  /**
   * Wake the worker up. Reschedules the next tick to fire immediately so
   * manual audits don't have to wait for the next poll interval to see their
   * findings verified.
   */
  wake() {
    if (!this.started || !this.installed) return;
    if (this.tickRunning) return; // a tick is already running; it'll auto-reschedule
    if (this.timer) clearTimeout(this.timer);
    this.schedule(50);
  }

  private async handleGroup(group: PendingFinding[]) {
    const first = group[0];
    const engineInfo = engineForRule(first.rule_id);
    if (!engineInfo) {
      // shouldn't happen since pickBatch filters to SUPPORTED_RULES, but be safe
      return;
    }
    // Manual audits ALWAYS run fresh. The user just asked for this contract;
    // serving them a stale "not_exploitable" verdict from an earlier engine
    // run would defeat the purpose of the audit button. Runner findings still
    // benefit from the cache (shared bytecode is common at scale).
    const isManual = group.some((g) => g.source === "manual");
    const cacheRow = !isManual && first.bytecode_hash
      ? (rawDb
          .prepare(
            `SELECT status, verdict, evidence_json, simulated_at
             FROM simulation_cache
             WHERE bytecode_hash = ? AND rule_id = ? AND engine = ? AND engine_version = ?`,
          )
          .get(first.bytecode_hash, first.rule_id, engineInfo.engine, engineInfo.version) as
          | { status: string; verdict: string | null; evidence_json: string | null; simulated_at: number }
          | undefined)
      : undefined;

    if (cacheRow) {
      this.stats.cacheHits++;
      this.applyVerdictToFindings(
        group,
        {
          status: cacheRow.status as VerdictStatus,
          verdict: cacheRow.verdict ?? undefined,
          engine: engineInfo.engine,
          engineVersion: engineInfo.version,
          evidence: cacheRow.evidence_json ? safeParse(cacheRow.evidence_json) : {},
          durationMs: 0,
        } as VerifyResult,
        engineInfo,
      );
      return;
    }

    this.stats.inFlight++;
    let result: VerifyResult;
    try {
      result = await verifyFinding({
        chainId: first.chain_id!,
        contractAddress: first.contract_address!,
        ruleId: first.rule_id,
      });
    } catch (err: any) {
      result = {
        status: "error",
        verdict: String(err?.message ?? err).slice(0, 200),
        engine: engineInfo.engine,
        engineVersion: engineInfo.version,
        evidence: {
          chainId: first.chain_id!,
          contractAddress: first.contract_address!,
          ruleId: first.rule_id,
          reason: `worker exception: ${err?.message ?? err}`,
        },
        durationMs: 0,
      };
      this.stats.lastError = String(err?.message ?? err);
    } finally {
      this.stats.inFlight--;
    }

    if (first.bytecode_hash) {
      try {
        rawDb
          .prepare(
            `INSERT OR REPLACE INTO simulation_cache
               (bytecode_hash, rule_id, engine, engine_version, status, verdict, evidence_json, simulated_at, duration_ms)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          )
          .run(
            first.bytecode_hash,
            first.rule_id,
            result.engine,
            result.engineVersion,
            result.status,
            result.verdict ?? null,
            JSON.stringify(result.evidence),
            Date.now(),
            result.durationMs,
          );
      } catch (err) {
        console.warn("[sim] cache write failed", err);
      }
    }

    this.applyVerdictToFindings(group, result, engineInfo);

    if (first.bytecode_hash) {
      try {
        const others = rawDb
          .prepare(
            `SELECT id FROM findings
             WHERE bytecode_hash = ? AND rule_id = ? AND simulation_status IS NULL`,
          )
          .all(first.bytecode_hash, first.rule_id) as { id: string }[];
        if (others.length > 0) {
          this.applyVerdictToFindings(others.map((o) => ({ id: o.id }) as any), result, engineInfo);
        }
      } catch (err) {
        console.warn("[sim] backfill propagate failed", err);
      }
    }

    if (result.status === "verified") this.stats.verified++;
    else if (result.status === "not_exploitable") this.stats.refuted++;
    else if (result.status === "inconclusive") this.stats.inconclusive++;
    else if (result.status === "error") this.stats.errored++;
    else this.stats.skipped++;

    // Sidecar pass: run the economic-attack verifier on this contract if
    // (a) it's enabled, (b) the primary verifier isn't the economic-attack
    // one (avoid recursion), (c) we have the basic inputs. Result is cached
    // by (bytecode_hash, sidecar rule_id) so the same bytecode is verified
    // exactly once across all its clones.
    if (
      SIDECAR_ECON_ENABLED &&
      first.contract_address &&
      first.chain_id != null &&
      engineInfo.engine !== "anvil-fork-economic"
    ) {
      try {
        await runEconomicSidecar({
          chainId: first.chain_id,
          contractAddress: first.contract_address,
          bytecodeHash: first.bytecode_hash,
          sourceFindingId: first.id,
        });
      } catch (err) {
        console.warn("[sim] economic sidecar failed", err);
      }
    }

    // Rescue-prove pass: if the primary verifier concluded the finding is
    // exploitable, run the rescue-prove module to definitively confirm it
    // by attempting an actual drain on the fork. This produces a PoE
    // artifact that the TG bot / rescue broadcaster consume. Best-effort —
    // never fails the verifier pass.
    if (
      result.status === "verified" &&
      first.contract_address &&
      first.chain_id != null &&
      rescueProveEligible(first.rule_id)
    ) {
      try {
        await maybeRunRescueProve({
          findingId: first.id,
          chainId: first.chain_id,
          contractAddress: first.contract_address,
          ruleId: first.rule_id,
          evidence: result.evidence,
        });
      } catch (err) {
        console.warn("[sim] rescue-prove failed", err);
      }
    }
  }

  private applyVerdictToFindings(
    rows: PendingFinding[],
    result: VerifyResult,
    engineInfo: { engine: string; version: string },
  ) {
    const stmt = rawDb.prepare(
      `UPDATE findings
       SET simulation_status = ?,
           simulation_verdict = ?,
           simulation_evidence_json = ?,
           simulation_engine = ?,
           simulated_at = ?
       WHERE id = ?`,
    );
    const tx = rawDb.transaction((rows: PendingFinding[]) => {
      const at = Date.now();
      const engineStr = `${engineInfo.engine}@${engineInfo.version}`;
      for (const r of rows) {
        stmt.run(
          result.status,
          result.verdict ?? null,
          JSON.stringify(result.evidence),
          engineStr,
          at,
          r.id,
        );
      }
    });
    tx(rows);
  }
}

function safeParse(s: string): any {
  try {
    return JSON.parse(s);
  } catch {
    return {};
  }
}

/** True iff the contract holds any value of the AT-RISK surface.
 *
 * For `native`-only rules (e.g. unguarded selfdestruct) we only check the
 * native balance — having ERC-20 balances does NOT make the contract a
 * worthy target for a selfdestruct exploit. For `token`-only rules we
 * skip when the native balance is non-zero but token balances are all
 * zero. For `both` we accept either.
 *
 * On chains where token enumeration is unsupported (`tokenScanUnsupported`),
 * we can only judge native balance — for `token`-only rules we then fall
 * back to "unknown ≠ proven" and skip; for `both` rules we accept any
 * non-zero native. On-demand verification via the UI button bypasses
 * this filter for the curious.
 */
function hasRelevantExposure(exp: Exposure, surface: ExposureSurface): boolean {
  if (!exp) return false;
  if (surface === "none") return false;
  const hasNative = Boolean(exp.nativeWei && exp.nativeWei !== "0");
  const hasToken =
    Array.isArray(exp.tokens) && exp.tokens.some((t) => t.balance && t.balance !== "0");
  switch (surface) {
    case "native":
      return hasNative;
    case "token":
      return hasToken;
    case "both":
      return hasNative || hasToken;
  }
}

/**
 * Score used to sort findings by AT-RISK exposure DESC. Surface-aware
 * USD when the pricing layer has data (post-v3 exposure pipeline);
 * falls back to coarse native-amount-as-ETH if USD is missing so we
 * never score an unknown contract as zero just because Coingecko was
 * slow.
 *
 *   - native-only rules score by nativeUsdValue (USD) or nativeWei/1e18 (fallback)
 *   - token-only rules score by tokensUsdValue (USD) or non-zero token count
 *   - both rules sum the two
 *   - "none" rules always score 0 (won't be prioritised)
 */
function relevantExposureValue(
  byKey: Map<string, Exposure> | null | undefined,
  r: PendingFinding,
): number {
  if (!byKey || !r.contract_address || r.chain_id == null) return 0;
  const exp = byKey.get(`${r.chain_id}:${r.contract_address.toLowerCase()}`);
  if (!exp) return 0;
  const surface = exposureSurfaceForRule(r.rule_id);
  if (surface === "none") return 0;
  let v = 0;
  if (surface === "native" || surface === "both") {
    if (exp.nativeUsdValue != null) {
      v += exp.nativeUsdValue;
    } else if (exp.nativeWei && exp.nativeWei !== "0") {
      try {
        const wei = BigInt(exp.nativeWei);
        const div = 1_000_000_000_000_000_000n;
        v += Number((wei * 1000n) / div) / 1000;
      } catch {
        v += 1;
      }
    }
  }
  if (surface === "token" || surface === "both") {
    if (exp.tokensUsdValue != null) {
      v += exp.tokensUsdValue;
    } else if (Array.isArray(exp.tokens)) {
      const nonZero = exp.tokens.filter((t) => t.balance && t.balance !== "0").length;
      v += nonZero * 0.01;
    }
  }
  if (!Number.isFinite(v)) v = 0;
  return v;
}

async function runWithConcurrency<T>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<void>,
): Promise<void> {
  let i = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) {
      const idx = i++;
      try {
        await fn(items[idx]);
      } catch (err) {
        console.warn("[sim] worker exception", err);
      }
    }
  });
  await Promise.all(workers);
}

export { canVerifyRule, SUPPORTED_RULES };

const g = globalThis as unknown as Globals;
if (!g.__simWorker) g.__simWorker = new SimWorker();
export const simWorker = g.__simWorker!;

/**
 * Runs the economic-attack verifier on the given contract and, if it returns
 * "verified", materialises a new finding row tagged
 * `source=sidecar-economic-attack`. Idempotent: if a sidecar finding for
 * this (chain, address, rule) already exists, we skip without re-running.
 *
 * Exported so the on-demand /api/simulation route can also trigger the
 * sidecar (otherwise on-demand verifies would silently miss this bug class).
 */
export async function runEconomicSidecar(args: {
  chainId: number;
  contractAddress: string;
  bytecodeHash?: string | null;
  sourceFindingId?: string;
  /** Optional audit run to associate with the sidecar finding. When set, a
   *  freshly materialised sidecar finding gets this run_id, and an EXISTING
   *  sidecar finding for the same (chain, address, rule) gets its run_id
   *  rewritten to this value so the manual-audit UI surfaces it under the
   *  run the user just triggered. */
  runId?: string;
}): Promise<{ ran: boolean; status?: string; findingId?: string; cached?: boolean }> {
  if (!SIDECAR_ECON_ENABLED) return { ran: false };
  const econVerifier = findVerifier(SIDECAR_ECON_RULE);
  if (!econVerifier) return { ran: false };
  const engine = econVerifier.id;
  const version = econVerifier.version;

  const existing = rawDb
    .prepare(
      `SELECT id FROM findings
       WHERE rule_id = ?
         AND lower(contract_address) = lower(?)
         AND chain_id = ?
       LIMIT 1`,
    )
    .get(SIDECAR_ECON_RULE, args.contractAddress, args.chainId) as { id: string } | undefined;
  if (existing) {
    // Idempotent re-link: a previous run already produced this sidecar
    // finding. If this call came from a manual audit, attach the run_id so
    // GET /api/audits/[runId] surfaces it under the user's run.
    if (args.runId) {
      try {
        rawDb
          .prepare(`UPDATE findings SET run_id = ? WHERE id = ? AND (run_id IS NULL OR run_id = '')`)
          .run(args.runId, existing.id);
      } catch {}
    }
    return { ran: false, findingId: existing.id, cached: true };
  }

  let result: VerifyResult | null = null;
  let cachedHit = false;

  if (args.bytecodeHash) {
    const cached = rawDb
      .prepare(
        `SELECT status, verdict, evidence_json, duration_ms
         FROM simulation_cache
         WHERE bytecode_hash = ? AND rule_id = ? AND engine = ? AND engine_version = ?`,
      )
      .get(args.bytecodeHash, SIDECAR_ECON_RULE, engine, version) as
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
      ruleId: SIDECAR_ECON_RULE,
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
            SIDECAR_ECON_RULE,
            engine,
            version,
            result.status,
            result.verdict ?? null,
            JSON.stringify(result.evidence),
            Date.now(),
            result.durationMs,
          );
      } catch (err) {
        console.warn("[sim] sidecar cache write failed", err);
      }
    }
  }

  if (result.status !== "verified") return { ran: true, status: result.status, cached: cachedHit };

  // Materialise a new finding row tagged as sidecar product.
  const id = `sidecar-econ-${createHash("sha1")
    .update(`${args.chainId}:${args.contractAddress.toLowerCase()}:${SIDECAR_ECON_RULE}`)
    .digest("hex")
    .slice(0, 24)}`;
  const now = Date.now();
  const evidence: any = result.evidence ?? {};
  const attackerKind = evidence.attackerKind ?? "any";
  const viaStatic = Boolean(evidence.viaStaticEvidence);
  const sigKind: string | undefined = evidence.staticSignatureKind;
  let title: string;
  if (sigKind === "pair-direct") {
    title =
      "Permissionless pair-direct manipulation (sync/skim/burn) — deflationary-burn / flash-loan exploitable";
  } else if (sigKind === "both") {
    title =
      "Permissionless function with router swap AND pair-direct manipulation — flash-loan exploitable";
  } else if (viaStatic) {
    title = "Permissionless function triggers AMM swap (static evidence) — flash-loan exploitable";
  } else {
    title = "Permissionless function triggers AMM swap — flash-loan exploitable";
  }

  const raw = {
    sidecar: true,
    source_finding_id: args.sourceFindingId,
    cached: cachedHit,
    attackerKind,
    viaStaticEvidence: viaStatic,
    summary:
      "Sidecar verifier (anvil-fork-economic) confirmed this contract exposes a " +
      "permissionless function that reaches an AMM router swap. Vulnerable to flash-loan " +
      "price manipulation.",
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
        SIDECAR_ECON_RULE,
        "sidecar_economic_unguarded_amm_action_v1",
        "critical",
        "probable_vulnerability",
        attackerKind === "any" ? "0.85" : "0.65",
        title,
        "access_control",
        args.bytecodeHash ?? null,
        args.contractAddress,
        args.chainId,
        now,
        SIDECAR_ECON_SOURCE,
        JSON.stringify([]),
        JSON.stringify(raw),
        result.status,
        result.verdict ?? null,
        JSON.stringify(evidence),
        `${engine}@${version}`,
        now,
      );
    console.info(
      `[sim] sidecar economic-attack verified for chain=${args.chainId} addr=${args.contractAddress} ` +
        `(attackerKind=${attackerKind}, viaStatic=${viaStatic}); finding=${id}`,
    );
    return { ran: true, status: "verified", findingId: id, cached: cachedHit };
  } catch (err) {
    console.warn("[sim] sidecar finding insert failed", err);
    return { ran: true, status: "verified", cached: cachedHit };
  }
}
