/**
 * One-off probe: pipe a hand-picked set of `proxy.upgradeTo_unprotected_v2`
 * candidates through `rescueProve` to measure how many are actually
 * drainable (vs how many are bare implementation contracts with no state).
 *
 * Usage:
 *   pnpm tsx scripts/probe-proxy-v2-rescue.ts < /tmp/probe/test_targets.txt
 *
 * Input format: each non-empty line of stdin:
 *   chainId|chainKey|0xaddress|bytecodeSize|relativePath
 *
 * Output: a JSON summary + per-target verdict to stdout.
 */
import { rescueProve } from "@/src/server/sim/rescue-prove";
import { bootOnce } from "@/src/server/boot";
import { nanoid } from "nanoid";

interface Target {
  chainId: number;
  chainKey: string;
  address: string;
  size: number;
}

async function main() {
  bootOnce();

  // Slurp stdin
  const chunks: string[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk.toString());
  const raw = chunks.join("");

  const targets: Target[] = [];
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const parts = trimmed.split("|");
    if (parts.length < 4) continue;
    targets.push({
      chainId: Number(parts[0]),
      chainKey: parts[1],
      address: parts[2],
      size: Number(parts[3]),
    });
  }

  if (targets.length === 0) {
    console.error("no targets on stdin");
    process.exit(1);
  }

  console.error(`probe: running rescue-prove on ${targets.length} target(s)`);
  console.error("------------------------------------------------------------");

  const results: Array<{
    target: Target;
    verdict: string;
    drainableUsd: number | null;
    totalUsd: number | null;
    elapsedMs: number;
    notes: string[];
    planSteps: number;
    error: string | null;
  }> = [];

  for (let i = 0; i < targets.length; i++) {
    const t = targets[i];
    const startedAt = Date.now();
    const label = `[${i + 1}/${targets.length}] ${t.chainKey}:${t.address}`;
    console.error(`${label} starting...`);
    try {
      const poe = await rescueProve({
        findingId: `probe-${nanoid(12)}`,
        chainId: t.chainId,
        contractAddress: t.address,
        ruleId: "proxy.upgradeTo_unprotected_v2",
        evidence: {
          attackerKind: "any",
          selectors: ["0x3659cfe6", "0x4f1ef286"],
        },
      });
      const elapsedMs = Date.now() - startedAt;
      const drainable = poe.totalRescuedUsd ?? 0;
      const preNative = poe.preState?.nativeUsd ?? 0;
      const preTokens = (poe.preState?.tokens ?? []).reduce(
        (acc, t) => acc + (t.usdValue ?? 0),
        0,
      );
      const total = preNative + preTokens;
      results.push({
        target: t,
        verdict: poe.verdict ?? "unknown",
        drainableUsd: drainable,
        totalUsd: total,
        elapsedMs,
        notes: poe.notes ?? [],
        planSteps: (poe.drainPlan ?? []).length,
        error: poe.error ?? null,
      });
      console.error(
        `${label} verdict=${poe.verdict} drainUSD=${drainable.toFixed(2)} totalUSD=${total.toFixed(2)} steps=${(poe.drainPlan ?? []).length} (${elapsedMs}ms)`,
      );
    } catch (err: any) {
      const elapsedMs = Date.now() - startedAt;
      results.push({
        target: t,
        verdict: "ERROR",
        drainableUsd: null,
        totalUsd: null,
        elapsedMs,
        notes: [],
        planSteps: 0,
        error: String(err?.message ?? err),
      });
      console.error(`${label} ERROR: ${err?.message ?? err}`);
    }
  }

  console.error("------------------------------------------------------------");
  const byVerdict: Record<string, number> = {};
  let totalDrainable = 0;
  let totalExposure = 0;
  for (const r of results) {
    byVerdict[r.verdict] = (byVerdict[r.verdict] ?? 0) + 1;
    totalDrainable += r.drainableUsd ?? 0;
    totalExposure += r.totalUsd ?? 0;
  }
  console.error("verdict distribution:");
  for (const [v, n] of Object.entries(byVerdict).sort((a, b) => b[1] - a[1])) {
    console.error(`  ${n.toString().padStart(3, " ")}  ${v}`);
  }
  console.error(`total exposure  : $${totalExposure.toFixed(2)}`);
  console.error(`total drainable : $${totalDrainable.toFixed(2)}`);

  // Machine-readable JSON to file (stdout is polluted by bootOnce loggers)
  const resultsFile = process.env.RESULTS_FILE ?? "/tmp/probe/rp_results.json";
  const { writeFileSync } = await import("node:fs");
  writeFileSync(
    resultsFile,
    JSON.stringify(
      {
        count: results.length,
        byVerdict,
        totalDrainableUsd: totalDrainable,
        totalExposureUsd: totalExposure,
        results: results.map((r) => ({
          chainId: r.target.chainId,
          chainKey: r.target.chainKey,
          address: r.target.address,
          size: r.target.size,
          verdict: r.verdict,
          drainableUsd: r.drainableUsd,
          totalUsd: r.totalUsd,
          elapsedMs: r.elapsedMs,
          planSteps: r.planSteps,
          notes: r.notes,
          error: r.error,
        })),
      },
      null,
      2,
    ),
  );
  console.error(`results written to ${resultsFile}`);
  // Force-exit because bootOnce's background workers keep the event loop alive
  process.exit(0);
}

main().catch((err) => {
  console.error("fatal:", err);
  process.exit(2);
});
