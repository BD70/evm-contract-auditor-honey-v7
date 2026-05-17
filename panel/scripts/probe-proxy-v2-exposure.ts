/**
 * Cheap exposure batch-check: take all 114 v2-FIRED proxy candidates and
 * ask `batchExposure` what they're worth. Cheaper than rescue-prove
 * because it doesn't spawn anvil forks — just price the balance sheets.
 *
 * Reads chainId|chainKey|0xaddress|size|path on stdin.
 * Writes a sorted summary to RESULTS_FILE (defaults to /tmp/probe/exposure.json).
 */
import { batchExposure } from "@/src/server/exposure";
import { writeFileSync } from "node:fs";

const RESULTS_FILE = process.env.RESULTS_FILE ?? "/tmp/probe/exposure.json";

async function main() {
  const chunks: string[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk.toString());
  const raw = chunks.join("");

  const targets: Array<{ chainId: number; chainKey: string; address: string; size: number }> = [];
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

  console.error(`probe-exposure: checking ${targets.length} contract(s)`);

  // batchExposure batches by chain internally, so just feed it all
  const t0 = Date.now();
  const expMap = await batchExposure(
    targets.map((t) => ({ chainId: t.chainId, address: t.address })),
  );
  const elapsedMs = Date.now() - t0;

  const rows = targets.map((t) => {
    const key = `${t.chainId}:${t.address.toLowerCase()}`;
    const exp = (expMap as any)[key];
    const totalUsd = exp?.totalUsdValue ?? null;
    const nativeUsd = exp?.nativeUsd ?? null;
    const tokenCount = (exp?.tokens?.length ?? 0) as number;
    const pricedTokens = (exp?.tokens ?? []).filter(
      (tk: any) => (tk?.usdValue ?? 0) > 0,
    ).length;
    return {
      chainId: t.chainId,
      chainKey: t.chainKey,
      address: t.address,
      sizeBytes: t.size,
      totalUsd,
      nativeUsd,
      tokenCount,
      pricedTokens,
    };
  });

  rows.sort((a, b) => (b.totalUsd ?? 0) - (a.totalUsd ?? 0));

  const withValue = rows.filter((r) => (r.totalUsd ?? 0) >= 1).length;
  const withDust = rows.filter(
    (r) => (r.totalUsd ?? 0) > 0 && (r.totalUsd ?? 0) < 1,
  ).length;
  const zero = rows.filter((r) => !r.totalUsd).length;

  console.error(`probe-exposure: ${elapsedMs}ms`);
  console.error(`  with priced value >= $1 : ${withValue}`);
  console.error(`  with dust (>$0, <$1)    : ${withDust}`);
  console.error(`  zero/unpriced           : ${zero}`);

  if (withValue > 0) {
    console.error("");
    console.error("=== top 20 by total USD ===");
    for (const r of rows.slice(0, Math.min(20, withValue))) {
      console.error(
        `  $${(r.totalUsd ?? 0).toFixed(2).padStart(12)}  ${r.chainKey.padEnd(20)}  ${r.address}  (${r.pricedTokens}/${r.tokenCount} priced)`,
      );
    }
  }

  writeFileSync(
    RESULTS_FILE,
    JSON.stringify(
      {
        count: rows.length,
        elapsedMs,
        withValue,
        withDust,
        zero,
        rows,
      },
      null,
      2,
    ),
  );
  console.error(`results written to ${RESULTS_FILE}`);
  // Force-exit because bootOnce's background workers keep the event loop alive
  process.exit(0);
}

main().catch((err) => {
  console.error("fatal:", err);
  process.exit(2);
});
