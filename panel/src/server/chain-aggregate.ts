
import { runnerRegistry } from "./runner-controller";
import type { ChainEntry } from "./chains-store";

const SUM_METRICS = [
  "evm_runner_audits_total",
  "evm_runner_audit_errors_total",
  "evm_runner_queue_depth",
  "evm_runner_webhook_deliveries_total",
  "evm_runner_webhook_failures_total",
  "evm_runner_blocks_processed_total",
  "evm_runner_contracts_seen_total",
  "evm_runner_contracts_audited_total",
];

export interface AggregateState {
  chainMode: true;
  status: "running" | "idle" | "crashed";
  running: number;
  total: number;
  pid: null;
  startedAt: number | null;
  lastError: string | null;
  metrics: Record<string, number> | null;
  health: Record<string, unknown> | null;
  chains: { slug: string; status: string; pid: number | null }[];
}

export function buildAggregateState(enabledChains: ChainEntry[]): AggregateState {
  const snaps = enabledChains.map((c) => {
    const ctrl = runnerRegistry.get(c.slug);
    return {
      slug: c.slug,
      status: ctrl?.status ?? "idle",
      pid: ctrl?.pid ?? null,
      startedAt: ctrl?.startedAt ?? null,
      lastError: ctrl?.lastError ?? null,
      metrics: ctrl?.metrics ?? null,
      health: ctrl?.health ?? null,
    };
  });

  const running = snaps.filter((s) => s.status === "running" || s.status === "starting").length;
  const crashed = snaps.filter((s) => s.status === "crashed").length;
  const aggStatus: AggregateState["status"] =
    running > 0 ? "running" : crashed > 0 ? "crashed" : "idle";

  // Earliest startedAt among running/starting chains.
  const startedAts = snaps
    .filter((s) => s.status === "running" || s.status === "starting")
    .map((s) => s.startedAt)
    .filter((t): t is number => t != null);
  const startedAt = startedAts.length > 0 ? Math.min(...startedAts) : null;

  // First error.
  const lastError = snaps.find((s) => s.lastError)?.lastError ?? null;

  // Sum metrics across all chains.
  let metrics: Record<string, number> | null = null;
  for (const snap of snaps) {
    if (!snap.metrics) continue;
    if (!metrics) metrics = {};
    for (const key of SUM_METRICS) {
      if (key in snap.metrics) {
        metrics[key] = (metrics[key] ?? 0) + snap.metrics[key];
      }
    }
    // Uptime: longest running chain.
    const up = snap.metrics["evm_runner_uptime_seconds"];
    if (up != null) {
      metrics["evm_runner_uptime_seconds"] = Math.max(
        metrics["evm_runner_uptime_seconds"] ?? 0,
        up,
      );
    }
  }

  // Health: merge lastProcessedBlock (max) + chainId from first running chain.
  let health: Record<string, unknown> | null = null;
  for (const snap of snaps) {
    if (!snap.health) continue;
    if (!health) health = {};
    const block =
      snap.health["lastProcessedBlock"] ??
      (snap.health["checkpoint"] as any)?.lastProcessedBlock;
    if (typeof block === "number") {
      const cur = (health["lastProcessedBlock"] as number | undefined) ?? -1;
      if (block > cur) {
        health["lastProcessedBlock"] = block;
        health["chainId"] = snap.health["chainId"];
      }
    }
  }

  return {
    chainMode: true,
    status: aggStatus,
    running,
    total: enabledChains.length,
    pid: null,
    startedAt,
    lastError,
    metrics,
    health,
    chains: snaps.map((s) => ({ slug: s.slug, status: s.status, pid: s.pid })),
  };
}
