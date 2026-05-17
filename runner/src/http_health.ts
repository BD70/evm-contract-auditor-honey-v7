import type { HealthReport } from "./health.js";

// Module-level Prometheus counters — incremented by runner.ts
export const metrics = {
  auditsTotal: 0,
  auditErrorsTotal: 0,
  queueDepth: 0,
  startedAt: Date.now(),
};

let _lastReport: HealthReport | null = null;

export function setLastHealthReport(report: HealthReport): void {
  _lastReport = report;
}

function prometheusText(): string {
  const uptime = Math.floor((Date.now() - metrics.startedAt) / 1000);
  return [
    `# HELP evm_runner_audits_total Total completed audit jobs`,
    `# TYPE evm_runner_audits_total counter`,
    `evm_runner_audits_total ${metrics.auditsTotal}`,
    `# HELP evm_runner_audit_errors_total Total failed audit jobs`,
    `# TYPE evm_runner_audit_errors_total counter`,
    `evm_runner_audit_errors_total ${metrics.auditErrorsTotal}`,
    `# HELP evm_runner_queue_depth Current in-flight audit jobs`,
    `# TYPE evm_runner_queue_depth gauge`,
    `evm_runner_queue_depth ${metrics.queueDepth}`,
    `# HELP evm_runner_uptime_seconds Seconds since runner started`,
    `# TYPE evm_runner_uptime_seconds counter`,
    `evm_runner_uptime_seconds ${uptime}`,
  ].join("\n") + "\n";
}

export function startHealthServer(
  port: number,
  getHealth: () => Promise<HealthReport>,
): void {
  Bun.serve({
    port,
    fetch: async (req: Request): Promise<Response> => {
      const url = new URL(req.url);
      if (url.pathname === "/health") {
        const report = await getHealth();
        setLastHealthReport(report);
        return new Response(JSON.stringify(report), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      if (url.pathname === "/ready") {
        const report = _lastReport ?? (await getHealth());
        setLastHealthReport(report);
        const status = report.allOk ? 200 : 503;
        return new Response(JSON.stringify({ ok: report.allOk }), {
          status,
          headers: { "Content-Type": "application/json" },
        });
      }
      if (url.pathname === "/metrics") {
        return new Response(prometheusText(), {
          status: 200,
          headers: { "Content-Type": "text/plain; version=0.0.4" },
        });
      }
      return new Response("not found", { status: 404 });
    },
    error: () => new Response("internal error", { status: 500 }),
  });
}
