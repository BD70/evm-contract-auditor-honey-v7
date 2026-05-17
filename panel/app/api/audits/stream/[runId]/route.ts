import { sseResponse } from "@/src/server/sse";
import { auditEvents, getAuditRun } from "@/src/server/audit-service";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: Request, { params }: { params: Promise<{ runId: string }> }) {
  const { runId } = await params;
  return sseResponse(req, (push) => {
    const existing = getAuditRun(runId);
    if (existing) push({ event: "snapshot", data: existing });
    const onProgress = (e: any) => push({ event: "progress", data: e });
    const onDone = (e: any) => push({ event: "done", data: e });
    auditEvents.on(`run:${runId}`, onProgress);
    auditEvents.on(`done:${runId}`, onDone);
    return () => {
      auditEvents.off(`run:${runId}`, onProgress);
      auditEvents.off(`done:${runId}`, onDone);
    };
  });
}
