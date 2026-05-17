import { sseResponse } from "@/src/server/sse";
import { eventBus, type FindingEvent } from "@/src/server/event-bus";
import { recentFindings } from "@/src/server/findings-store";
import { bootOnce } from "@/src/server/boot";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  bootOnce();
  return sseResponse(req, (push) => {
    for (const row of recentFindings(20)) {
      push({ event: "snapshot", data: row });
    }
    const onNew = (evt: FindingEvent) => push({ event: "finding", data: evt });
    eventBus.on("findings:new", onNew);
    return () => {
      eventBus.off("findings:new", onNew);
    };
  });
}
