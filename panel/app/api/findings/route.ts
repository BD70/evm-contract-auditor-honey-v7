import { NextResponse } from "next/server";
import { queryFindings, severityCounts } from "@/src/server/findings-store";
import { bootOnce } from "@/src/server/boot";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  bootOnce();
  const url = new URL(req.url);
  const sp = url.searchParams;
  const severity = sp.getAll("severity").flatMap((s) => s.split(",")).filter(Boolean);
  const simStatus = sp.getAll("simStatus").flatMap((s) => s.split(",")).filter(Boolean);
  const since = sp.get("since") ? Number(sp.get("since")) : undefined;
  const result = queryFindings({
    limit: sp.get("limit") ? Number(sp.get("limit")) : 50,
    offset: sp.get("offset") ? Number(sp.get("offset")) : 0,
    severity: severity.length ? severity : undefined,
    source: (sp.get("source") as any) ?? undefined,
    ruleId: sp.get("ruleId") ?? undefined,
    search: sp.get("q") ?? undefined,
    chainId: sp.get("chainId") ? Number(sp.get("chainId")) : undefined,
    status: sp.get("status") ?? undefined,
    simStatus: simStatus.length ? simStatus : undefined,
    since,
  });
  const stats = severityCounts(since ?? Date.now() - 24 * 3600 * 1000);
  return NextResponse.json({ ...result, severityCounts: stats });
}
