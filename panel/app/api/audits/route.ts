import { NextResponse } from "next/server";
import { startAudit, type AuditInput } from "@/src/server/audit-service";
import { listAuditRuns } from "@/src/server/findings-store";
import { bootOnce } from "@/src/server/boot";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  bootOnce();
  return NextResponse.json({ rows: listAuditRuns(50) });
}

export async function POST(req: Request) {
  bootOnce();
  let body: AuditInput;
  try {
    body = (await req.json()) as AuditInput;
  } catch (err: any) {
    return NextResponse.json({ error: "invalid JSON" }, { status: 400 });
  }
  try {
    const { runId } = await startAudit(body);
    return NextResponse.json({ ok: true, runId });
  } catch (err: any) {
    return NextResponse.json({ ok: false, error: err?.message ?? String(err) }, { status: 400 });
  }
}
