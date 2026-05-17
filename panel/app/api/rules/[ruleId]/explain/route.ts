import { NextResponse } from "next/server";
import { explainRule } from "@/src/server/rule-service";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: Request, { params }: { params: Promise<{ ruleId: string }> }) {
  const { ruleId } = await params;
  let body: any;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "invalid JSON" }, { status: 400 }); }
  const auditJson = body?.auditJson;
  if (!auditJson || typeof auditJson !== "object") {
    return NextResponse.json({ error: "missing auditJson" }, { status: 400 });
  }
  try {
    const result = await explainRule(ruleId, auditJson);
    return NextResponse.json(result);
  } catch (err: any) {
    return NextResponse.json({ error: err?.message ?? String(err) }, { status: 400 });
  }
}
