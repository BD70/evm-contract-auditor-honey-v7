import { NextResponse } from "next/server";
import { readRule } from "@/src/server/rule-service";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(_req: Request, { params }: { params: Promise<{ ruleId: string }> }) {
  const { ruleId } = await params;
  const r = readRule(ruleId);
  if (!r) return NextResponse.json({ error: "not found" }, { status: 404 });
  return NextResponse.json(r);
}
