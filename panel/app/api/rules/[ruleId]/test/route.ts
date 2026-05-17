import { NextResponse } from "next/server";
import { testRule } from "@/src/server/rule-service";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(_req: Request, { params }: { params: Promise<{ ruleId: string }> }) {
  const { ruleId } = await params;
  try {
    const result = await testRule(ruleId);
    return NextResponse.json(result);
  } catch (err: any) {
    return NextResponse.json({ error: err?.message ?? String(err) }, { status: 400 });
  }
}
