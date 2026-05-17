import { NextResponse } from "next/server";
import { listRules } from "@/src/server/rule-service";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  return NextResponse.json({ rules: listRules() });
}
