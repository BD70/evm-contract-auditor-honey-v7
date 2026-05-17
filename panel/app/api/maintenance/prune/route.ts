import { NextResponse } from "next/server";
import { runPrune } from "@/src/server/prune-job";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  let body: any = {};
  try { body = await req.json(); } catch {}
  const result = runPrune(body?.retention ?? {}, { vacuum: !!body?.vacuum });
  return NextResponse.json(result);
}
