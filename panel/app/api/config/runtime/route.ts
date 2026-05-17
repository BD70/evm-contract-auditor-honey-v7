import { NextResponse } from "next/server";
import { auditorBinInfo } from "@/src/server/auditor-bin";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  return NextResponse.json({
    platform: process.platform,
    arch: process.arch,
    binaries: auditorBinInfo(),
  });
}
