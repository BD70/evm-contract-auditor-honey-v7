import { NextResponse } from "next/server";
import { envFieldsMeta } from "@/src/server/env-store";

export const runtime = "nodejs";

export async function GET() {
  return NextResponse.json({ fields: envFieldsMeta });
}
