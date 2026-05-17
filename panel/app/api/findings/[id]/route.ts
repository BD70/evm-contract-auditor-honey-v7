import { NextResponse } from "next/server";
import { getFinding } from "@/src/server/findings-store";
import { bootOnce } from "@/src/server/boot";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  bootOnce();
  const { id } = await params;
  const f = getFinding(id);
  if (!f) return NextResponse.json({ error: "not found" }, { status: 404 });
  return NextResponse.json(f);
}
