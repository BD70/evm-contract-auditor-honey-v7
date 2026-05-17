import { NextResponse } from "next/server";
import { batchExposure, type ExposureRequest } from "@/src/server/exposure";
import { bootOnce } from "@/src/server/boot";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// POST body: { items: [{ chainId: number, address: string }] }
// Capped at 200 items per request to keep the panel honest with QuickNode.
const MAX_ITEMS = 200;

export async function POST(req: Request) {
  bootOnce();
  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "invalid JSON" }, { status: 400 });
  }
  const raw: unknown[] = Array.isArray(body?.items) ? body.items : [];
  const items: ExposureRequest[] = [];
  for (const r of raw.slice(0, MAX_ITEMS)) {
    if (!r || typeof r !== "object") continue;
    const chainId = (r as any).chainId;
    const address = (r as any).address;
    if (typeof chainId !== "number" || typeof address !== "string") continue;
    items.push({ chainId, address });
  }
  if (items.length === 0) return NextResponse.json({ exposures: {} });
  const exposures = await batchExposure(items);
  return NextResponse.json({ exposures });
}
