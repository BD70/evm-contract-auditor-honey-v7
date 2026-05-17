import { NextResponse } from "next/server";
import { loadLatestPoe } from "@/src/server/sim/poe-store";
import { bootOnce } from "@/src/server/boot";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * GET /api/proofs/[findingId]/poe.json
 *
 * Plain-JSON download of the latest PoE artifact for a finding. Returned
 * with a Content-Disposition so a TG bot or rescue-broadcast tool can pipe
 * it directly into a file. Returns 404 when no PoE has been produced yet.
 */
export async function GET(
  _req: Request,
  { params }: { params: Promise<{ findingId: string }> },
) {
  bootOnce();
  const { findingId } = await params;
  const poe = loadLatestPoe(findingId);
  if (!poe) return NextResponse.json({ error: "no PoE for this finding" }, { status: 404 });
  return new NextResponse(JSON.stringify(poe, null, 2), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Content-Disposition": `attachment; filename=\"poe-${findingId}.json\"`,
    },
  });
}
