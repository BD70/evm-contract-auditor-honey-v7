import { NextResponse } from "next/server";
import { getFinding } from "@/src/server/findings-store";
import { loadLatestPoe, loadAllPoeForFinding, loadActionsForFinding } from "@/src/server/sim/poe-store";
import { bootOnce } from "@/src/server/boot";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * GET /api/proofs/[findingId]
 *
 * Returns the most-recent Proof-of-Exploit artifact (or null) for a finding,
 * plus the audit-trail of every rescue-related action taken for it.
 * Query: ?all=true to include every PoE attempt (chronological).
 */
export async function GET(
  req: Request,
  { params }: { params: Promise<{ findingId: string }> },
) {
  bootOnce();
  const { findingId } = await params;
  const f = getFinding(findingId);
  if (!f) return NextResponse.json({ error: "finding not found" }, { status: 404 });
  const url = new URL(req.url);
  const includeAll = url.searchParams.get("all") === "true";
  const latest = loadLatestPoe(findingId);
  const all = includeAll ? loadAllPoeForFinding(findingId) : [];
  const actions = loadActionsForFinding(findingId);
  return NextResponse.json({
    finding: {
      id: f.id,
      ruleId: f.rule_id,
      contractAddress: f.contract_address,
      chainId: f.chain_id,
      severity: f.severity,
      simulationStatus: f.simulation_status,
      simulationVerdict: f.simulation_verdict,
    },
    poe: latest,
    poeHistory: all,
    actions,
  });
}
