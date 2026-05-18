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

/**
 * POST /api/proofs/[findingId]
 *
 * Re-runs rescue-prove for the given finding. Accepts:
 *   { force?: boolean, tokens?: string[] }
 *
 * When force=true, all value/exposure gates are bypassed — the drain plan
 * will be attempted regardless of contract balance.
 *
 * When tokens is provided, the drain plan will ONLY target those specific
 * token addresses. Each address is fetched for real-time balance. Use this
 * to rescue specific tokens even if they weren't in the original exposure scan.
 */
export async function POST(
  req: Request,
  { params }: { params: Promise<{ findingId: string }> },
) {
  bootOnce();
  const { findingId } = await params;
  const f = getFinding(findingId);
  if (!f) return NextResponse.json({ error: "finding not found" }, { status: 404 });
  if (!f.contract_address || f.chain_id == null) {
    return NextResponse.json({ error: "finding has no chain/address context" }, { status: 400 });
  }
  let body: any = {};
  try { body = await req.json(); } catch {}
  const force = body?.force === true;
  const tokens: string[] | undefined = Array.isArray(body?.tokens)
    ? body.tokens.filter((t: any) => typeof t === "string" && /^0x[a-fA-F0-9]{40}$/.test(t))
    : undefined;

  let evidence: any = {};
  try {
    evidence = f.simulation_evidence_json ? JSON.parse(f.simulation_evidence_json) : {};
  } catch { evidence = {}; }

  const { rescueProve } = await import("@/src/server/sim/rescue-prove");
  const poe = await rescueProve({
    findingId: f.id,
    chainId: f.chain_id,
    contractAddress: f.contract_address,
    ruleId: f.rule_id,
    evidence,
    force,
    targetTokens: tokens,
  });
  return NextResponse.json({ ok: true, poe });
}
