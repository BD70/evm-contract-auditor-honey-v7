import { NextResponse } from "next/server";
import { loadLatestPoe, logRescueAction } from "@/src/server/sim/poe-store";
import { broadcastRescue, type RescueMode } from "@/src/server/rescue/broadcaster";
import { getFinding } from "@/src/server/findings-store";
import { bootOnce } from "@/src/server/boot";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * POST /api/proofs/[findingId]/rescue
 *
 * Body: {
 *   mode: "dry-run-fork" | "dry-run-sign" | "live",
 *   authToken?: string,        // required for "live"
 *   escrowOverride?: "0x..."   // only honoured by dry-run-fork
 * }
 *
 * Returns the broadcast/simulation result. Default mode is "dry-run-fork".
 *
 * "live" mode requires ALL of these env vars to be set:
 *   RESCUE_BROADCAST_ENABLED=true
 *   RESCUER_PRIVATE_KEY=0x...
 *   RESCUE_AUTH_TOKEN=...            (must match `authToken` in body)
 *   RESCUE_ESCROW_ADDR=0x...         (where funds land)
 *
 * The endpoint always logs into the rescue_actions table for the audit
 * trail, regardless of mode.
 */
export async function POST(
  req: Request,
  { params }: { params: Promise<{ findingId: string }> },
) {
  bootOnce();
  const { findingId } = await params;
  const f = getFinding(findingId);
  if (!f) return NextResponse.json({ error: "finding not found" }, { status: 404 });
  const poe = loadLatestPoe(findingId);
  if (!poe) {
    return NextResponse.json(
      { error: "no PoE artifact for this finding; run rescue-prove first" },
      { status: 400 },
    );
  }
  let body: any = {};
  try {
    body = await req.json();
  } catch {}
  const modeRaw = String(body?.mode ?? "dry-run-fork");
  const mode: RescueMode =
    modeRaw === "live" || modeRaw === "dry-run-sign" || modeRaw === "dry-run-fork"
      ? (modeRaw as RescueMode)
      : "dry-run-fork";
  if (poe.verdict !== "true_positive_drained" && poe.verdict !== "true_positive_partial") {
    return NextResponse.json(
      {
        error: `cannot rescue: PoE verdict is '${poe.verdict}'. ` +
          `Only true_positive_drained / true_positive_partial PoEs are rescuable.`,
      },
      { status: 400 },
    );
  }
  logRescueAction({
    findingId,
    attemptId: poe.attemptId,
    kind: "rescue-requested",
    actor: req.headers.get("x-forwarded-for") ?? "api",
    detail: { mode },
  });
  const result = await broadcastRescue({
    poe,
    mode,
    authToken: typeof body?.authToken === "string" ? body.authToken : null,
    escrowOverride:
      mode === "dry-run-fork" && typeof body?.escrowOverride === "string"
        ? body.escrowOverride
        : undefined,
  });
  return NextResponse.json(result);
}
