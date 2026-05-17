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
 *
 *   // v8+: operator-override knobs for forcing a rescue on a verdict the
 *   // heuristic deemed non-actionable, and/or restricting which drain
 *   // steps are actually broadcast.
 *   force?: boolean,                // bypass verdict gate (default false)
 *   selectedSteps?: number[],       // restrict drainPlan to these indices
 *   selectedAssets?: string[],      // alt: restrict by per-step asset substring
 *                                   //  (e.g. token address or symbol). Each
 *                                   //  step is kept if step.asset includes one
 *                                   //  of the given substrings (case-insensitive).
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
 * Without `force`, only true_positive_drained / true_positive_partial PoEs
 * are accepted. With `force=true` the verdict gate is bypassed AND the
 * caller is expected to have selected which steps to fire (or accept all
 * available steps) — this is how operators rescue dust contracts whose
 * tokens have no Coingecko price, or who want to fire only the subset of
 * steps they believe will actually move value.
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
  const force = body?.force === true;
  const selectedSteps: number[] | null = Array.isArray(body?.selectedSteps)
    ? body.selectedSteps.filter((n: any) => typeof n === "number" && Number.isInteger(n) && n >= 0)
    : null;
  const selectedAssets: string[] | null = Array.isArray(body?.selectedAssets)
    ? body.selectedAssets
        .filter((s: any) => typeof s === "string" && s.length > 0)
        .map((s: string) => s.toLowerCase())
    : null;

  // Verdict gate. Without `force`, only verdicts the heuristic deemed
  // safely-broadcastable pass. With `force`, ANY verdict is allowed —
  // it's on the operator to know what they're doing. We still require at
  // least one drain step to be present (otherwise the broadcast would be
  // a no-op).
  const SAFE_VERDICTS = new Set<string>([
    "true_positive_drained",
    "true_positive_partial",
    // requires_flashloan_helper is broadcastable IFF a receiver is
    // configured for the chain. The broadcaster checks this gate itself.
    "requires_flashloan_helper",
    // victim_approval_rescue is broadcastable IFF consented victims exist.
    "victim_approval_rescue",
  ]);
  if (!force && !SAFE_VERDICTS.has(poe.verdict)) {
    return NextResponse.json(
      {
        error:
          `cannot rescue: PoE verdict is '${poe.verdict}'. ` +
          `Only [${[...SAFE_VERDICTS].join(", ")}] are rescuable by default. ` +
          `Use { force: true, selectedSteps: [...] } to override and broadcast specific drain ` +
          `steps anyway (e.g. for unpriced tokens or precondition-gap surfaces the heuristic ` +
          `couldn't auto-validate).`,
      },
      { status: 400 },
    );
  }
  if (force && poe.drainPlan.length === 0) {
    return NextResponse.json(
      {
        error:
          `cannot force-rescue: this PoE has an empty drainPlan. There are no candidate steps ` +
          `to broadcast. Re-run rescue-prove with RESCUE_INCLUDE_DUST=true (to keep candidates ` +
          `for unpriced tokens) or RESCUE_ATTEMPT_ALL_ADMIN=true (to keep admin-named selectors ` +
          `even when bytecode-PUSHed evidence is weak).`,
      },
      { status: 400 },
    );
  }

  logRescueAction({
    findingId,
    attemptId: poe.attemptId,
    kind: "rescue-requested",
    actor: req.headers.get("x-forwarded-for") ?? "api",
    detail: {
      mode,
      force,
      selectedSteps: selectedSteps ?? null,
      selectedAssets: selectedAssets ?? null,
      verdict: poe.verdict,
    },
  });
  const result = await broadcastRescue({
    poe,
    mode,
    authToken: typeof body?.authToken === "string" ? body.authToken : null,
    escrowOverride:
      mode === "dry-run-fork" && typeof body?.escrowOverride === "string"
        ? body.escrowOverride
        : undefined,
    force,
    selectedSteps,
    selectedAssets,
  });
  return NextResponse.json(result);
}
