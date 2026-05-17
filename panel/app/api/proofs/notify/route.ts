import { NextResponse } from "next/server";
import { bootOnce } from "@/src/server/boot";
import { logRescueAction } from "@/src/server/sim/poe-store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * POST /api/proofs/notify
 *
 * Inbound webhook receiver. External tools (TG bots, monitoring, custom
 * alerting) can POST notifications about rescue lifecycle events into the
 * panel — they'll show up on the finding's timeline.
 *
 * Body: {
 *   findingId: string,
 *   attemptId?: string,
 *   kind: "identity-challenge" | "identity-verified" | "rescue-confirmed",
 *   actor?: string,
 *   detail?: object
 * }
 *
 * The list of kinds intentionally OVERLAPS with internal rescue_actions
 * kinds — TG bots/operators can mirror their off-chain steps into the
 * timeline so the panel has the full audit picture.
 */
const ALLOWED_KINDS = new Set([
  "identity-challenge",
  "identity-verified",
  "rescue-confirmed",
  "tg-notified",
]);

export async function POST(req: Request) {
  bootOnce();
  let body: any = {};
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "invalid JSON" }, { status: 400 });
  }
  const findingId = typeof body?.findingId === "string" ? body.findingId : null;
  const kind = typeof body?.kind === "string" ? body.kind : null;
  if (!findingId || !kind) {
    return NextResponse.json({ error: "findingId and kind are required" }, { status: 400 });
  }
  if (!ALLOWED_KINDS.has(kind)) {
    return NextResponse.json(
      { error: `unsupported kind '${kind}'. Allowed: ${[...ALLOWED_KINDS].join(", ")}` },
      { status: 400 },
    );
  }
  logRescueAction({
    findingId,
    attemptId: typeof body?.attemptId === "string" ? body.attemptId : null,
    kind: kind as any,
    actor: typeof body?.actor === "string" ? body.actor : "external",
    detail:
      body?.detail && typeof body.detail === "object"
        ? (body.detail as Record<string, unknown>)
        : undefined,
  });
  return NextResponse.json({ ok: true, findingId, kind });
}
