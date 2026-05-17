import { NextResponse } from "next/server";
import fs from "node:fs";
import path from "node:path";
import { panelPaths } from "@/src/server/paths";
import { runnerController } from "@/src/server/runner-controller";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Destructive: wipes the runner's STATE_DIR contents (checkpoint + artifacts +
// stale locks). Requires runner to be idle to avoid corrupting an in-flight
// save. The runner will rebuild from the configured START_BLOCK on next start.
export async function POST(req: Request) {
  let body: any = {};
  try { body = await req.json(); } catch {}
  if (runnerController.status === "running" || runnerController.status === "starting") {
    return NextResponse.json(
      { ok: false, error: "stop the runner before resetting state" },
      { status: 409 },
    );
  }
  const confirm = body?.confirm === true;
  if (!confirm) {
    return NextResponse.json(
      { ok: false, error: "confirm=true required to wipe runner state" },
      { status: 400 },
    );
  }
  const removed: string[] = [];
  const candidates = [
    path.join(panelPaths.stateDir, "checkpoint.json"),
    path.join(panelPaths.stateDir, ".runner.lock"),
    panelPaths.artifactsDir,
  ];
  for (const target of candidates) {
    try {
      if (fs.existsSync(target)) {
        fs.rmSync(target, { recursive: true, force: true });
        removed.push(target);
      }
    } catch (err: any) {
      return NextResponse.json({ ok: false, error: `failed to remove ${target}: ${err?.message}` }, { status: 500 });
    }
  }
  return NextResponse.json({ ok: true, removed });
}
