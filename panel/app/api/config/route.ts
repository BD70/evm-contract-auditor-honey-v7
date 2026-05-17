import { NextResponse } from "next/server";
import { applyPatchAtomic, readEnvRedacted, previewPatch } from "@/src/server/env-store";
import { runnerController } from "@/src/server/runner-controller";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  return NextResponse.json({ values: readEnvRedacted() });
}

export async function PUT(req: Request) {
  let body: any;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "invalid JSON" }, { status: 400 }); }
  const dry = !!body?.dryRun;
  const restart = !!body?.restartRunner;
  const patch = body?.patch ?? {};
  try {
    if (dry) {
      const diff = previewPatch(patch);
      return NextResponse.json({ ok: true, diff });
    }
    const result = applyPatchAtomic(patch);
    let restarted = false;
    if (restart && (runnerController.status === "running" || runnerController.status === "crashed")) {
      try {
        await runnerController.restart();
        restarted = true;
      } catch (err: any) {
        return NextResponse.json({ ok: true, applied: result.applied, restartError: err?.message ?? String(err) });
      }
    }
    return NextResponse.json({ ok: true, applied: result.applied, restarted });
  } catch (err: any) {
    return NextResponse.json({ ok: false, error: err?.message ?? String(err) }, { status: 400 });
  }
}
