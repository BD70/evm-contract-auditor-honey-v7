import { NextResponse } from "next/server";
import { runnerController, runnerRegistry } from "@/src/server/runner-controller";
import { readChainsRaw } from "@/src/server/chains-store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  let body: any = {};
  try { body = await req.json(); } catch {}
  const graceful = body?.graceful !== false;

  const enabledChains = readChainsRaw().filter((c) => c.enabled);
  if (enabledChains.length > 0) {
    await Promise.allSettled(
      enabledChains.map((c) => {
        const ctrl = runnerRegistry.get(c.slug);
        return ctrl ? ctrl.stop({ graceful }) : Promise.resolve();
      }),
    );
    return NextResponse.json({ ok: true, chainMode: true });
  }

  await runnerController.stop({ graceful });
  return NextResponse.json({ ok: true, snapshot: runnerController.snapshot() });
}
