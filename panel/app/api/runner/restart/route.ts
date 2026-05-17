import { NextResponse } from "next/server";
import { runnerController, runnerRegistry, type StartArgs } from "@/src/server/runner-controller";
import { bootOnce } from "@/src/server/boot";
import { readChainsRaw, chainHealthPort } from "@/src/server/chains-store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  bootOnce();
  let args: StartArgs | undefined;
  try { args = (await req.json()) as StartArgs; } catch {}

  const enabledChains = readChainsRaw().filter((c) => c.enabled);
  if (enabledChains.length > 0) {
    await Promise.allSettled(
      enabledChains.map((c) => {
        const ctrl = runnerRegistry.ensure(c.slug, chainHealthPort(c.slug));
        return ctrl.restart(args);
      }),
    );
    return NextResponse.json({ ok: true, chainMode: true });
  }

  try {
    await runnerController.restart(args);
    return NextResponse.json({ ok: true, snapshot: runnerController.snapshot() });
  } catch (err: any) {
    return NextResponse.json({ ok: false, error: err?.message ?? String(err) }, { status: 500 });
  }
}
