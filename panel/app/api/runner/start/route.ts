import { NextResponse } from "next/server";
import { runnerController, runnerRegistry, type StartArgs } from "@/src/server/runner-controller";
import { bootOnce } from "@/src/server/boot";
import { readChainsRaw, chainHealthPort } from "@/src/server/chains-store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  bootOnce();
  let args: StartArgs = {};
  try { args = (await req.json()) as StartArgs; } catch {}

  const enabledChains = readChainsRaw().filter((c) => c.enabled);
  if (enabledChains.length > 0) {
    // Multi-chain mode: start each enabled chain via its own controller.
    const results: { slug: string; ok: boolean; error?: string }[] = [];
    for (const chain of enabledChains) {
      const ctrl = runnerRegistry.ensure(chain.slug, chainHealthPort(chain.slug));
      try {
        if (ctrl.status !== "running" && ctrl.status !== "starting") {
          await ctrl.start(args);
        }
        results.push({ slug: chain.slug, ok: true });
      } catch (err: any) {
        results.push({ slug: chain.slug, ok: false, error: err?.message ?? String(err) });
      }
    }
    return NextResponse.json({ ok: true, chainMode: true, chains: results });
  }

  // Single-chain fallback.
  try {
    await runnerController.start(args);
    return NextResponse.json({ ok: true, snapshot: runnerController.snapshot() });
  } catch (err: any) {
    return NextResponse.json({ ok: false, error: err?.message ?? String(err) }, { status: 409 });
  }
}
