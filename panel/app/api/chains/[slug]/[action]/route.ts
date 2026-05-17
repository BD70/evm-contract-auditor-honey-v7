import { NextResponse } from "next/server";
import { bootOnce } from "@/src/server/boot";
import { chainHealthPort, readChainsRaw } from "@/src/server/chains-store";
import { runnerRegistry, type StartArgs } from "@/src/server/runner-controller";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(
  req: Request,
  { params }: { params: Promise<{ slug: string; action: string }> },
) {
  bootOnce();
  const { slug, action } = await params;

  const chain = readChainsRaw().find((c) => c.slug === slug);
  if (!chain) {
    return NextResponse.json({ ok: false, error: `unknown chain: ${slug}` }, { status: 404 });
  }
  if (!chain.enabled && (action === "start" || action === "restart")) {
    return NextResponse.json(
      { ok: false, error: `chain ${slug} is disabled` },
      { status: 409 },
    );
  }

  const ctrl = runnerRegistry.ensure(slug, chainHealthPort(slug));

  let args: StartArgs = {};
  try {
    args = (await req.json()) as StartArgs;
  } catch {}

  try {
    if (action === "start") {
      await ctrl.start(args ?? {});
    } else if (action === "stop") {
      await ctrl.stop({ graceful: (args as any)?.graceful !== false });
    } else if (action === "restart") {
      await ctrl.restart(args);
    } else {
      return NextResponse.json({ ok: false, error: `unknown action: ${action}` }, { status: 400 });
    }
    return NextResponse.json({ ok: true, snapshot: ctrl.snapshot() });
  } catch (err: any) {
    return NextResponse.json(
      { ok: false, error: err?.message ?? String(err) },
      { status: action === "start" ? 409 : 500 },
    );
  }
}
