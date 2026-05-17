import { NextResponse } from "next/server";
import { bootOnce } from "@/src/server/boot";
import { removeChain, updateChain } from "@/src/server/chains-store";
import { runnerRegistry } from "@/src/server/runner-controller";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function PUT(req: Request, { params }: { params: Promise<{ slug: string }> }) {
  bootOnce();
  const { slug } = await params;
  try {
    const body = await req.json();
    const entry = updateChain(slug, body);
    return NextResponse.json({ ok: true, chain: entry });
  } catch (err: any) {
    return NextResponse.json({ ok: false, error: err?.message ?? String(err) }, { status: 400 });
  }
}

export async function DELETE(_req: Request, { params }: { params: Promise<{ slug: string }> }) {
  bootOnce();
  const { slug } = await params;
  const ctrl = runnerRegistry.get(slug);
  if (ctrl && (ctrl.status === "running" || ctrl.status === "starting" || ctrl.status === "stopping")) {
    return NextResponse.json(
      { ok: false, error: "stop the chain runner before deleting it" },
      { status: 409 },
    );
  }
  try {
    removeChain(slug);
    runnerRegistry.remove(slug);
    return NextResponse.json({ ok: true });
  } catch (err: any) {
    return NextResponse.json({ ok: false, error: err?.message ?? String(err) }, { status: 400 });
  }
}
