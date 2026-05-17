import { NextResponse } from "next/server";
import { bootOnce } from "@/src/server/boot";
import { addChain, chainHealthPort, readChainsRedacted } from "@/src/server/chains-store";
import { runnerRegistry } from "@/src/server/runner-controller";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  bootOnce();
  const chains = readChainsRedacted().map((c) => {
    const ctrl = runnerRegistry.get(c.slug);
    return {
      ...c,
      healthPort: chainHealthPort(c.slug),
      runner: ctrl ? ctrl.snapshot() : null,
    };
  });
  return NextResponse.json({ ok: true, chains });
}

export async function POST(req: Request) {
  bootOnce();
  try {
    const body = await req.json();
    const entry = addChain(body);
    return NextResponse.json({ ok: true, chain: entry }, { status: 201 });
  } catch (err: any) {
    return NextResponse.json({ ok: false, error: err?.message ?? String(err) }, { status: 400 });
  }
}
