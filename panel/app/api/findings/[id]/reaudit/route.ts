import { NextResponse } from "next/server";
import { getFinding } from "@/src/server/findings-store";
import { startAudit } from "@/src/server/audit-service";
import { bootOnce } from "@/src/server/boot";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  bootOnce();
  const { id } = await params;
  const f = getFinding(id);
  if (!f) return NextResponse.json({ error: "not found" }, { status: 404 });
  let body: any = {};
  try { body = await req.json(); } catch {}
  const raw = f.raw ?? {};
  const bytecode = raw.bytecode_identity?.runtime_code ?? raw.input?.value ?? null;
  if (!bytecode) {
    return NextResponse.json({ error: "no bytecode stored on finding; re-audit requires original input" }, { status: 400 });
  }
  const { runId } = await startAudit({
    kind: "reaudit",
    bytecode,
    contractAddress: f.contract_address,
    chainId: f.chain_id,
    rulesPath: body?.rulesPath,
    llmJudge: !!body?.llmJudge,
    llmJudgeRefresh: !!body?.llmJudgeRefresh,
    reauditOf: id,
  } as any);
  return NextResponse.json({ ok: true, runId });
}
