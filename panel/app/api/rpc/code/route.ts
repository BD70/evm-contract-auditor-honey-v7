import { NextResponse } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  let body: any;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "invalid JSON" }, { status: 400 }); }
  const { rpcUrl, address, block = "latest" } = body ?? {};
  if (typeof rpcUrl !== "string" || typeof address !== "string") {
    return NextResponse.json({ error: "rpcUrl and address required" }, { status: 400 });
  }
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
    return NextResponse.json({ error: "invalid address format" }, { status: 400 });
  }
  const payload = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getCode", params: [address, block] });
  try {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), 15_000);
    const r = await fetch(rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: payload,
      signal: ac.signal,
    });
    clearTimeout(t);
    if (!r.ok) return NextResponse.json({ error: `rpc HTTP ${r.status}` }, { status: 502 });
    const j: any = await r.json();
    if (j.error) return NextResponse.json({ error: j.error.message ?? "rpc error" }, { status: 502 });
    const code = j.result ?? "0x";
    if (code === "0x" || code === "0x0") {
      return NextResponse.json({ code, empty: true });
    }
    const bytes = (code.length - 2) / 2;
    return NextResponse.json({ code, empty: false, bytes });
  } catch (err: any) {
    return NextResponse.json({ error: err?.message ?? String(err) }, { status: 502 });
  }
}
