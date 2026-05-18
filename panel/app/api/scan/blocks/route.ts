// POST /api/scan/blocks
//
// Flexible block scanning: scan a specific block, a range, the last N blocks,
// or switch to head-following mode. Runs as a one-shot (--once) unless
// mode is "head" (continuous).
//
// Body:
//   {
//     chain: "eth-mainnet",                // required: which chain to scan
//     mode: "block" | "range" | "lastN" | "head",  // required
//     block?: number,                      // for mode "block"
//     from?: number,                       // for mode "range"
//     to?: number,                         // for mode "range"
//     lastN?: number,                      // for mode "lastN" (default 100)
//     startBlock?: number,                 // for mode "head" (optional start)
//     noWebhook?: boolean,                 // skip webhook notifications
//   }

import { NextResponse } from "next/server";
import { runnerRegistry, type StartArgs } from "@/src/server/runner-controller";
import { bootOnce } from "@/src/server/boot";
import { readChainsRaw, chainHealthPort } from "@/src/server/chains-store";
import { rpcRequest } from "@/src/server/sim/anvil-pool";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  bootOnce();
  let body: any = {};
  try { body = await req.json(); } catch {}

  const chain = body?.chain;
  if (!chain || typeof chain !== "string") {
    return NextResponse.json({ error: "chain is required (e.g. 'eth-mainnet')" }, { status: 400 });
  }

  const chains = readChainsRaw();
  const chainCfg = chains.find((c) => c.slug === chain);
  if (!chainCfg) {
    return NextResponse.json({
      error: `unknown chain '${chain}'`,
      available: chains.filter((c) => c.enabled).map((c) => c.slug),
    }, { status: 400 });
  }

  const mode = body?.mode;
  if (!mode || !["block", "range", "lastN", "head"].includes(mode)) {
    return NextResponse.json({
      error: "mode is required: 'block' | 'range' | 'lastN' | 'head'",
    }, { status: 400 });
  }

  let args: StartArgs = {};
  const noWebhook = body?.noWebhook === true;
  if (noWebhook) args.noWebhook = true;

  if (mode === "block") {
    const block = Number(body?.block);
    if (!Number.isInteger(block) || block < 0) {
      return NextResponse.json({ error: "block must be a positive integer" }, { status: 400 });
    }
    args.replayBlock = block;
    args.once = true;
  } else if (mode === "range") {
    const from = Number(body?.from);
    const to = Number(body?.to);
    if (!Number.isInteger(from) || !Number.isInteger(to) || from < 0 || to < from) {
      return NextResponse.json({ error: "from and to must be integers with to >= from" }, { status: 400 });
    }
    if (to - from + 1 > 10_000) {
      return NextResponse.json({ error: "range exceeds max of 10,000 blocks" }, { status: 400 });
    }
    args.replayRange = { from, to };
    args.once = true;
  } else if (mode === "lastN") {
    const lastN = Number(body?.lastN ?? 100);
    if (!Number.isInteger(lastN) || lastN < 1 || lastN > 10_000) {
      return NextResponse.json({ error: "lastN must be 1-10000" }, { status: 400 });
    }
    // Fetch the current head block from the chain RPC
    let headBlock: number;
    try {
      const rpcUrl = chainCfg.rpcHttpUrl;
      const hexBlock = await rpcRequest(rpcUrl, "eth_blockNumber", []);
      headBlock = Number(BigInt(hexBlock as string));
    } catch (e: any) {
      return NextResponse.json({ error: `failed to get head block: ${e?.message}` }, { status: 502 });
    }
    const from = Math.max(0, headBlock - lastN + 1);
    args.replayRange = { from, to: headBlock };
    args.once = true;
  } else if (mode === "head") {
    if (body?.startBlock !== undefined) {
      const sb = Number(body.startBlock);
      if (!Number.isInteger(sb) || sb < 0) {
        return NextResponse.json({ error: "startBlock must be a positive integer" }, { status: 400 });
      }
      args.startBlock = sb;
    }
    // head mode = continuous, no --once
  }

  const ctrl = runnerRegistry.ensure(chain, chainHealthPort(chain));

  // If the runner is already running, stop it first for replay modes
  if (ctrl.status === "running" || ctrl.status === "starting") {
    if (mode !== "head") {
      // For one-shot modes, stop the existing runner first
      try {
        await ctrl.stop({ graceful: true });
      } catch {}
    } else {
      // For head mode, restart with new args
      try {
        await ctrl.restart(args);
        return NextResponse.json({
          ok: true,
          mode,
          chain,
          args,
          message: `Runner restarted in head-follow mode${args.startBlock ? ` from block ${args.startBlock}` : ""}`,
        });
      } catch (e: any) {
        return NextResponse.json({ ok: false, error: e?.message ?? String(e) }, { status: 500 });
      }
    }
  }

  try {
    await ctrl.start(args);
    const modeDesc = mode === "block"
      ? `scanning block ${args.replayBlock}`
      : mode === "range"
        ? `scanning blocks ${args.replayRange!.from} to ${args.replayRange!.to} (${args.replayRange!.to - args.replayRange!.from + 1} blocks)`
        : mode === "lastN"
          ? `scanning last ${body?.lastN ?? 100} blocks (${args.replayRange!.from} to ${args.replayRange!.to})`
          : `following head${args.startBlock ? ` from block ${args.startBlock}` : ""}`;

    return NextResponse.json({
      ok: true,
      mode,
      chain,
      args,
      message: modeDesc,
    });
  } catch (e: any) {
    return NextResponse.json({ ok: false, error: e?.message ?? String(e) }, { status: 500 });
  }
}

export async function GET() {
  bootOnce();
  const chains = readChainsRaw().filter((c) => c.enabled);
  return NextResponse.json({
    usage: {
      endpoint: "POST /api/scan/blocks",
      modes: {
        block: { description: "Scan a single specific block", params: { chain: "string", mode: "block", block: "number" } },
        range: { description: "Scan a block range", params: { chain: "string", mode: "range", from: "number", to: "number" } },
        lastN: { description: "Scan the last N blocks from head", params: { chain: "string", mode: "lastN", lastN: "number (1-10000, default 100)" } },
        head: { description: "Follow new blocks continuously", params: { chain: "string", mode: "head", startBlock: "number (optional)" } },
      },
      options: { noWebhook: "boolean (optional, skip webhook notifications)" },
    },
    chains: chains.map((c) => c.slug),
  });
}
