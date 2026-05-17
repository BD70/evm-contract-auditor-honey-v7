import { NextResponse } from "next/server";
import { runnerController } from "@/src/server/runner-controller";
import { bootOnce } from "@/src/server/boot";
import { readChainsRaw } from "@/src/server/chains-store";
import { buildAggregateState } from "@/src/server/chain-aggregate";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  bootOnce();

  const enabledChains = readChainsRaw().filter((c) => c.enabled);
  if (enabledChains.length > 0) {
    return NextResponse.json(buildAggregateState(enabledChains));
  }

  return NextResponse.json(runnerController.snapshot());
}
