import { sseResponse } from "@/src/server/sse";
import { runnerController, runnerRegistry, type LogLine } from "@/src/server/runner-controller";
import { bootOnce } from "@/src/server/boot";
import { readChainsRaw, chainHealthPort } from "@/src/server/chains-store";
import { buildAggregateState } from "@/src/server/chain-aggregate";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  bootOnce();
  return sseResponse(req, (push) => {
    const enabledChains = readChainsRaw().filter((c) => c.enabled);

    if (enabledChains.length > 0) {
      const cleanups: (() => void)[] = [];

      const pushAggregate = () =>
        push({ event: "state", data: buildAggregateState(enabledChains) });

      for (const chain of enabledChains) {
        const ctrl = runnerRegistry.ensure(chain.slug, chainHealthPort(chain.slug));
        // Replay tail with slug tag.
        for (const line of ctrl.tail(100)) {
          push({ event: "log", data: { ...line, slug: chain.slug } });
        }
        const onLog = (line: LogLine) =>
          push({ event: "log", data: { ...line, slug: chain.slug } });
        // Each chain state change → push a fresh AGGREGATE state event so
        // Dashboard/RunnerPill always see summed metrics, not a per-chain snapshot.
        ctrl.on("log", onLog);
        ctrl.on("state", pushAggregate);
        cleanups.push(() => {
          ctrl.off("log", onLog);
          ctrl.off("state", pushAggregate);
        });
      }

      // Send initial aggregate on connect.
      pushAggregate();
      return () => cleanups.forEach((fn) => fn());
    }

    // Single-chain fallback.
    for (const line of runnerController.tail(200)) {
      push({ event: "log", data: line });
    }
    push({ event: "state", data: runnerController.snapshot() });
    const onLog = (line: LogLine) => push({ event: "log", data: line });
    const onState = () => push({ event: "state", data: runnerController.snapshot() });
    runnerController.on("log", onLog);
    runnerController.on("state", onState);
    return () => {
      runnerController.off("log", onLog);
      runnerController.off("state", onState);
    };
  });
}
