import { sseResponse } from "@/src/server/sse";
import { runnerController, runnerRegistry, type LogLine } from "@/src/server/runner-controller";
import { bootOnce } from "@/src/server/boot";
import { readChainsRaw, chainHealthPort } from "@/src/server/chains-store";
import { buildAggregateState } from "@/src/server/chain-aggregate";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const TAIL_PER_CHAIN = 10;
const LOG_THROTTLE_MS = 300;
const STATE_THROTTLE_MS = 1000;

export async function GET(req: Request) {
  bootOnce();
  return sseResponse(req, (push) => {
    const enabledChains = readChainsRaw().filter((c) => c.enabled);

    if (enabledChains.length > 0) {
      const cleanups: (() => void)[] = [];

      let stateTimer: ReturnType<typeof setTimeout> | null = null;
      let stateDirty = false;
      const pushAggregate = () => {
        stateDirty = true;
        if (!stateTimer) {
          stateTimer = setTimeout(() => {
            stateTimer = null;
            if (stateDirty) {
              stateDirty = false;
              push({ event: "state", data: buildAggregateState(enabledChains) });
            }
          }, STATE_THROTTLE_MS);
        }
      };

      let logBuffer: Array<LogLine & { slug: string }> = [];
      let flushTimer: ReturnType<typeof setTimeout> | null = null;

      const flushLogs = () => {
        flushTimer = null;
        if (logBuffer.length === 0) return;
        const batch = logBuffer.slice(-8);
        logBuffer = [];
        for (const line of batch) {
          push({ event: "log", data: line });
        }
      };

      for (const chain of enabledChains) {
        const ctrl = runnerRegistry.ensure(chain.slug, chainHealthPort(chain.slug));
        for (const line of ctrl.tail(TAIL_PER_CHAIN)) {
          push({ event: "log", data: { ...line, slug: chain.slug } });
        }
        const onLog = (line: LogLine) => {
          logBuffer.push({ ...line, slug: chain.slug });
          if (!flushTimer) {
            flushTimer = setTimeout(flushLogs, LOG_THROTTLE_MS);
          }
        };
        ctrl.on("log", onLog);
        ctrl.on("state", pushAggregate);
        cleanups.push(() => {
          ctrl.off("log", onLog);
          ctrl.off("state", pushAggregate);
        });
      }

      // Initial state push (once, not throttled)
      push({ event: "state", data: buildAggregateState(enabledChains) });
      return () => {
        if (flushTimer) clearTimeout(flushTimer);
        if (stateTimer) clearTimeout(stateTimer);
        cleanups.forEach((fn) => fn());
      };
    }

    for (const line of runnerController.tail(50)) {
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
