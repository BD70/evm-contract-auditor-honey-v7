// IMPORTANT: env-bootstrap MUST be the very first import in this file. Other
// modules read process.env values at module-load time (sim worker, anvil
// pool, etc.) so we need the .env file applied before any of them evaluate.
import "./env-bootstrap";
import { ingestWatcher } from "./ingest-watcher";
import { runnerController } from "./runner-controller";
import { ensurePanelDirs } from "./paths";
import { ensurePruneSchedule } from "./prune-job";
import { ensureExposurePrewarmer } from "./exposure-prewarm";
import { auditorBinInfo } from "./auditor-bin";
import { simWorker } from "./sim/worker";
import { startTgBot, tgBotEnabled } from "./rescue/tg-bot";

type Globals = { __panelBooted?: boolean };
const g = globalThis as unknown as Globals;

export function bootOnce() {
  if (g.__panelBooted) return;
  g.__panelBooted = true;
  raiseFdLimit();
  try {
    ensurePanelDirs();
    ingestWatcher.startIfNeeded();
    ensurePruneSchedule();
    ensureExposurePrewarmer();
    void simWorker.startIfNeeded().catch((err) => console.warn("[sim] startIfNeeded failed", err));
    if (tgBotEnabled()) {
      void startTgBot().catch((err) => console.warn("[tg-bot] start failed", err));
    }
    const bins = auditorBinInfo();
    for (const { tool, resolved, source } of bins) {
      console.info(`[panel] ${tool} → ${resolved} (${source})`);
    }
    if (
      !process.env.PANEL_USER ||
      !process.env.PANEL_PASS ||
      process.env.PANEL_PASS === "changeme"
    ) {
      console.warn(
        "[panel] WARNING: PANEL_USER/PANEL_PASS not set (or default). HTTP basic auth is insecure as-is.",
      );
    }
  } catch (err) {
    console.warn("[panel] boot warning:", err);
  }
  void runnerController; // keep singleton resident
}

/**
 * Raise the soft file-descriptor limit so Next.js + sqlite + chokidar +
 * anvil sockets don't trip EMFILE. macOS launchctl's default soft maxfiles
 * is 256 which is well below what we need. Previously this was done in the
 * PM2 launcher via `/bin/sh -c "ulimit -n 65536 && ..."`, but that wrapper
 * hid the real Next.js PID from PM2's memory monitor — so we now launch
 * Next directly and raise FDs here as a defensive belt.
 */
function raiseFdLimit() {
  try {
    // process.setrlimit isn't in Node's public API on all platforms; use the
    // posix bridge when available. On macOS the soft limit can be raised up
    // to kern.maxfilesperproc (~184320) without root.
    const anyProc = process as unknown as {
      getrlimit?: (r: string) => { soft: number; hard: number };
      setrlimit?: (r: string, l: { soft: number; hard: number }) => void;
    };
    if (typeof anyProc.setrlimit === "function" && typeof anyProc.getrlimit === "function") {
      const cur = anyProc.getrlimit("nofile");
      const target = Math.min(65_536, cur.hard);
      if (cur.soft < target) {
        anyProc.setrlimit("nofile", { soft: target, hard: cur.hard });
        console.info(`[panel] raised RLIMIT_NOFILE soft ${cur.soft} -> ${target} (hard=${cur.hard})`);
      }
    }
  } catch (err) {
    console.warn("[panel] could not raise FD limit (continuing):", err);
  }
}
