// IMPORTANT: env-bootstrap MUST be the very first import in this file. Other
// modules read process.env values at module-load time (sim worker, anvil
// pool, etc.) so we need the .env file applied before any of them evaluate.
import "./env-bootstrap";
import { ingestWatcher } from "./ingest-watcher";
import { runnerController } from "./runner-controller";
import { ensurePanelDirs } from "./paths";
import { ensurePruneSchedule } from "./prune-job";
import { auditorBinInfo } from "./auditor-bin";
import { simWorker } from "./sim/worker";
import { startTgBot, tgBotEnabled } from "./rescue/tg-bot";

type Globals = { __panelBooted?: boolean };
const g = globalThis as unknown as Globals;

export function bootOnce() {
  if (g.__panelBooted) return;
  g.__panelBooted = true;
  try {
    ensurePanelDirs();
    ingestWatcher.startIfNeeded();
    ensurePruneSchedule();
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
