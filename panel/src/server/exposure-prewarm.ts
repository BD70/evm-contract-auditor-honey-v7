// Background warmer for the exposure cache.
//
// `/api/exposure` is the only consistently-slow read path in the panel:
// fully cold-cache requests for 200 contracts take ~9 s because each
// (chainId, address) needs a QuickNode RPC round trip (native balance
// + token holdings + USD pricing). The UI shows "…" placeholders while
// that completes, so the table itself isn't blocked — but the exposure
// column is empty for several seconds after every page change.
//
// This warmer runs in the background on the panel process and periodically
// primes the cache with the (chainId, address) pairs the UI is most likely
// to ask about next — i.e. the most-recently-discovered findings that
// will show up on the first page of the default filter view (verified +
// unverified). After the warmer has run once, page navigation feels
// instantaneous because every visible row's exposure is already a hot
// cache hit.

import { batchExposure, type ExposureRequest } from "./exposure";
import { rawDb } from "@/src/db/client";

const TICK_MS = Number(process.env.PANEL_EXPOSURE_PREWARM_INTERVAL_MS ?? 60_000);
const ROWS_PER_TICK = Number(process.env.PANEL_EXPOSURE_PREWARM_BATCH ?? 200);
const ENABLED = process.env.PANEL_EXPOSURE_PREWARM_DISABLE !== "1";

type Globals = { __panelExposurePrewarmTimer?: NodeJS.Timeout };
const g = globalThis as unknown as Globals;

export function ensureExposurePrewarmer() {
  if (!ENABLED) return;
  if (g.__panelExposurePrewarmTimer) return;
  // First tick after a 20s grace period — let the panel finish boot and
  // the worker pool stabilise before we add load.
  setTimeout(() => {
    void tickOnce();
  }, 20_000).unref();
  g.__panelExposurePrewarmTimer = setInterval(() => {
    void tickOnce();
  }, TICK_MS);
  g.__panelExposurePrewarmTimer.unref();
}

async function tickOnce() {
  try {
    // Pull the most-recent N unique (chain_id, contract_address) pairs from
    // findings that the default UI filter would surface. We deliberately
    // include `unverified` so the operator's "queued for sim" rows are
    // also warm when they flip to `verified`.
    const rows = rawDb
      .prepare(
        `SELECT chain_id AS chainId, LOWER(contract_address) AS address, MAX(discovered_at) AS ts
           FROM findings
          WHERE chain_id IS NOT NULL
            AND contract_address IS NOT NULL
            AND (simulation_status = 'verified' OR simulation_status IS NULL OR simulation_status = 'pending')
          GROUP BY chain_id, LOWER(contract_address)
          ORDER BY ts DESC
          LIMIT ?`,
      )
      .all(ROWS_PER_TICK) as { chainId: number; address: string }[];
    if (rows.length === 0) return;
    const items: ExposureRequest[] = rows
      .filter((r) => typeof r.chainId === "number" && typeof r.address === "string")
      .map((r) => ({ chainId: r.chainId, address: r.address }));
    if (items.length === 0) return;
    const startedAt = Date.now();
    // batchExposure already short-circuits on warm entries, so the marginal
    // cost is just the cold pairs.
    const result = await batchExposure(items);
    const elapsed = Date.now() - startedAt;
    // Cheap visibility — only log when we actually did work (i.e. a real
    // chunk of cold lookups). Otherwise we just spam the log every minute.
    if (elapsed > 1_000) {
      console.info(
        `[exposure-prewarm] warmed ${Object.keys(result).length}/${items.length} contracts in ${elapsed}ms`,
      );
    }
  } catch (err) {
    console.warn("[exposure-prewarm] tick failed:", err);
  }
}
