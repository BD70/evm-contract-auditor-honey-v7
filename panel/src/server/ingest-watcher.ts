
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { panelPaths } from "./paths";
import { ingestApiJson, upsertDeployment } from "./findings-store";
import { rawDb } from "@/src/db/client";

const MAX_INGEST_BYTES = 8 * 1024 * 1024;
const RECONCILE_INTERVAL_MS = Number(process.env.INGEST_RECONCILE_INTERVAL_MS ?? 5_000);
// Yield to the event loop every N directories scanned so a long sweep over a
// runner-state tree with thousands of subdirs doesn't starve HTTP handlers.
const SCAN_YIELD_EVERY = 64;
// Cap the in-memory `seen` set so a multi-day uptime can't bloat the process.
// 100k file paths is ~10MB worst case — well below any practical state-dir size.
const SEEN_MAX_ENTRIES = 100_000;
const SEEN_TRIM_TO = 75_000;

type Globals = { __panelIngestWatcher?: IngestWatcher };

// Runner artifacts live in two layouts:
//   legacy single-runner: <STATE_DIR>/artifacts/<chainId>/<block>/<tx>/<kind>.json
//   chain mode:           <STATE_DIR>/<slug>/artifacts/<chainId>/<block>/<tx>/<kind>.json
// Checkpoints: <STATE_DIR>/checkpoint.json or <STATE_DIR>/<slug>/checkpoint.json.
//
// We previously used chokidar with a recursive watch on the state dir, but
// macOS's per-process fd limit (256 by default) is blown out by the thousands
// of per-tx subdirectories the runner creates, producing an EMFILE storm and a
// multi-GB error-object leak in the panel. Polling every few seconds is plenty
// fast for this workload (runners emit artifacts in block-sized bursts and we
// don't need sub-second ingestion latency) and uses zero file descriptors.
class IngestWatcher {
  private started = false;
  private seen = new Set<string>();
  private timer: NodeJS.Timeout | null = null;
  private running = false;
  /** mtime cache for checkpoint.json so we only re-parse when the file actually changes. */
  private checkpointMtime = new Map<string, number>();

  /** True iff this checkpoint lives at `<STATE_DIR>/<slug>/checkpoint.json`
   * (= a per-chain runner artifact) and NOT at `<STATE_DIR>/checkpoint.json`
   * (= the legacy single-runner format that ingestCheckpoint actually parses). */
  private isPerSlugCheckpoint(p: string): boolean {
    const rel = path.relative(panelPaths.stateDir, p).split(path.sep);
    return rel.length === 2 && rel[1] === "checkpoint.json";
  }

  /** Cheap mtime cache so we don't re-parse multi-MB blobs when nothing changed. */
  private async ingestCheckpointIfChanged(p: string): Promise<void> {
    try {
      const stat = await fsp.stat(p);
      const last = this.checkpointMtime.get(p) ?? 0;
      if (stat.mtimeMs === last) return;
      this.checkpointMtime.set(p, stat.mtimeMs);
      await this.ingestCheckpoint(p);
    } catch {}
  }

  async startIfNeeded() {
    if (this.started) return;
    this.started = true;
    try {
      fs.mkdirSync(panelPaths.stateDir, { recursive: true });
    } catch {}
    this.scheduleTick(0);
  }

  async stop() {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    this.started = false;
  }

  private scheduleTick(delay = RECONCILE_INTERVAL_MS) {
    if (!this.started) return;
    this.timer = setTimeout(() => {
      this.tick().catch((err) => console.warn("[ingest] tick error", err));
    }, delay);
  }

  private async tick() {
    if (this.running) {
      this.scheduleTick();
      return;
    }
    this.running = true;
    try {
      await this.reconcile();
    } finally {
      this.running = false;
      this.scheduleTick();
    }
  }

  private async reconcile() {
    // Use async fsp.* APIs and yield to the event loop every SCAN_YIELD_EVERY
    // directories so a sweep over a 8000+-file runner-state tree never holds
    // the loop long enough to make HTTP feel hung.
    let dirRoot: fs.Stats;
    try {
      dirRoot = await fsp.stat(panelPaths.stateDir);
    } catch {
      return;
    }
    if (!dirRoot.isDirectory()) return;

    let scanned = 0;
    let processed = 0;
    let dirsSinceYield = 0;
    const stack: string[] = [panelPaths.stateDir];
    while (stack.length) {
      const dir = stack.pop()!;
      let entries: fs.Dirent[];
      try {
        entries = await fsp.readdir(dir, { withFileTypes: true });
      } catch {
        continue;
      }
      dirsSinceYield++;
      if (dirsSinceYield >= SCAN_YIELD_EVERY) {
        dirsSinceYield = 0;
        await new Promise<void>((resolve) => setImmediate(resolve));
      }
      for (const e of entries) {
        const full = path.join(dir, e.name);
        if (e.isDirectory()) {
          if (e.name === "node_modules" || e.name.startsWith(".")) continue;
          stack.push(full);
          continue;
        }
        if (!e.isFile() || !full.endsWith(".json")) continue;
        scanned++;
        // checkpoint.json gets rewritten by the runner every block; always
        // re-process it. Everything else is processed once.
        if (e.name !== "checkpoint.json" && this.seen.has(full)) continue;
        const handled = await this.handlePath(full);
        if (handled) processed++;
      }
    }
    this.trimSeen();
    if (processed > 0) {
      console.log(`[ingest] reconcile processed ${processed} new file(s) (scanned ${scanned})`);
    }
  }

  private trimSeen() {
    if (this.seen.size <= SEEN_MAX_ENTRIES) return;
    // Sets retain insertion order; drop oldest entries until we're back under
    // the target. Cheap O(n) but only runs when we've crossed the cap.
    const drop = this.seen.size - SEEN_TRIM_TO;
    let dropped = 0;
    for (const k of this.seen) {
      if (dropped++ >= drop) break;
      this.seen.delete(k);
    }
  }

  private parsePathContext(p: string): {
    slug: string | null;
    chainId: number | null;
    blockNumber: number | null;
    txHash: string | null;
  } {
    const rel = path.relative(panelPaths.stateDir, p).split(path.sep);
    const artIdx = rel.indexOf("artifacts");
    if (artIdx < 0) return { slug: null, chainId: null, blockNumber: null, txHash: null };
    const slug = artIdx > 0 ? rel[0] : null;
    const after = rel.slice(artIdx + 1);
    // after = [<chainId>, <block>, <tx>, <kind>.json]
    return {
      slug,
      chainId: after[0] ? Number(after[0]) || null : null,
      blockNumber: after[1] ? Number(after[1]) || null : null,
      txHash: after[2] ?? null,
    };
  }

  private async handlePath(p: string): Promise<boolean> {
    const base = path.basename(p);
    if (base === "checkpoint.json") {
      // ingestCheckpoint only cares about the legacy single-runner format which
      // emits `deliveredEvents` / `pendingWebhookEvents` at the root. Per-chain
      // runners emit a wholly different shape (`{ chainId, lastProcessedBlock,
      // history[] }`) and the function is a no-op on them — but a no-op that
      // JSON.parses up to ~1.5 MB per file every 5s, which is the ~45 MB/tick
      // churn that was tipping the panel into Node OOM every ~15 min. Short-
      // circuit per-slug checkpoints entirely.
      if (this.isPerSlugCheckpoint(p)) {
        // Mark as seen so we don't keep re-checking; reconcile will still
        // pick it up if the slug changes structure (unlikely).
        return false;
      }
      await this.ingestCheckpointIfChanged(p);
      return true;
    }
    if (!p.endsWith(".json")) return false;
    if (this.seen.has(p)) return false;

    try {
      const stat = await fsp.stat(p);
      if (stat.size > MAX_INGEST_BYTES) {
        this.seen.add(p);
        return false;
      }
      const txt = await fsp.readFile(p, "utf8");
      const obj = JSON.parse(txt);

      const { chainId, blockNumber, txHash } = this.parsePathContext(p);

      if (base === "deployment.json") {
        upsertDeployment({
          chainId,
          blockNumber,
          contractAddress: obj.contractAddress ?? null,
          txHash: obj.txHash ?? txHash ?? "",
          deployer: obj.deployer ?? null,
          bytecodeHash: obj.creationBytecodeHash ?? null,
          proxyKind: obj.proxy?.kind ?? null,
          proxyTarget: obj.proxy?.target ?? null,
          detectedAt: Date.now(),
          auditStatus: "pending",
          runnerEventId: obj.correlationId ?? null,
          rawJson: obj,
        });
        this.seen.add(p);
        return true;
      }

      // Runner wraps the bare API JSON under `apiJson`; manual audits emit it bare.
      const api =
        obj && typeof obj === "object" && obj.apiJson && typeof obj.apiJson === "object"
          ? obj.apiJson
          : obj;
      if (api && api.schema && String(api.schema).startsWith("evm-audit.api")) {
        const ctxAddress =
          (obj?.target?.contractAddress ?? obj?.target?.targetAddress) ||
          api.contract_address ||
          api.bytecode_identity?.contract_address ||
          (api.chain_context && api.chain_context.contractAddress) ||
          null;
        const bytecodeHash =
          api.bytecode_identity?.bytecode_hash ||
          api.bytecode_identity?.runtime_code_hash ||
          api.bytecode_identity?.runtime_hash ||
          obj?.target?.runtimeBytecodeHash ||
          null;
        ingestApiJson(api, {
          source: "runner",
          chainId: chainId ?? (api.chain_context?.chainId ?? null),
          blockNumber: blockNumber ?? (api.chain_context?.blockNumber ?? null),
          txHash: txHash ?? (api.chain_context?.txHash ?? null),
          contractAddress: ctxAddress,
          bytecodeHash,
        });
      }
      this.seen.add(p);
      return true;
    } catch {
      // record as seen so we don't retry forever on a broken file
      this.seen.add(p);
      return false;
    }
  }

  private async ingestCheckpoint(filePath?: string) {
    try {
      const p = filePath ?? panelPaths.checkpointFile;
      let txt: string;
      try {
        txt = await fsp.readFile(p, "utf8");
      } catch {
        return;
      }
      const obj = JSON.parse(txt);
      const upsert = rawDb.prepare(`
        INSERT OR REPLACE INTO webhook_events (event_id, event_type, status, attempts, last_error, payload_json, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `);
      const delivered = obj.deliveredEvents ?? {};
      for (const [eid, payload] of Object.entries<any>(delivered)) {
        upsert.run(eid, payload?.eventType ?? null, "delivered", payload?.attempts ?? 1, null, null, Date.now());
      }
      const pending = obj.pendingWebhookEvents ?? {};
      for (const [eid, evt] of Object.entries<any>(pending)) {
        upsert.run(
          eid,
          evt?.eventType ?? evt?.payload?.event ?? null,
          "pending",
          evt?.attempts ?? 0,
          evt?.lastError ?? null,
          evt?.payload ? JSON.stringify(evt.payload).slice(0, 8000) : null,
          Date.now(),
        );
      }
    } catch {}
  }
}

const g = globalThis as unknown as Globals;
if (!g.__panelIngestWatcher) g.__panelIngestWatcher = new IngestWatcher();
export const ingestWatcher = g.__panelIngestWatcher;
