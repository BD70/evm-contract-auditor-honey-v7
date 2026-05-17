
import fs from "node:fs";
import path from "node:path";
import chokidar, { type FSWatcher } from "chokidar";
import { panelPaths } from "./paths";
import { ingestApiJson, upsertDeployment } from "./findings-store";
import { rawDb } from "@/src/db/client";

const MAX_INGEST_BYTES = 8 * 1024 * 1024;

type Globals = { __panelIngestWatcher?: IngestWatcher };

class IngestWatcher {
  private watcher: FSWatcher | null = null;
  private started = false;
  private seen = new Set<string>();

  async startIfNeeded() {
    if (this.started) return;
    this.started = true;
    try {
      fs.mkdirSync(panelPaths.artifactsDir, { recursive: true });
    } catch {}
    // One-shot reconcile
    this.reconcile().catch((err) => console.warn("[ingest] reconcile error", err));

    this.watcher = chokidar.watch(
      [`${panelPaths.artifactsDir}/**/*.json`, panelPaths.checkpointFile],
      {
        ignoreInitial: true,
        awaitWriteFinish: { stabilityThreshold: 250, pollInterval: 100 },
      },
    );
    this.watcher.on("add", (p) => this.handlePath(p).catch(() => {}));
    this.watcher.on("change", (p) => this.handlePath(p).catch(() => {}));
  }

  async stop() {
    if (this.watcher) await this.watcher.close();
    this.watcher = null;
    this.started = false;
  }

  private async reconcile() {
    if (!fs.existsSync(panelPaths.artifactsDir)) return;
    const stack = [panelPaths.artifactsDir];
    while (stack.length) {
      const dir = stack.pop()!;
      let entries: fs.Dirent[];
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        continue;
      }
      for (const e of entries) {
        const full = path.join(dir, e.name);
        if (e.isDirectory()) stack.push(full);
        else if (e.isFile() && full.endsWith(".json")) {
          await this.handlePath(full);
        }
      }
    }
    await this.ingestCheckpoint();
  }

  private async handlePath(p: string) {
    if (p === panelPaths.checkpointFile) return this.ingestCheckpoint();
    if (!p.endsWith(".json")) return;
    if (this.seen.has(p)) return;

    try {
      const stat = fs.statSync(p);
      if (stat.size > MAX_INGEST_BYTES) return;
      const txt = fs.readFileSync(p, "utf8");
      const obj = JSON.parse(txt);

      // Extract deployment + audit linkage from path: artifacts/<chainId>/<block>/<tx>/<kind>.json
      const segs = path.relative(panelPaths.artifactsDir, p).split(path.sep);
      let chainId: number | null = null;
      let blockNumber: number | null = null;
      let txHash: string | null = null;
      if (segs.length >= 4) {
        chainId = Number(segs[0]) || null;
        blockNumber = Number(segs[1]) || null;
        txHash = segs[2];
      }

      const file = path.basename(p);
      if (file === "deployment.json") {
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
      } else if (obj && obj.schema && String(obj.schema).startsWith("evm-audit.api")) {
        const contractAddress =
          obj.contract_address ?? obj.bytecode_identity?.contract_address ?? null;
        const bytecodeHash =
          obj.bytecode_identity?.bytecode_hash ?? obj.bytecode_identity?.runtime_code_hash ?? null;
        ingestApiJson(obj, {
          source: "runner",
          chainId,
          blockNumber,
          txHash,
          contractAddress,
          bytecodeHash,
        });
      }
      this.seen.add(p);
    } catch (err) {
      // swallow
    }
  }

  private async ingestCheckpoint() {
    try {
      if (!fs.existsSync(panelPaths.checkpointFile)) return;
      const txt = fs.readFileSync(panelPaths.checkpointFile, "utf8");
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
