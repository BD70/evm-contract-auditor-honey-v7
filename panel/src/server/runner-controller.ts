
import { spawn, type ChildProcess, execFileSync } from "node:child_process";
import { EventEmitter } from "node:events";
import path from "node:path";
import fs from "node:fs";
import { panelPaths } from "./paths";
import { rawDb } from "@/src/db/client";

export type RunnerStatus = "idle" | "starting" | "running" | "stopping" | "crashed";

export interface LogLine {
  ts: number;
  level: "debug" | "info" | "warn" | "error" | "stderr";
  msg: string;
  raw?: unknown;
}

export interface StartArgs {
  replayBlock?: number;
  replayRange?: { from: number; to: number };
  once?: boolean;
  rules?: string;
  noWebhook?: boolean;
  dryRunWebhook?: boolean;
  startBlock?: number;
}

export const DEFAULT_SLUG = "__default__";

export interface RunnerControllerOptions {
  slug?: string;
  healthPort?: number;
}

export interface RunnerSnapshot {
  slug: string;
  status: RunnerStatus;
  pid: number | null;
  startedAt: number | null;
  stoppedAt: number | null;
  lastExitCode: number | null;
  lastError: string | null;
  health: any;
  metrics: Record<string, number> | null;
  args: StartArgs | null;
}

// Per-runner log ring. Dropped from 10_000 → 2_000 because we run 14 chain
// runners and the previous setting could keep ~14 × 10k × ~300 B = ~42 MB of
// log lines pinned in panel-process memory, contributing to the Node-OOM /
// pm2-restart cycle that made AVAX (largest backlog) look like it was
// "crashing". 2_000 lines × 14 chains ≈ 8 MB worst-case.
const BUF_SIZE = 500;
const HEALTH_PORT = Number(process.env.HEALTH_PORT ?? 9090);

export class RunnerController extends EventEmitter {
  readonly slug: string;
  private readonly healthPort: number;
  status: RunnerStatus = "idle";
  pid: number | null = null;
  startedAt: number | null = null;
  stoppedAt: number | null = null;
  lastExitCode: number | null = null;
  lastError: string | null = null;
  args: StartArgs | null = null;
  health: any = null;
  metrics: Record<string, number> | null = null;

  private proc: ChildProcess | null = null;
  private buffer: LogLine[] = [];
  private healthTimer: NodeJS.Timeout | null = null;
  private stderrPartial = "";
  private stdoutPartial = "";

  constructor(opts: RunnerControllerOptions = {}) {
    super();
    this.slug = opts.slug ?? DEFAULT_SLUG;
    this.healthPort = opts.healthPort ?? HEALTH_PORT;
  }

  private get isChain(): boolean {
    return this.slug !== DEFAULT_SLUG;
  }

  private get lockDir(): string {
    return this.isChain ? path.join(panelPaths.stateDir, this.slug) : panelPaths.stateDir;
  }

  snapshot(): RunnerSnapshot {
    return {
      slug: this.slug,
      status: this.status,
      pid: this.pid,
      startedAt: this.startedAt,
      stoppedAt: this.stoppedAt,
      lastExitCode: this.lastExitCode,
      lastError: this.lastError,
      health: this.health,
      metrics: this.metrics,
      args: this.args,
    };
  }

  tail(n = 200): LogLine[] {
    return this.buffer.slice(Math.max(0, this.buffer.length - n));
  }

  async start(args: StartArgs = {}): Promise<void> {
    if (this.status === "running" || this.status === "starting") {
      throw new Error("runner already running");
    }
    this.args = args;
    this.lastError = null;
    this.setStatus("starting");
    await this.clearStaleLock();

    const flags: string[] = ["runner/src/cli.ts"];
    if (args.once) flags.push("--once");
    if (args.replayBlock !== undefined) flags.push("--replay-block", String(args.replayBlock));
    if (args.replayRange) flags.push("--replay-range", `${args.replayRange.from}:${args.replayRange.to}`);
    if (args.rules) flags.push("--rules", args.rules);
    if (args.noWebhook) flags.push("--no-webhook");
    if (args.dryRunWebhook) flags.push("--dry-run-webhook");
    if (args.startBlock !== undefined) flags.push("--start-block", String(args.startBlock));
    if (this.isChain) flags.push("--chain", this.slug);

    const env = { ...process.env, UI_MODE: "json", HEALTH_PORT: String(this.healthPort) };

    this.pushLog({ ts: Date.now(), level: "info", msg: `spawning bun ${flags.join(" ")} (slug=${this.slug}, healthPort=${this.healthPort}, cwd=${panelPaths.repoRoot})` });

    let proc: ChildProcess;
    try {
      proc = spawn("bun", flags, {
        cwd: panelPaths.repoRoot,
        env,
        stdio: ["ignore", "pipe", "pipe"],
        // detached: true assigns a new process group so we can SIGTERM/SIGKILL
        // the entire tree (bun + any python subprocess it spawned)
        detached: true,
      });
      // Don't hold the parent open if it tries to exit — child still keeps running
      // until explicitly killed, which is what we want.
      proc.unref();
    } catch (err: any) {
      this.lastError = err?.message ?? String(err);
      this.pushLog({ ts: Date.now(), level: "error", msg: `failed to spawn bun: ${this.lastError}` });
      this.setStatus("crashed");
      throw err;
    }

    this.proc = proc;
    this.pid = proc.pid ?? null;
    this.startedAt = Date.now();
    this.stoppedAt = null;

    rawDb
      .prepare(`INSERT INTO runner_lifecycle (event, pid, at) VALUES (?, ?, ?)`)
      .run("started", this.pid, this.startedAt);

    proc.stdout?.on("data", (chunk: Buffer) => this.consumeStdout(chunk.toString("utf8")));
    proc.stderr?.on("data", (chunk: Buffer) => this.consumeStderr(chunk.toString("utf8")));

    proc.on("error", (err) => {
      this.lastError = err.message;
      this.pushLog({ ts: Date.now(), level: "error", msg: `process error: ${err.message}` });
    });

    proc.on("exit", (code, signal) => {
      const exitedAt = Date.now();
      this.lastExitCode = code;
      this.stoppedAt = exitedAt;
      this.proc = null;
      this.pid = null;
      const reason = signal ? `signal ${signal}` : `exit ${code}`;
      const event = this.status === "stopping" ? "stopped" : code === 0 ? "stopped" : "crashed";
      this.pushLog({ ts: exitedAt, level: event === "crashed" ? "error" : "info", msg: `runner exited (${reason})` });
      this.setStatus(event === "crashed" ? "crashed" : "idle");
      if (this.healthTimer) {
        clearInterval(this.healthTimer);
        this.healthTimer = null;
      }
      rawDb
        .prepare(`INSERT INTO runner_lifecycle (event, pid, at, exit_code, reason) VALUES (?, ?, ?, ?, ?)`)
        .run(event, null, exitedAt, code, reason);
    });

    // Promote to running on first stdout / first healthy probe
    this.setStatus("running");
    this.beginHealthLoop();
  }

  async stop(opts: { graceful?: boolean; timeoutMs?: number } = {}): Promise<void> {
    if (!this.proc) return;
    if (this.status === "stopping") {
      // Already stopping — wait for exit, but escalate if it drags on.
      return this.awaitExit(opts.timeoutMs ?? 12_000);
    }
    this.setStatus("stopping");
    const proc = this.proc;
    const graceful = opts.graceful !== false;
    const graceMs = Math.max(1000, opts.timeoutMs ?? 8_000);

    const sendSignal = (sig: NodeJS.Signals) => {
      const pid = proc.pid;
      if (!pid) return false;
      try {
        // Kill the whole process group (bun + python child + watchers).
        // Negative pid = process group on POSIX.
        process.kill(-pid, sig);
        return true;
      } catch (err: any) {
        // ESRCH = already gone. Anything else, fall back to single-process kill.
        if (err?.code === "ESRCH") return false;
        try {
          proc.kill(sig);
          return true;
        } catch {
          return false;
        }
      }
    };

    this.pushLog({ ts: Date.now(), level: "info", msg: graceful ? "sending SIGTERM to runner group" : "sending SIGKILL to runner group" });
    sendSignal(graceful ? "SIGTERM" : "SIGKILL");
    try {
      await this.awaitExit(graceMs);
    } catch {
      this.pushLog({ ts: Date.now(), level: "warn", msg: `graceful stop timed out after ${graceMs}ms; sending SIGKILL` });
      sendSignal("SIGKILL");
      try {
        await this.awaitExit(5_000);
      } catch {
        this.pushLog({ ts: Date.now(), level: "error", msg: "SIGKILL did not reap process within 5s; abandoning handle" });
        // Force the snapshot into a terminal state so the UI is honest.
        this.proc = null;
        this.pid = null;
        this.stoppedAt = Date.now();
        this.setStatus("crashed");
      }
    }
  }

  private awaitExit(timeoutMs: number): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const proc = this.proc;
      if (!proc) return resolve();
      const t = setTimeout(() => reject(new Error("exit timeout")), timeoutMs);
      const onExit = () => {
        clearTimeout(t);
        resolve();
      };
      proc.once("exit", onExit);
    });
  }

  async restart(args?: StartArgs): Promise<void> {
    if (this.proc) await this.stop({ graceful: true });
    await this.start(args ?? this.args ?? {});
  }

  private async clearStaleLock(): Promise<void> {
    const lockPath = path.join(this.lockDir, ".runner.lock");
    try {
      if (!fs.existsSync(lockPath)) return;
      const txt = fs.readFileSync(lockPath, "utf8");
      const owner = JSON.parse(txt) as { pid?: number; acquiredAt?: string };
      if (typeof owner?.pid !== "number") {
        fs.rmSync(lockPath, { force: true });
        this.pushLog({ ts: Date.now(), level: "warn", msg: `cleared malformed runner lock at ${lockPath}` });
        return;
      }

      // Lock owner alive? `kill(pid, 0)` throws ESRCH if not.
      let alive = false;
      try {
        process.kill(owner.pid, 0);
        alive = true;
      } catch (err: any) {
        if (err?.code === "ESRCH") {
          fs.rmSync(lockPath, { force: true });
          this.pushLog({
            ts: Date.now(),
            level: "warn",
            msg: `cleared stale runner lock (pid ${owner.pid} not running)`,
          });
          return;
        }
        if (err?.code === "EPERM") alive = true;
      }
      if (!alive) return;

      const ourPid = this.proc?.pid;
      if (ourPid && owner.pid === ourPid) return;

      // Lock owner is alive but NOT our current child. That's an orphan from a
      // previous panel session (PM2 restart, crash, ulimit OOM) that survived
      // because we spawn detached. The orphan never releases its lock on its
      // own, so without reaping the new spawn loops "state directory is
      // already in use" forever. Verify it's actually one of our runners via
      // `ps` (matches `runner/src/cli.ts` + `--chain <slug>`) before killing.
      if (!looksLikeRunnerProcess(owner.pid, this.slug)) {
        this.pushLog({
          ts: Date.now(),
          level: "warn",
          msg: `lock pid ${owner.pid} is alive but doesn't look like a runner process — leaving lock alone`,
        });
        return;
      }

      this.pushLog({
        ts: Date.now(),
        level: "warn",
        msg: `reaping orphan runner (pid ${owner.pid}, acquiredAt=${owner.acquiredAt}) holding ${lockPath}`,
      });

      // Kill the process group (runner was spawned detached) so any bun
      // subprocesses go too. Fall back to per-pid kill if PGID kill fails.
      const sendSig = (sig: NodeJS.Signals) => {
        try { process.kill(-owner.pid!, sig); return; } catch {}
        try { process.kill(owner.pid!, sig); } catch {}
      };
      sendSig("SIGTERM");
      const isDead = () => {
        try { process.kill(owner.pid!, 0); return false; } catch (e: any) { return e?.code === "ESRCH"; }
      };
      const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
      const deadline = Date.now() + 3_000;
      while (!isDead() && Date.now() < deadline) await sleep(100);
      if (!isDead()) {
        sendSig("SIGKILL");
        const k2 = Date.now() + 1_000;
        while (!isDead() && Date.now() < k2) await sleep(50);
      }
      try { fs.rmSync(lockPath, { force: true }); } catch {}
      this.pushLog({
        ts: Date.now(),
        level: "info",
        msg: `orphan pid ${owner.pid} reaped; lock cleared`,
      });
    } catch (err: any) {
      this.pushLog({ ts: Date.now(), level: "warn", msg: `stale-lock check failed: ${err?.message ?? err}` });
    }
  }

  private setStatus(s: RunnerStatus) {
    if (this.status === s) return;
    this.status = s;
    this.emit("state", this.snapshot());
  }

  private pushLog(line: LogLine) {
    this.buffer.push(line);
    if (this.buffer.length > BUF_SIZE) this.buffer.splice(0, this.buffer.length - BUF_SIZE);
    this.emit("log", line);
  }

  private consumeStdout(chunk: string) {
    this.stdoutPartial += chunk;
    let nl;
    while ((nl = this.stdoutPartial.indexOf("\n")) >= 0) {
      const line = this.stdoutPartial.slice(0, nl).trim();
      this.stdoutPartial = this.stdoutPartial.slice(nl + 1);
      if (!line) continue;
      this.parseAndPush(line, false);
    }
  }

  private consumeStderr(chunk: string) {
    this.stderrPartial += chunk;
    let nl;
    while ((nl = this.stderrPartial.indexOf("\n")) >= 0) {
      const line = this.stderrPartial.slice(0, nl).trim();
      this.stderrPartial = this.stderrPartial.slice(nl + 1);
      if (!line) continue;
      this.parseAndPush(line, true);
    }
  }

  private parseAndPush(line: string, isStderr: boolean) {
    try {
      const obj = JSON.parse(line);
      const lvl = String(obj.level ?? (isStderr ? "error" : "info")).toLowerCase();
      const level: LogLine["level"] =
        lvl === "debug" || lvl === "info" || lvl === "warn" || lvl === "error" ? (lvl as LogLine["level"]) : isStderr ? "stderr" : "info";
      const msg = obj.message ?? obj.msg ?? line;
      const ts = typeof obj.ts === "number" ? obj.ts : Date.now();
      this.pushLog({ ts, level, msg, raw: obj });
    } catch {
      this.pushLog({ ts: Date.now(), level: isStderr ? "stderr" : "info", msg: line });
    }
  }

  private beginHealthLoop() {
    if (this.healthTimer) clearInterval(this.healthTimer);
    const poll = async () => {
      try {
        const health = await fetchJson(`http://127.0.0.1:${this.healthPort}/health`, 4000);
        this.health = health;
      } catch (err: any) {
        this.health = { ok: false, error: err?.message ?? String(err) };
      }
      try {
        const metricsTxt = await fetchText(`http://127.0.0.1:${this.healthPort}/metrics`, 4000);
        this.metrics = parsePromMetrics(metricsTxt);
      } catch {
        this.metrics = null;
      }
      this.emit("state", this.snapshot());
    };
    poll();
    this.healthTimer = setInterval(poll, 5000);
  }
}

async function fetchJson(url: string, timeoutMs: number): Promise<any> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const r = await fetch(url, { signal: ac.signal });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return await r.json();
  } finally {
    clearTimeout(t);
  }
}
async function fetchText(url: string, timeoutMs: number): Promise<string> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const r = await fetch(url, { signal: ac.signal });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return await r.text();
  } finally {
    clearTimeout(t);
  }
}

function parsePromMetrics(txt: string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const rawLine of txt.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const m = line.match(/^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{[^}]*\})?\s+([0-9.eE+\-]+)/);
    if (m) {
      const v = Number(m[2]);
      if (Number.isFinite(v)) out[m[1]] = v;
    }
  }
  return out;
}

class RunnerRegistry {
  private controllers = new Map<string, RunnerController>();

  constructor() {
    this.controllers.set(DEFAULT_SLUG, new RunnerController());
  }

  default(): RunnerController {
    return this.controllers.get(DEFAULT_SLUG)!;
  }

  /** Get-or-create a per-chain controller. healthPort must be stable per slug. */
  ensure(slug: string, healthPort: number): RunnerController {
    if (slug === DEFAULT_SLUG) return this.default();
    let c = this.controllers.get(slug);
    if (!c) {
      c = new RunnerController({ slug, healthPort });
      this.controllers.set(slug, c);
    }
    return c;
  }

  get(slug: string): RunnerController | undefined {
    return this.controllers.get(slug);
  }

  all(): RunnerController[] {
    return [...this.controllers.values()];
  }

  remove(slug: string): void {
    if (slug === DEFAULT_SLUG) return;
    this.controllers.delete(slug);
  }
}

type Globals = { __panelRunnerRegistry?: RunnerRegistry };
const g = globalThis as unknown as Globals;
if (!g.__panelRunnerRegistry) g.__panelRunnerRegistry = new RunnerRegistry();

export const runnerRegistry = g.__panelRunnerRegistry;
export const runnerController = runnerRegistry.default();

// Suppress unused import warnings on platforms that tree-shake
void path;
void fs;

/**
 * Best-effort sanity check that `pid` looks like one of OUR runner processes
 * before we kill it. Reads `ps` for the PID's command line and looks for
 * `runner/src/cli.ts` and (when slug is provided) the chain slug.
 *
 * This is intentionally conservative: if we can't read `ps` or anything looks
 * off, return false so we leave the foreign process alone and surface the
 * lock error to the operator.
 */
function looksLikeRunnerProcess(pid: number, slug: string): boolean {
  try {
    const out = execFileSync("ps", ["-o", "command=", "-p", String(pid)], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 2_000,
    }).trim();
    if (!out.includes("runner/src/cli.ts")) return false;
    // Default (legacy) supervisor doesn't pass --chain; only chain-mode runners do.
    if (slug && slug !== "default") {
      return out.includes(`--chain ${slug}`);
    }
    return true;
  } catch {
    return false;
  }
}
