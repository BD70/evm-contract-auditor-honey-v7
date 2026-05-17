// Lazy pool of forked Anvil instances keyed by chainId. Each fork stays warm
// for IDLE_MS after the most recent acquire() so back-to-back simulations on
// the same chain reuse the same anvil process (forking is the expensive step:
// 1-3s of cold-start RPC chatter). Idle forks are torn down automatically.
//
// We cap MAX_LIVE concurrent forks; if a new chain is requested past the cap,
// the longest-idle fork is evicted. The pool gracefully degrades when anvil
// is not on PATH (verification is simply disabled).

import { spawn, type ChildProcess } from "node:child_process";
import { readChainsRaw } from "../chains-store";
import { chainMetaByChainId } from "@/src/lib/chain-meta";

const ANVIL_BIN = process.env.ANVIL_BIN ?? "anvil";
const IDLE_MS = Number(process.env.SIM_ANVIL_IDLE_MS ?? 120_000);
const MAX_LIVE = Math.max(1, Number(process.env.SIM_ANVIL_MAX_LIVE ?? 2));
const SPAWN_TIMEOUT_MS = Number(process.env.SIM_ANVIL_SPAWN_TIMEOUT_MS ?? 30_000);
const FORK_GAS_LIMIT = process.env.SIM_ANVIL_GAS_LIMIT ?? "30000000";

// Anvil's deterministic dev accounts (mnemonic "test test ..."). We hardcode
// the first two; account 0 is the attacker, account 1 is a victim relayer
// when we need a second non-attacker identity.
export const ATTACKER_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
export const ATTACKER_PRIVKEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
export const RELAYER_ADDRESS = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

// Deterministic probe address. We inject the probe runtime here via
// `anvil_setCode` on every fresh anvil instance, so verifiers never need to
// deploy the probe themselves (which used to cost a deploy + receipt + code
// sanity check, ~3 RPC roundtrips per verification). The runtime is:
//   33 60 00 55 00   ; CALLER  PUSH1 0  SSTORE  STOP
export const PROBE_ADDRESS = "0x000000000000000000000000000000000000bEEF";
export const PROBE_RUNTIME = "0x3360005500";

// Re-entering probe address used exclusively by the reentrancy verifier. We
// keep this separate from PROBE_ADDRESS because the re-entering probe has
// state-dependent behaviour (it reads a stored selector from slot 1 and
// re-enters the caller with it); we don't want that bleeding into other
// verifiers' traces.
//
// Runtime (31 bytes) — assembled by hand. Disassembly:
//   00: 33                  CALLER
//   01: 60 00               PUSH1 0
//   03: 55                  SSTORE                ; sstore(0, caller())  - witness
//   04: 60 01               PUSH1 1
//   06: 54                  SLOAD                 ; selector = sload(1)
//   07: 80                  DUP1
//   08: 15                  ISZERO
//   09: 60 1D               PUSH1 0x1D            ; jump-past-callback offset
//   0B: 57                  JUMPI                 ; if selector == 0, skip
//   0C: 60 00               PUSH1 0
//   0E: 52                  MSTORE                ; mstore(0, selector)
//   0F: 60 00               PUSH1 0               ; retSize
//   11: 60 00               PUSH1 0               ; retOffset
//   13: 60 04               PUSH1 4               ; inSize (low 4 bytes of selector)
//   15: 60 1C               PUSH1 0x1C            ; inOffset = 28 (right-aligned)
//   17: 60 00               PUSH1 0               ; value
//   19: 33                  CALLER                ; to = caller (the victim)
//   1A: 5A                  GAS                   ; gas = all
//   1B: F1                  CALL
//   1C: 50                  POP                   ; discard success
//   1D: 5B                  JUMPDEST
//   1E: 00                  STOP
//
// Verifiers configure the re-entry selector with anvil_setStorageAt(probe, 0x01, …).
// If slot 1 is zero, the probe behaves exactly like PROBE_RUNTIME (witness-only).
export const REENTRY_PROBE_ADDRESS = "0x000000000000000000000000000000000000fEEd";
export const REENTRY_PROBE_RUNTIME = "0x336000556001548015601d5760005260006000600460" +
  "1c600033" + "5af1" + "50" + "5b00";

export interface AnvilInstance {
  chainId: number;
  rpcUrl: string;
  port: number;
  url: string;
  pid: number;
  startedAt: number;
  lastUsedAt: number;
  /** Block number the fork was rooted at (read once after spawn). */
  forkBlock: number | null;
  /** Address of the always-on probe contract. Pre-deployed via anvil_setCode. */
  probeAddress: string;
}

interface Slot extends AnvilInstance {
  proc: ChildProcess;
  idleTimer: NodeJS.Timeout | null;
  ready: Promise<void>;
}

type Globals = { __anvilPool?: AnvilPool };

class AnvilPool {
  private slots = new Map<number, Slot>(); // keyed by chainId
  private spawning = new Map<number, Promise<Slot>>();
  private installed: boolean | null = null;
  private shuttingDown = false;

  constructor() {
    const shutdown = () => this.shutdown().catch(() => {});
    process.on("exit", shutdown);
    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
  }

  /** Returns true if anvil is on PATH (or at ANVIL_BIN); cached after first probe. */
  async isAvailable(): Promise<boolean> {
    if (this.installed != null) return this.installed;
    try {
      const p = spawn(ANVIL_BIN, ["--version"], { stdio: ["ignore", "pipe", "pipe"] });
      const ok = await new Promise<boolean>((resolve) => {
        const t = setTimeout(() => {
          try { p.kill("SIGKILL"); } catch {}
          resolve(false);
        }, 2000);
        p.once("exit", (code) => {
          clearTimeout(t);
          resolve(code === 0);
        });
        p.once("error", () => {
          clearTimeout(t);
          resolve(false);
        });
      });
      this.installed = ok;
    } catch {
      this.installed = false;
    }
    return this.installed;
  }

  /** Get (or spawn) a forked anvil for chainId. */
  async acquire(chainId: number): Promise<AnvilInstance | null> {
    if (this.shuttingDown) return null;
    if (!(await this.isAvailable())) return null;
    const existing = this.slots.get(chainId);
    if (existing) {
      this.touch(existing);
      return this.publicView(existing);
    }
    const pending = this.spawning.get(chainId);
    if (pending) {
      const slot = await pending;
      this.touch(slot);
      return this.publicView(slot);
    }
    const promise = this.spawnSlot(chainId);
    this.spawning.set(chainId, promise);
    try {
      const slot = await promise;
      return this.publicView(slot);
    } finally {
      this.spawning.delete(chainId);
    }
  }

  /** Force-close a chain's fork (e.g. after detecting RPC errors). */
  async drop(chainId: number): Promise<void> {
    const s = this.slots.get(chainId);
    if (!s) return;
    this.slots.delete(chainId);
    await this.killSlot(s);
  }

  async shutdown(): Promise<void> {
    this.shuttingDown = true;
    await Promise.all([...this.slots.values()].map((s) => this.killSlot(s)));
    this.slots.clear();
  }

  // ---------- internals ----------

  private publicView(s: Slot): AnvilInstance {
    return {
      chainId: s.chainId,
      rpcUrl: s.rpcUrl,
      port: s.port,
      url: s.url,
      pid: s.pid,
      startedAt: s.startedAt,
      lastUsedAt: s.lastUsedAt,
      forkBlock: s.forkBlock,
      probeAddress: PROBE_ADDRESS,
    };
  }

  private touch(s: Slot) {
    s.lastUsedAt = Date.now();
    if (s.idleTimer) clearTimeout(s.idleTimer);
    s.idleTimer = setTimeout(() => {
      this.slots.delete(s.chainId);
      this.killSlot(s).catch(() => {});
    }, IDLE_MS);
    s.idleTimer.unref?.();
  }

  private async evictOldestIfNeeded() {
    if (this.slots.size < MAX_LIVE) return;
    let oldest: Slot | null = null;
    for (const s of this.slots.values()) {
      if (!oldest || s.lastUsedAt < oldest.lastUsedAt) oldest = s;
    }
    if (oldest) {
      this.slots.delete(oldest.chainId);
      await this.killSlot(oldest);
    }
  }

  private resolveRpcUrl(chainId: number): string | null {
    const meta = chainMetaByChainId(chainId);
    if (!meta) return null;
    const entry = readChainsRaw().find((c) => c.slug === meta.slug);
    return entry?.rpcHttpUrl ?? null;
  }

  private async spawnSlot(chainId: number): Promise<Slot> {
    await this.evictOldestIfNeeded();
    const rpcUrl = this.resolveRpcUrl(chainId);
    if (!rpcUrl) throw new Error(`no rpc configured for chainId=${chainId}`);
    const args = [
      "--fork-url", rpcUrl,
      "--port", "0",
      "--accounts", "2",
      "--balance", "1000",
      "--gas-limit", FORK_GAS_LIMIT,
      "--code-size-limit", "1048576",
      "--no-rate-limit",
    ];
    // NOTE: do NOT pass --no-mining; anvil's default auto-mining is what makes
    // eth_sendTransaction synchronous. With --no-mining, txs sit in the
    // mempool and cast/viem calls block forever.
    const proc = spawn(ANVIL_BIN, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdoutBuf = "";
    let stderrBuf = "";
    let port = 0;
    const ready = new Promise<void>((resolve, reject) => {
      const t = setTimeout(() => {
        try { proc.kill("SIGKILL"); } catch {}
        reject(new Error(`anvil spawn timeout after ${SPAWN_TIMEOUT_MS}ms; stderr=${stderrBuf.slice(-400)}`));
      }, SPAWN_TIMEOUT_MS);
      const onLine = (line: string) => {
        // anvil emits e.g. "Listening on 127.0.0.1:61353" once ready
        const m = line.match(/Listening on (?:127\.0\.0\.1|0\.0\.0\.0):(\d+)/);
        if (m) {
          port = Number(m[1]);
          clearTimeout(t);
          resolve();
        }
      };
      proc.stdout?.on("data", (b: Buffer) => {
        stdoutBuf += b.toString("utf8");
        let idx;
        while ((idx = stdoutBuf.indexOf("\n")) >= 0) {
          const line = stdoutBuf.slice(0, idx);
          stdoutBuf = stdoutBuf.slice(idx + 1);
          onLine(line);
        }
        // cap retained buffer to avoid unbounded growth on long-lived anvils
        if (stdoutBuf.length > 16_384) stdoutBuf = stdoutBuf.slice(-4_096);
      });
      proc.stderr?.on("data", (b: Buffer) => {
        stderrBuf += b.toString("utf8");
        if (stderrBuf.length > 16_384) stderrBuf = stderrBuf.slice(-4_096);
      });
      proc.once("error", (err) => {
        clearTimeout(t);
        reject(err);
      });
      proc.once("exit", (code) => {
        clearTimeout(t);
        reject(new Error(`anvil exited (code=${code}) before ready; stderr=${stderrBuf.slice(-400)}`));
      });
    });
    try {
      await ready;
    } catch (err) {
      try { proc.kill("SIGKILL"); } catch {}
      throw err;
    }

    const slot: Slot = {
      chainId,
      rpcUrl,
      port,
      url: `http://127.0.0.1:${port}`,
      pid: proc.pid ?? -1,
      startedAt: Date.now(),
      lastUsedAt: Date.now(),
      forkBlock: null,
      probeAddress: PROBE_ADDRESS,
      proc,
      idleTimer: null,
      ready: Promise.resolve(),
    };

    // Look up the fork block once (best-effort).
    try {
      const r = await rpcRequest(slot.url, "eth_blockNumber", []);
      slot.forkBlock = Number(r);
    } catch {
      // ignore; we'll still serve simulations
    }

    // Pre-install the probes so verifiers can use them without paying a
    // deploy. Best-effort: if either call fails the relevant verifier will
    // skip rather than crash.
    try {
      await rpcRequest(slot.url, "anvil_setCode", [PROBE_ADDRESS, PROBE_RUNTIME]);
    } catch (err) {
      console.warn(`[sim] anvil_setCode probe failed on chainId=${chainId}:`, err);
    }
    try {
      await rpcRequest(slot.url, "anvil_setCode", [REENTRY_PROBE_ADDRESS, REENTRY_PROBE_RUNTIME]);
    } catch (err) {
      console.warn(`[sim] anvil_setCode reentry-probe failed on chainId=${chainId}:`, err);
    }

    proc.once("exit", () => {
      if (this.slots.get(chainId) === slot) {
        this.slots.delete(chainId);
        if (slot.idleTimer) clearTimeout(slot.idleTimer);
      }
    });

    this.slots.set(chainId, slot);
    this.touch(slot);
    console.info(`[sim] anvil spawned chainId=${chainId} pid=${slot.pid} port=${slot.port} fork=${slot.forkBlock}`);
    return slot;
  }

  private async killSlot(s: Slot): Promise<void> {
    if (s.idleTimer) {
      clearTimeout(s.idleTimer);
      s.idleTimer = null;
    }
    if (!s.proc.killed) {
      try { s.proc.kill("SIGTERM"); } catch {}
      await new Promise<void>((resolve) => {
        const t = setTimeout(() => {
          try { s.proc.kill("SIGKILL"); } catch {}
          resolve();
        }, 2000);
        s.proc.once("exit", () => {
          clearTimeout(t);
          resolve();
        });
      });
    }
  }
}

const gAny = globalThis as unknown as Globals;
if (!gAny.__anvilPool) gAny.__anvilPool = new AnvilPool();
export const anvilPool = gAny.__anvilPool!;

/** Tiny single-shot JSON-RPC call. We avoid pulling viem in here so anvil
 * comms have zero dependency surface; viem is loaded only by the exploit
 * driver which needs ABI encoding helpers. */
export async function rpcRequest<T = unknown>(
  url: string,
  method: string,
  params: unknown[],
  opts: { timeoutMs?: number } = {},
): Promise<T> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), opts.timeoutMs ?? 15_000);
  try {
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      signal: ac.signal,
    });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const j: any = await r.json();
    if (j.error) {
      const err = new Error(j.error.message ?? "rpc error");
      (err as any).code = j.error.code;
      (err as any).data = j.error.data;
      throw err;
    }
    return j.result as T;
  } finally {
    clearTimeout(t);
  }
}
