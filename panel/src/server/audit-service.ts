
import { spawn } from "node:child_process";
import path from "node:path";
import fs from "node:fs";
import crypto from "node:crypto";
import { nanoid } from "nanoid";
import { EventEmitter } from "node:events";
import { panelPaths, ensurePanelDirs } from "./paths";
import { rawDb } from "@/src/db/client";
import { ingestApiJson } from "./findings-store";
import { readEnvAll } from "./env-store";
import { resolveAuditorBin } from "./auditor-bin";

export type ManualKind = "manual_hex" | "manual_file" | "manual_address" | "reaudit";

export interface AuditInput {
  kind: ManualKind;
  bytecode?: string; // hex
  address?: string;
  chainId?: number;
  rpcUrl?: string;
  filename?: string;
  inputSummary?: string;
  llmJudge?: boolean;
  llmJudgeRefresh?: boolean;
  rulesPath?: string;
  chainContext?: Record<string, unknown>;
  reauditOf?: string;
}

export interface AuditProgressEvent {
  ts: number;
  level: "info" | "warn" | "error";
  msg: string;
}

type Globals = { __panelAuditEvents?: EventEmitter };
const g = globalThis as unknown as Globals;
if (!g.__panelAuditEvents) {
  g.__panelAuditEvents = new EventEmitter();
  g.__panelAuditEvents.setMaxListeners(500);
}
export const auditEvents = g.__panelAuditEvents!;

function normalizeHex(s: string): string {
  let v = s.trim();
  if (v.startsWith("0x") || v.startsWith("0X")) v = v.slice(2);
  return v;
}

function sha256(buf: Buffer): string {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function rulesDir(override?: string): string {
  if (override) {
    return path.isAbsolute(override) ? override : path.join(panelPaths.repoRoot, override);
  }
  return panelPaths.rulesDir;
}

export async function resolveBytecode(input: AuditInput): Promise<{ hex: string; summary: string; address?: string }> {
  if (input.kind === "manual_hex") {
    if (!input.bytecode) throw new Error("bytecode is required");
    const hex = normalizeHex(input.bytecode);
    if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length === 0) throw new Error("invalid hex bytecode");
    return { hex, summary: input.inputSummary ?? `hex paste (${hex.length / 2} bytes)` };
  }
  if (input.kind === "manual_address") {
    if (!input.address) throw new Error("address required");
    const rpcUrl = input.rpcUrl ?? readEnvAll().RPC_HTTP_URL;
    if (!rpcUrl) throw new Error("no rpc URL configured");
    const code = await rpcGetCode(rpcUrl, input.address);
    if (!code || code === "0x" || code === "0x0") throw new Error("no code at address");
    const hex = normalizeHex(code);
    return { hex, summary: `${input.address} (chain ${input.chainId ?? "?"})`, address: input.address };
  }
  if (input.kind === "manual_file") {
    if (!input.bytecode) throw new Error("file bytes missing");
    // bytecode field carries raw text content for files; could be hex or Solidity artifact JSON
    const txt = input.bytecode.trim();
    if (txt.startsWith("{")) {
      try {
        const obj = JSON.parse(txt);
        const candidates = [
          obj.deployedBytecode?.object,
          obj.deployedBytecode,
          obj.bytecode?.object,
          obj.bytecode,
          obj.evm?.deployedBytecode?.object,
        ];
        for (const c of candidates) {
          if (typeof c === "string" && c.length > 0) {
            return { hex: normalizeHex(c), summary: `file ${input.filename ?? ""} (artifact deployedBytecode)` };
          }
        }
        throw new Error("artifact JSON has no deployedBytecode");
      } catch (err: any) {
        throw new Error(`failed to parse artifact JSON: ${err?.message ?? err}`);
      }
    }
    const hex = normalizeHex(txt);
    if (!/^[0-9a-fA-F]+$/.test(hex)) throw new Error("file is not valid hex or artifact JSON");
    return { hex, summary: `file ${input.filename ?? "upload"} (${hex.length / 2} bytes)` };
  }
  if (input.kind === "reaudit") {
    if (!input.bytecode) throw new Error("reaudit needs bytecode");
    return { hex: normalizeHex(input.bytecode), summary: `reaudit of finding ${input.reauditOf ?? "?"}` };
  }
  throw new Error(`unknown kind ${(input as any).kind}`);
}

async function rpcGetCode(rpcUrl: string, address: string): Promise<string> {
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "eth_getCode",
    params: [address, "latest"],
  });
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), 15_000);
  try {
    const r = await fetch(rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
      signal: ac.signal,
    });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const j: any = await r.json();
    if (j.error) throw new Error(`rpc error: ${j.error.message ?? JSON.stringify(j.error)}`);
    return j.result;
  } finally {
    clearTimeout(timer);
  }
}

export interface StartedAudit {
  runId: string;
}

export async function startAudit(input: AuditInput): Promise<StartedAudit> {
  ensurePanelDirs();
  const runId = nanoid(16);
  const started = Date.now();
  const resolved = await resolveBytecode(input);
  const buf = Buffer.from(resolved.hex, "hex");
  const bytecodeHash = sha256(buf);
  const tmpFile = path.join(panelPaths.uploadsDir, `${runId}.hex`);
  fs.writeFileSync(tmpFile, "0x" + resolved.hex);

  rawDb
    .prepare(
      `INSERT INTO audit_runs (id, kind, input_summary, bytecode_hash, contract_address, chain_id, rules_fingerprint, started_at, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'running')`,
    )
    .run(
      runId,
      input.kind,
      resolved.summary,
      bytecodeHash,
      resolved.address ?? null,
      input.chainId ?? null,
      input.rulesPath ?? "rules/core",
      started,
    );

  const auditorBin = resolveAuditorBin("evm-audit");
  const argv = [
    "--file",
    tmpFile,
    "--rules",
    rulesDir(input.rulesPath),
    "--format",
    "api-json",
    "--no-resolve",
  ];
  if (input.llmJudge) argv.push("--llm-judge");
  if (input.llmJudgeRefresh) argv.push("--llm-judge-refresh");
  if (input.chainContext) argv.push("--chain-context", JSON.stringify(input.chainContext));

  const emit = (e: AuditProgressEvent) => auditEvents.emit(`run:${runId}`, e);
  emit({ ts: Date.now(), level: "info", msg: `starting ${auditorBin} ${argv.join(" ")}` });

  const proc = spawn(auditorBin, argv, {
    cwd: panelPaths.repoRoot,
    env: { ...process.env },
    stdio: ["ignore", "pipe", "pipe"],
  });

  const stdoutChunks: Buffer[] = [];
  const stderrChunks: string[] = [];
  let outBytes = 0;
  const MAX_OUT = 16 * 1024 * 1024;

  proc.stdout?.on("data", (chunk: Buffer) => {
    outBytes += chunk.length;
    if (outBytes > MAX_OUT) {
      proc.kill("SIGKILL");
      return;
    }
    stdoutChunks.push(chunk);
  });
  proc.stderr?.on("data", (chunk: Buffer) => {
    const txt = chunk.toString("utf8");
    stderrChunks.push(txt);
    for (const line of txt.split("\n")) {
      const l = line.trim();
      if (!l) continue;
      emit({ ts: Date.now(), level: "info", msg: l });
    }
  });

  proc.on("error", (err) => {
    emit({ ts: Date.now(), level: "error", msg: `spawn error: ${err.message}` });
  });

  proc.on("exit", (code) => {
    const finishedAt = Date.now();
    const duration = finishedAt - started;
    const stderr = stderrChunks.join("");
    const stdout = Buffer.concat(stdoutChunks).toString("utf8");
    let api: any = null;
    let parseErr: string | null = null;
    if (code === 0 && stdout) {
      try {
        api = JSON.parse(stdout);
      } catch (err: any) {
        parseErr = err?.message ?? String(err);
      }
    }
    let findingCount = 0;
    if (api) {
      const ctx = {
        source: "manual" as const,
        runId,
        chainId: input.chainId ?? null,
        contractAddress: resolved.address ?? null,
        bytecodeHash,
      };
      const { ids } = ingestApiJson(api, ctx);
      findingCount = ids.length;
    }
    rawDb
      .prepare(
        `UPDATE audit_runs SET finished_at=?, duration_ms=?, status=?, stderr_tail=?, finding_count=?, raw_json=?, error=? WHERE id=?`,
      )
      .run(
        finishedAt,
        duration,
        code === 0 && api ? "ok" : "failed",
        stderr.slice(-4096),
        findingCount,
        api ? JSON.stringify(api).slice(0, 2 * 1024 * 1024) : null,
        code === 0 ? parseErr : `exit ${code}`,
        runId,
      );
    emit({
      ts: finishedAt,
      level: code === 0 && !parseErr ? "info" : "error",
      msg: code === 0 ? `done; ${findingCount} findings` : `failed (exit ${code})`,
    });
    auditEvents.emit(`done:${runId}`, { runId, status: code === 0 && api ? "ok" : "failed", findingCount });
    try { fs.unlinkSync(tmpFile); } catch {}
  });

  return { runId };
}

export function getAuditRun(runId: string): any | null {
  const row = rawDb.prepare(`SELECT * FROM audit_runs WHERE id = ?`).get(runId) as any;
  if (!row) return null;
  return {
    ...row,
    raw: row.raw_json ? JSON.parse(row.raw_json) : null,
  };
}
