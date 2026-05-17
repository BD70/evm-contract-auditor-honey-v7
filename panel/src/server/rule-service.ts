
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { panelPaths } from "./paths";
import { readEnvAll } from "./env-store";
import { resolveAuditorBin } from "./auditor-bin";

export interface RuleMeta {
  ruleId: string;
  internalName: string | null;
  severity: string | null;
  category: string | null;
  userSummary: string | null;
  technicalSummary: string | null;
  fileName: string;
}

export function listRules(): RuleMeta[] {
  if (!fs.existsSync(panelPaths.rulesDir)) return [];
  const files = fs.readdirSync(panelPaths.rulesDir).filter((f) => f.endsWith(".json"));
  const out: RuleMeta[] = [];
  for (const f of files) {
    try {
      const txt = fs.readFileSync(path.join(panelPaths.rulesDir, f), "utf8");
      const obj = JSON.parse(txt);
      const rule = obj.rule ?? {};
      const reporting = obj.reporting ?? {};
      out.push({
        ruleId: rule.id ?? f.replace(/\.json$/, ""),
        internalName: rule.internal_name ?? null,
        severity: rule.severity ?? reporting.severity ?? null,
        category: rule.category ?? null,
        userSummary: reporting.user_summary ?? null,
        technicalSummary: reporting.technical_summary ?? null,
        fileName: f,
      });
    } catch {}
  }
  out.sort((a, b) => a.ruleId.localeCompare(b.ruleId));
  return out;
}

export function readRule(ruleId: string): { meta: RuleMeta; raw: any; rawText: string; filePath: string } | null {
  const all = listRules();
  const meta = all.find((r) => r.ruleId === ruleId);
  if (!meta) return null;
  const filePath = path.join(panelPaths.rulesDir, meta.fileName);
  const rawText = fs.readFileSync(filePath, "utf8");
  return { meta, raw: JSON.parse(rawText), rawText, filePath };
}

function ruleBin(): string {
  return resolveAuditorBin("evm-rule");
}

async function runRule(args: string[]): Promise<{ stdout: string; stderr: string; code: number | null }> {
  return await new Promise((resolve) => {
    const proc = spawn(ruleBin(), args, {
      cwd: panelPaths.repoRoot,
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    let err = "";
    proc.stdout?.on("data", (b) => (out += b.toString("utf8")));
    proc.stderr?.on("data", (b) => (err += b.toString("utf8")));
    proc.on("error", (e) => resolve({ stdout: out, stderr: (err + "\n" + e.message), code: 1 }));
    proc.on("exit", (code) => resolve({ stdout: out, stderr: err, code }));
  });
}

export async function explainRule(ruleId: string, auditJson: any): Promise<{ stdout: string; stderr: string; code: number | null }> {
  const rule = readRule(ruleId);
  if (!rule) throw new Error("unknown rule");
  const tmp = path.join(panelPaths.cacheDir, `explain-${Date.now()}.json`);
  fs.writeFileSync(tmp, JSON.stringify(auditJson));
  try {
    const result = await runRule(["explain", rule.filePath, tmp]);
    return result;
  } finally {
    try { fs.unlinkSync(tmp); } catch {}
  }
}

export async function testRule(ruleId: string): Promise<{ stdout: string; stderr: string; code: number | null; corpusDir: string | null }> {
  const rule = readRule(ruleId);
  if (!rule) throw new Error("unknown rule");
  const corpusDir = findCorpusDir(ruleId);
  if (!corpusDir) {
    return { stdout: "", stderr: "no matching corpus directory found for rule", code: 2, corpusDir: null };
  }
  const result = await runRule(["test", rule.filePath, corpusDir]);
  return { ...result, corpusDir };
}

export async function validateRule(ruleId: string): Promise<{ stdout: string; stderr: string; code: number | null }> {
  const rule = readRule(ruleId);
  if (!rule) throw new Error("unknown rule");
  return runRule(["validate", rule.filePath]);
}

export async function doctorRule(ruleId: string): Promise<{ stdout: string; stderr: string; code: number | null }> {
  const rule = readRule(ruleId);
  if (!rule) throw new Error("unknown rule");
  return runRule(["doctor", rule.filePath]);
}

function findCorpusDir(ruleId: string): string | null {
  if (!fs.existsSync(panelPaths.corpusDir)) return null;
  const dirs = fs.readdirSync(panelPaths.corpusDir, { withFileTypes: true }).filter((d) => d.isDirectory());
  const slug = ruleId.replace(/[.\-]/g, "_");
  for (const d of dirs) {
    if (d.name === ruleId || d.name === slug) return path.join(panelPaths.corpusDir, d.name);
    if (slug.includes(d.name) || d.name.includes(slug.split("_").slice(-2).join("_"))) {
      return path.join(panelPaths.corpusDir, d.name);
    }
  }
  // Match by rule.internal_name tail
  try {
    const meta = readRule(ruleId)?.meta;
    if (meta?.internalName) {
      const tail = meta.internalName.replace(/^reference_/, "").replace(/_v\d+$/, "");
      for (const d of dirs) if (d.name.includes(tail.split("_")[0])) return path.join(panelPaths.corpusDir, d.name);
    }
  } catch {}
  return null;
}
