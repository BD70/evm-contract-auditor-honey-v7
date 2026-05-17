
import fs from "node:fs";
import path from "node:path";
import { panelPaths } from "./paths";
import { ENV_FIELDS, ENV_FIELD_BY_KEY, envPatchSchema, type EnvPatch } from "./env-schema";

const SECRET_MASK = "***";

interface ParsedEnv {
  pairs: { key: string; value: string }[];
  raw: string;
}

function parseEnvFile(content: string): ParsedEnv {
  const pairs: { key: string; value: string }[] = [];
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    pairs.push({ key, value });
  }
  return { pairs, raw: content };
}

function serializeEnvFile(pairs: { key: string; value: string }[]): string {
  return (
    pairs
      .map(({ key, value }) => {
        const needsQuotes = /[\s#"']/.test(value);
        const v = needsQuotes ? `"${value.replace(/"/g, '\\"')}"` : value;
        return `${key}=${v}`;
      })
      .join("\n") + "\n"
  );
}

export function readEnvAll(): Record<string, string> {
  try {
    if (!fs.existsSync(panelPaths.runnerEnvFile)) return {};
    const txt = fs.readFileSync(panelPaths.runnerEnvFile, "utf8");
    const { pairs } = parseEnvFile(txt);
    return Object.fromEntries(pairs.map((p) => [p.key, p.value]));
  } catch {
    return {};
  }
}

export function readEnvRedacted(): Record<string, string> {
  const all = readEnvAll();
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(all)) {
    const field = ENV_FIELD_BY_KEY[k];
    if (field?.secret && v) out[k] = SECRET_MASK;
    else out[k] = v;
  }
  return out;
}

export interface DiffEntry {
  key: string;
  before: string | null;
  after: string | null;
  secret: boolean;
}

export function diffEnv(patch: EnvPatch, current: Record<string, string>): DiffEntry[] {
  const diffs: DiffEntry[] = [];
  for (const [k, v] of Object.entries(patch)) {
    const field = ENV_FIELD_BY_KEY[k];
    const incoming = v == null || v === "" ? null : String(v);
    const existing = current[k] ?? null;
    // Secrets sent as mask mean "unchanged"
    if (field?.secret && incoming === SECRET_MASK) continue;
    if (incoming === existing) continue;
    diffs.push({
      key: k,
      before: existing,
      after: incoming,
      secret: Boolean(field?.secret),
    });
  }
  return diffs;
}

export interface ApplyResult {
  applied: DiffEntry[];
  path: string;
}

export function applyPatchAtomic(rawPatch: unknown): ApplyResult {
  const patch = envPatchSchema.parse(rawPatch);
  const current = readEnvAll();
  const diffs = diffEnv(patch, current);

  const newMap: Record<string, string> = { ...current };
  for (const d of diffs) {
    if (d.after == null) delete newMap[d.key];
    else newMap[d.key] = d.after;
  }

  // Preserve original ordering for known keys; append new ones at the end
  const existingPairs = (() => {
    try {
      const txt = fs.readFileSync(panelPaths.runnerEnvFile, "utf8");
      return parseEnvFile(txt).pairs;
    } catch {
      return [];
    }
  })();

  const seen = new Set<string>();
  const merged: { key: string; value: string }[] = [];
  for (const { key } of existingPairs) {
    if (seen.has(key)) continue;
    if (newMap[key] !== undefined) {
      merged.push({ key, value: newMap[key] });
      seen.add(key);
    }
  }
  for (const key of Object.keys(newMap)) {
    if (seen.has(key)) continue;
    merged.push({ key, value: newMap[key] });
    seen.add(key);
  }

  const tmpPath = panelPaths.runnerEnvFile + ".tmp";
  fs.mkdirSync(path.dirname(panelPaths.runnerEnvFile), { recursive: true });
  fs.writeFileSync(tmpPath, serializeEnvFile(merged), { mode: 0o600 });
  fs.renameSync(tmpPath, panelPaths.runnerEnvFile);

  return { applied: diffs, path: panelPaths.runnerEnvFile };
}

export function previewPatch(rawPatch: unknown): DiffEntry[] {
  const patch = envPatchSchema.parse(rawPatch);
  return diffEnv(patch, readEnvAll());
}

export const envFieldsMeta = ENV_FIELDS;
