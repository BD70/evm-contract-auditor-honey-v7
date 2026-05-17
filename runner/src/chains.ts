import { readFile } from "node:fs/promises";
import path from "node:path";

export interface ChainEntry {
  slug: string;
  name: string;
  enabled: boolean;
  rpcHttpUrl: string;
  rpcWsUrl?: string;
  startBlock?: number;
  confirmations?: number;
  webhookUrl?: string;
  webhookAuthHeader?: string;
  rulesPath?: string;
}

export const CHAIN_SLUG_PATTERN = /^[a-z0-9][a-z0-9-]{0,40}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireString(obj: Record<string, unknown>, key: string, slugCtx: string): string {
  const v = obj[key];
  if (typeof v !== "string" || v.trim() === "") {
    throw new Error(`invalid_chains_field:${slugCtx}.${key}`);
  }
  return v.trim();
}

function optionalString(obj: Record<string, unknown>, key: string, slugCtx: string): string | undefined {
  const v = obj[key];
  if (v === undefined || v === null || v === "") {
    return undefined;
  }
  if (typeof v !== "string") {
    throw new Error(`invalid_chains_field:${slugCtx}.${key}`);
  }
  return v.trim();
}

function optionalInt(obj: Record<string, unknown>, key: string, slugCtx: string): number | undefined {
  const v = obj[key];
  if (v === undefined || v === null || v === "") {
    return undefined;
  }
  if (typeof v !== "number" || !Number.isInteger(v) || v < 0) {
    throw new Error(`invalid_chains_field:${slugCtx}.${key}`);
  }
  return v;
}

export function parseChainsDocument(content: string): ChainEntry[] {
  let doc: unknown;
  try {
    doc = JSON.parse(content);
  } catch {
    throw new Error("invalid_chains_json");
  }
  if (!isRecord(doc)) {
    throw new Error("invalid_chains_shape");
  }
  if (doc.version !== 1) {
    throw new Error("invalid_chains_version");
  }
  if (!Array.isArray(doc.chains)) {
    throw new Error("invalid_chains_list");
  }
  const seen = new Set<string>();
  const entries: ChainEntry[] = [];
  for (const raw of doc.chains) {
    if (!isRecord(raw)) {
      throw new Error("invalid_chains_entry");
    }
    const slug = requireString(raw, "slug", "chain");
    if (!CHAIN_SLUG_PATTERN.test(slug)) {
      throw new Error(`invalid_chains_slug:${slug}`);
    }
    if (seen.has(slug)) {
      throw new Error(`duplicate_chains_slug:${slug}`);
    }
    seen.add(slug);
    const rpcHttpUrl = requireString(raw, "rpcHttpUrl", slug);
    if (!/^https?:\/\//.test(rpcHttpUrl)) {
      throw new Error(`invalid_chains_rpc:${slug}`);
    }
    const rpcWsUrl = optionalString(raw, "rpcWsUrl", slug);
    if (rpcWsUrl && !/^wss?:\/\//.test(rpcWsUrl)) {
      throw new Error(`invalid_chains_ws:${slug}`);
    }
    entries.push({
      slug,
      name: requireString(raw, "name", slug),
      enabled: raw.enabled === undefined ? true : raw.enabled === true,
      rpcHttpUrl,
      rpcWsUrl,
      startBlock: optionalInt(raw, "startBlock", slug),
      confirmations: optionalInt(raw, "confirmations", slug),
      webhookUrl: optionalString(raw, "webhookUrl", slug),
      webhookAuthHeader: optionalString(raw, "webhookAuthHeader", slug),
      rulesPath: optionalString(raw, "rulesPath", slug),
    });
  }
  return entries;
}

export function chainsFilePath(repoRoot: string): string {
  return path.join(repoRoot, "chains.json");
}

export async function loadChainsFile(repoRoot: string): Promise<ChainEntry[] | null> {
  let content: string;
  try {
    content = await readFile(chainsFilePath(repoRoot), "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException | undefined)?.code === "ENOENT") {
      return null;
    }
    throw error;
  }
  return parseChainsDocument(content);
}

export function selectChain(entries: ChainEntry[], slug: string): ChainEntry {
  const match = entries.find((c) => c.slug === slug);
  if (!match) {
    throw new Error(`unknown_chain_slug:${slug}`);
  }
  return match;
}
