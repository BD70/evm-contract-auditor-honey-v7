import fs from "node:fs";
import path from "node:path";
import { z } from "zod";
import { panelPaths } from "./paths";

export const SECRET_MASK = "***";
const BASE_HEALTH_PORT = Number(process.env.HEALTH_PORT ?? 9090);

const slugSchema = z
  .string()
  .regex(/^[a-z0-9][a-z0-9-]{0,40}$/, "slug must match ^[a-z0-9][a-z0-9-]{0,40}$");

export const chainEntrySchema = z.object({
  slug: slugSchema,
  name: z.string().min(1),
  enabled: z.boolean().default(true),
  rpcHttpUrl: z.string().regex(/^https?:\/\//, "rpcHttpUrl must start with http(s)://"),
  rpcWsUrl: z
    .string()
    .regex(/^wss?:\/\//, "rpcWsUrl must start with ws(s)://")
    .optional()
    .or(z.literal("")),
  startBlock: z.number().int().min(0).optional(),
  confirmations: z.number().int().min(0).optional(),
  webhookUrl: z.string().url().optional().or(z.literal("")),
  webhookAuthHeader: z.string().optional(),
  rulesPath: z.string().optional(),
});

export type ChainEntry = z.infer<typeof chainEntrySchema>;

const chainsDocSchema = z.object({
  version: z.literal(1),
  chains: z.array(chainEntrySchema),
});

function emptyDoc(): z.infer<typeof chainsDocSchema> {
  return { version: 1, chains: [] };
}

export function readChainsRaw(): ChainEntry[] {
  try {
    if (!fs.existsSync(panelPaths.chainsFile)) return [];
    const parsed = chainsDocSchema.parse(JSON.parse(fs.readFileSync(panelPaths.chainsFile, "utf8")));
    return parsed.chains;
  } catch {
    return [];
  }
}

function maskEntry(c: ChainEntry): ChainEntry {
  return c.webhookAuthHeader ? { ...c, webhookAuthHeader: SECRET_MASK } : c;
}

export function readChainsRedacted(): ChainEntry[] {
  return readChainsRaw().map(maskEntry);
}

/** Deterministic per-slug health port so polling stays stable across requests. */
export function chainHealthPort(slug: string): number {
  const idx = readChainsRaw().findIndex((c) => c.slug === slug);
  return BASE_HEALTH_PORT + 1 + (idx < 0 ? readChainsRaw().length : idx);
}

function writeChainsAtomic(chains: ChainEntry[]): void {
  const doc = { version: 1 as const, chains };
  chainsDocSchema.parse(doc);
  const tmp = panelPaths.chainsFile + ".tmp";
  fs.mkdirSync(path.dirname(panelPaths.chainsFile), { recursive: true });
  fs.writeFileSync(tmp, JSON.stringify(doc, null, 2) + "\n", { mode: 0o600 });
  fs.renameSync(tmp, panelPaths.chainsFile);
}

function normalize(input: unknown): ChainEntry {
  const c = chainEntrySchema.parse(input);
  // Drop empty-string optionals so they don't override env on the runner side.
  if (c.rpcWsUrl === "") delete c.rpcWsUrl;
  if (c.webhookUrl === "") delete c.webhookUrl;
  if (c.webhookAuthHeader === "") delete c.webhookAuthHeader;
  return c;
}

export function addChain(input: unknown): ChainEntry {
  const entry = normalize(input);
  const chains = readChainsRaw();
  if (chains.some((c) => c.slug === entry.slug)) {
    throw new Error(`chain slug already exists: ${entry.slug}`);
  }
  if (entry.webhookAuthHeader === SECRET_MASK) delete entry.webhookAuthHeader;
  writeChainsAtomic([...chains, entry]);
  return maskEntry(entry);
}

export function updateChain(slug: string, input: unknown): ChainEntry {
  const chains = readChainsRaw();
  const idx = chains.findIndex((c) => c.slug === slug);
  if (idx < 0) throw new Error(`unknown chain: ${slug}`);
  const incoming = normalize({ ...(input as Record<string, unknown>), slug });
  // Preserve existing secret when client submits the mask sentinel.
  if (incoming.webhookAuthHeader === SECRET_MASK) {
    incoming.webhookAuthHeader = chains[idx].webhookAuthHeader;
  }
  const next = [...chains];
  next[idx] = incoming;
  writeChainsAtomic(next);
  return maskEntry(incoming);
}

export function removeChain(slug: string): void {
  const chains = readChainsRaw();
  if (!chains.some((c) => c.slug === slug)) throw new Error(`unknown chain: ${slug}`);
  writeChainsAtomic(chains.filter((c) => c.slug !== slug));
}
