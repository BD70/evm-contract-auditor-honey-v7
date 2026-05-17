import { createHash, randomBytes } from "node:crypto";
import { mkdir, readdir, readFile, rename, stat, unlink, writeFile } from "node:fs/promises";
import path from "node:path";

export function normalizeHex(value: string | undefined | null): string {
  if (!value) {
    return "0x";
  }
  const trimmed = value.trim().toLowerCase();
  return trimmed.startsWith("0x") ? trimmed : `0x${trimmed}`;
}

export function stripHexPrefix(value: string): string {
  return normalizeHex(value).slice(2);
}

export function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function eventId(parts: Array<string | number | undefined>): string {
  return sha256Hex(parts.filter((part) => part !== undefined).join(":"));
}

export function parseInteger(value: string | undefined, fallback: number): number {
  if (!value) {
    return fallback;
  }
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export function parseRequiredInteger(name: string, value: string): number {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) {
    throw new Error(`${name} must be an integer`);
  }
  return parsed;
}

export function parseLogLevel(value: string | undefined): "debug" | "info" | "warn" | "error" {
  const normalized = (value ?? "").toLowerCase();
  switch (normalized) {
    case "debug":
    case "info":
    case "warn":
    case "error":
      return normalized as "debug" | "info" | "warn" | "error";
    default:
      return "info";
  }
}

export async function ensureDir(dir: string): Promise<void> {
  await mkdir(dir, { recursive: true });
}

export async function readJsonFile<T>(filePath: string, fallback: T): Promise<T> {
  try {
    const content = await readFile(filePath, "utf8");
    return JSON.parse(content) as T;
  } catch {
    return fallback;
  }
}

export async function writeJsonFile(filePath: string, value: unknown): Promise<void> {
  await ensureDir(path.dirname(filePath));
  // High-entropy suffix so concurrent writers (which all use the same pid and
  // can land on the same Date.now() millisecond) never collide on the same
  // temp filename. Previous suffix `${pid}-${Date.now()}` caused parallel
  // state.save() calls to overwrite + rename out from under each other,
  // producing ENOENT on the second rename and crashing the runner.
  const tempPath = `${filePath}.tmp-${process.pid}-${Date.now()}-${randomBytes(6).toString("hex")}`;
  const payload = `${JSON.stringify(value, null, 2)}\n`;
  const attempt = async (): Promise<void> => {
    await writeFile(tempPath, payload, "utf8");
    await rename(tempPath, filePath);
  };
  try {
    await attempt();
  } catch (error) {
    const err = error as NodeJS.ErrnoException;
    // If the parent directory disappeared between writeFile and rename, recreate
    // and try once more before giving up.
    if (err?.code === "ENOENT") {
      try {
        await ensureDir(path.dirname(filePath));
        await attempt();
        return;
      } catch (retryError) {
        await unlink(tempPath).catch(() => undefined);
        throw retryError;
      }
    }
    await unlink(tempPath).catch(() => undefined);
    throw error;
  }
}

export function parseAddressFromStorage(storageValue: string): string | undefined {
  const raw = stripHexPrefix(storageValue);
  if (!raw || /^0+$/.test(raw)) {
    return undefined;
  }
  return `0x${raw.slice(-40)}`;
}

export function hexToNumber(value: string): number {
  return Number.parseInt(stripHexPrefix(value), 16);
}

export function nowIso(): string {
  return new Date().toISOString();
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function splitCommand(command: string): string[] {
  const matches = command.match(/(?:[^\s"]+|"[^"]*")+/g) ?? [];
  return matches.map((part) => part.replace(/^"(.*)"$/, "$1"));
}

export function compactJsonSize(value: unknown): number {
  return Buffer.byteLength(JSON.stringify(value), "utf8");
}

export function lowerCaseHeaderMap(input?: string): Record<string, string> {
  if (!input) {
    return {};
  }
  const idx = input.indexOf(":");
  if (idx === -1) {
    return { authorization: input };
  }
  const key = input.slice(0, idx).trim().toLowerCase();
  const value = input.slice(idx + 1).trim();
  return key ? { [key]: value } : {};
}

export async function hashPath(targetPath: string): Promise<string> {
  const fileStat = await stat(targetPath);
  if (fileStat.isFile()) {
    return sha256Hex(await readFile(targetPath, "utf8"));
  }
  const hash = createHash("sha256");
  const files = await walkFiles(targetPath);
  for (const filePath of files.sort()) {
    const relativePath = path.relative(targetPath, filePath);
    hash.update(relativePath);
    hash.update("\0");
    hash.update(await readFile(filePath));
    hash.update("\0");
  }
  return hash.digest("hex");
}

async function walkFiles(root: string): Promise<string[]> {
  const entries = await readdir(root, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const fullPath = path.join(root, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await walkFiles(fullPath)));
      continue;
    }
    if (entry.isFile()) {
      files.push(fullPath);
    }
  }
  return files;
}

export function clampPositiveInteger(name: string, value: number, minimum = 1): number {
  if (!Number.isFinite(value) || value < minimum) {
    throw new Error(`${name} must be >= ${minimum}`);
  }
  return Math.trunc(value);
}

export function requireNonNegativeInteger(name: string, value: number): number {
  if (!Number.isFinite(value) || value < 0) {
    throw new Error(`${name} must be >= 0`);
  }
  return Math.trunc(value);
}

export function isTransientHttpStatus(status: number): boolean {
  return status === 408 || status === 409 || status === 425 || status === 429 || status >= 500;
}

export function isTransientNetworkError(error: unknown): boolean {
  if (!(error instanceof Error)) {
    return false;
  }
  const message = error.message.toLowerCase();
  return (
    message.includes("network") ||
    message.includes("fetch") ||
    message.includes("timeout") ||
    message.includes("tempor") ||
    message.includes("socket") ||
    message.includes("econn") ||
    message.includes("etimedout")
  );
}

export async function retry<T>(
  fn: (attempt: number) => Promise<T>,
  options: {
    attempts: number;
    baseDelayMs: number;
    shouldRetry: (error: unknown, attempt: number) => boolean;
  },
): Promise<T> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= options.attempts; attempt += 1) {
    try {
      return await fn(attempt);
    } catch (error) {
      lastError = error;
      if (attempt >= options.attempts || !options.shouldRetry(error, attempt)) {
        throw error;
      }
      await sleep(options.baseDelayMs * attempt);
    }
  }
  throw lastError instanceof Error ? lastError : new Error("retry failed");
}
