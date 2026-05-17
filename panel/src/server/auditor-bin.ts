
import path from "node:path";
import fs from "node:fs";
import { panelPaths } from "./paths";
import { readEnvAll } from "./env-store";

type Tool = "evm-audit" | "evm-rule" | "evm-check" | "evm-decon" | "evm-diff";

const ENV_OVERRIDE: Partial<Record<Tool, keyof ReturnType<typeof readEnvAll>>> = {
  "evm-audit": "AUDITOR_BIN",
  "evm-rule": "RULE_BIN",
};

function nodeArchToGoArch(arch: string): string {
  return arch === "x64" ? "amd64" : arch;
}

function platformSuffix(): string {
  return `${process.platform}-${nodeArchToGoArch(process.arch)}`;
}

function prebuiltPath(tool: Tool): string | null {
  const name = `${tool}-${platformSuffix()}`;
  const candidate = path.join(panelPaths.repoRoot, "bin", name);
  try {
    fs.accessSync(candidate, fs.constants.X_OK);
    return candidate;
  } catch {
    return null;
  }
}

/**
 * Resolve the executable path for a Go auditor tool.
 * Priority:
 *   1. Env override (AUDITOR_BIN / RULE_BIN from .env or process.env)
 *   2. Pre-built platform binary at <repoRoot>/bin/<tool>-<os>-<arch>
 *   3. Tool name (PATH lookup — requires Go toolchain installed)
 */
export function resolveAuditorBin(tool: Tool): string {
  const envKey = ENV_OVERRIDE[tool];
  if (envKey) {
    const envBin = readEnvAll()[envKey] ?? process.env[envKey];
    if (envBin) return envBin as string;
  }

  const prebuilt = prebuiltPath(tool);
  if (prebuilt) return prebuilt;

  return tool;
}

export function auditorBinInfo(): { tool: Tool; resolved: string; source: "env" | "prebuilt" | "path" }[] {
  const tools: Tool[] = ["evm-audit", "evm-rule", "evm-check", "evm-decon", "evm-diff"];
  return tools.map((tool) => {
    const envKey = ENV_OVERRIDE[tool];
    if (envKey && (readEnvAll()[envKey] ?? process.env[envKey])) {
      return { tool, resolved: resolveAuditorBin(tool), source: "env" };
    }
    if (prebuiltPath(tool)) {
      return { tool, resolved: resolveAuditorBin(tool), source: "prebuilt" };
    }
    return { tool, resolved: tool, source: "path" };
  });
}
