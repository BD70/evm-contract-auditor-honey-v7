// Side-effect module: load the runner's .env file at the repo root into
// `process.env`, but only for keys that aren't already set. This is the
// counterpart to Next.js's automatic .env loading from `panel/.env`, which
// covers panel-specific secrets but not the runner-wide config (ANVIL_BIN,
// AUDITOR_BIN, SIM_*, GOMEMLIMIT, …).
//
// IMPORTANT: this file is imported as a side effect at the very top of
// `panel/src/server/boot.ts`, before any other server module loads. Modules
// like `sim/worker` and `sim/anvil-pool` read process.env at module-load
// time (module-level constants) so the loader must run first.
//
// We intentionally do NOT overwrite values that are already in process.env
// so explicit shell exports / PM2 `--update-env` passes still win.

import fs from "node:fs";
import path from "node:path";

type Globals = { __panelEnvBootstrapped?: boolean };
const g = globalThis as unknown as Globals;

function repoRootGuess(): string {
  if (process.env.REPO_ROOT) return path.resolve(process.env.REPO_ROOT);
  return path.resolve(process.cwd(), "..");
}

function loadEnvFile(filePath: string) {
  if (!fs.existsSync(filePath)) return;
  let txt: string;
  try {
    txt = fs.readFileSync(filePath, "utf8");
  } catch {
    return;
  }
  for (const rawLine of txt.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
    if (process.env[key] != null && process.env[key] !== "") continue;
    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    process.env[key] = value;
  }
}

if (!g.__panelEnvBootstrapped) {
  g.__panelEnvBootstrapped = true;
  const root = repoRootGuess();
  // RUNNER_ENV_FILE override wins when set explicitly.
  loadEnvFile(process.env.RUNNER_ENV_FILE ?? path.join(root, ".env"));
}
