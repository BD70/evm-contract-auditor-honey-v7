
import path from "node:path";
import fs from "node:fs";

function detectRepoRoot(): string {
  if (process.env.REPO_ROOT) return path.resolve(process.env.REPO_ROOT);
  // panel/ lives inside the repo
  const candidate = path.resolve(process.cwd(), "..");
  // Sanity check: parent should contain runner/ or rules/
  if (fs.existsSync(path.join(candidate, "runner")) || fs.existsSync(path.join(candidate, "rules"))) {
    return candidate;
  }
  return candidate;
}

function detectStateDir(repoRoot: string): string {
  if (process.env.STATE_DIR_OVERRIDE) return path.resolve(process.env.STATE_DIR_OVERRIDE);
  // Try to read from runner .env
  try {
    const envPath = process.env.RUNNER_ENV_FILE ?? path.join(repoRoot, ".env");
    if (fs.existsSync(envPath)) {
      const txt = fs.readFileSync(envPath, "utf8");
      const m = txt.match(/^STATE_DIR\s*=\s*(.+)$/m);
      if (m) {
        const raw = m[1].trim().replace(/^["']|["']$/g, "");
        return path.resolve(repoRoot, raw);
      }
    }
  } catch {}
  return path.join(repoRoot, "runner-state");
}

const repoRoot = detectRepoRoot();
const panelRoot = process.cwd();
const stateDir = detectStateDir(repoRoot);
const rulesDir = path.join(repoRoot, "rules", "core");
const corpusDir = path.join(repoRoot, "corpus");
const runnerEnvFile = process.env.RUNNER_ENV_FILE ?? path.join(repoRoot, ".env");

export const panelPaths = {
  repoRoot,
  panelRoot,
  stateDir,
  artifactsDir: path.join(stateDir, "artifacts"),
  checkpointFile: path.join(stateDir, "checkpoint.json"),
  rulesDir,
  corpusDir,
  runnerEntry: path.join(repoRoot, "runner", "src", "cli.ts"),
  runnerEnvFile,
  chainsFile: path.join(repoRoot, "chains.json"),
  uploadsDir: path.join(panelRoot, "data", "uploads"),
  cacheDir: path.join(panelRoot, "data", "cache"),
};

export function ensurePanelDirs() {
  fs.mkdirSync(panelPaths.uploadsDir, { recursive: true });
  fs.mkdirSync(panelPaths.cacheDir, { recursive: true });
}
