// PM2 ecosystem for the evm-auditor-panel.
//
// Why this exists: macOS launchctl's default soft `maxfiles` is 256, and pm2
// inherits whatever ulimit it was started with. Next.js + chokidar + sqlite +
// the anvil child sockets routinely push past 256 file descriptors and trigger
// `EMFILE: too many open files, watch`, which crashes the process in a tight
// restart loop.
//
// We wrap the launcher in `/bin/sh -c "ulimit -n 65536 && ..."` so the panel
// always boots with a generous FD ceiling regardless of how pm2 itself was
// launched. 65536 is well under the macOS hard limit (kern.maxfilesperproc =
// 184320 on this host) but multiple orders of magnitude above what we'd ever
// realistically need.

// Always source .env from the repo root on every (re)start so changes to
// RESCUE_FLASHLOAN_RECEIVER, RESCUER_PRIVATE_KEY, etc. take effect with a
// plain `pm2 restart --update-env`. Next.js's own .env loader does NOT
// override variables already present in process.env, so without this the
// first value PM2 captured on initial boot would stick forever.
const path = require("node:path");
const fs = require("node:fs");
function loadDotenv(file) {
  const out = {};
  if (!fs.existsSync(file)) return out;
  for (const raw of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq < 1) continue;
    const k = line.slice(0, eq).trim();
    let v = line.slice(eq + 1).trim();
    if (
      (v.startsWith('"') && v.endsWith('"')) ||
      (v.startsWith("'") && v.endsWith("'"))
    ) {
      v = v.slice(1, -1);
    }
    out[k] = v;
  }
  return out;
}
const dotenv = loadDotenv(path.resolve(__dirname, "..", ".env"));

module.exports = {
  apps: [
    {
      name: "evm-auditor-panel",
      script: "/bin/sh",
      args: ["-c", "ulimit -n 65536 && exec npx next start -p 3000"],
      cwd: __dirname,
      autorestart: true,
      max_restarts: 10,
      min_uptime: "30s",
      // Heap ceiling raised from 1500M → 4500M and matching NODE_OPTIONS bumped
      // from 2048 to 5120 MB. Empirically the panel's working set sits around
      // 2.0–2.2 GB when servicing 14 chain runners + the sim worker + ingest
      // reconciliation; the previous 2 GB Node heap was getting exhausted
      // mid-GC (see Mark-Compact trace in evm-auditor-panel-error.log) and
      // pm2 restarted us every ~15 min. Restart-on-memory is still in place
      // as a safety net but now at a level that won't trigger during normal
      // multi-chain operation. macOS hosts here have ≥16 GB of RAM so 5 GB
      // ceiling is well within physical bounds.
      max_memory_restart: "4500M",
      kill_timeout: 5000,
      env: {
        ...dotenv,
        NODE_ENV: "production",
        NODE_OPTIONS: "--max-old-space-size=5120",
      },
    },
  ],
};
