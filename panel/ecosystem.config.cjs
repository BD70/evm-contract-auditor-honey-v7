// PM2 ecosystem for the evm-auditor-panel.
//
// Two important invariants here:
//
// 1. Always source .env from the repo root on every (re)start so changes to
//    RESCUE_FLASHLOAN_RECEIVER, RESCUER_PRIVATE_KEY, etc. take effect with a
//    plain `pm2 restart --update-env`. Next.js's own .env loader does NOT
//    override variables already present in process.env, so without this the
//    first value PM2 captured on initial boot would stick forever.
//
// 2. Launch Next.js DIRECTLY (not via /bin/sh -> npx -> node -> next) so PM2
//    monitors the actual node process. Previously we wrapped the launcher in
//    `/bin/sh -c "ulimit -n 65536 && exec npx next start -p 3000"`. After the
//    `exec`, the shell is replaced by npx, which then forks node — PM2 was
//    watching the npx wrapper's RSS (~70 MB) not the next-server child's
//    (which routinely climbed past 5 GB before V8 OOM'd it; see error log
//    2026-05-18 with FATAL "Ineffective mark-compacts near heap limit"). With
//    the direct launch, `max_memory_restart` actually triggers and we get
//    clean PM2 restarts instead of hard V8 kills.
//
//    For the ulimit: macOS launchctl's default soft maxfiles is 256, which
//    EMFILE-crashes the panel. We expect the operator to start the PM2
//    daemon itself under a raised ulimit (see scripts/pm2-bootstrap.sh).
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

const nextBin = path.resolve(__dirname, "node_modules", "next", "dist", "bin", "next");
if (!fs.existsSync(nextBin)) {
  throw new Error(`next bin missing: ${nextBin} — run \`npm install\` in panel/ first`);
}

module.exports = {
  apps: [
    {
      name: "evm-auditor-panel",
      // We still wrap in /bin/sh because we need `ulimit -n 65536` on macOS
      // (default soft maxfiles is 256, which EMFILE-crashes Next + sqlite +
      // anvil sockets).
      //
      // The CRITICAL difference from v11: we exec `node next-bin` directly
      // instead of `npx next`. After the shell `exec`, the shell is replaced
      // by node and the next-server process keeps the original shell's PID
      // — which is exactly the PID PM2 monitors. The old `exec npx next`
      // path left npx as the monitored PID and the actual heavy next-server
      // ran as a CHILD of npx, so PM2's `max_memory_restart` never saw the
      // real RSS (next-server hit 5+ GB before V8 OOM'd; PM2 thought it
      // was using ~70 MB).
      script: "/bin/sh",
      args: ["-c", `ulimit -n 65536 && exec node "${nextBin}" start -p 3000`],
      cwd: __dirname,
      autorestart: true,
      max_restarts: 10,
      min_uptime: "30s",
      // PM2 watches the SCRIPT pid (= node here). Once heap approaches the
      // V8 ceiling, restart cleanly instead of letting V8 OOM hard-kill us.
      // Steady-state is 400-800 MB; transient spikes during rescue-prove
      // can reach 1.5-2 GB. We restart at 2.5 GB, well below
      // --max-old-space-size=3072 so PM2 wins the race against V8.
      max_memory_restart: "2500M",
      kill_timeout: 5000,
      env: {
        ...dotenv,
        NODE_ENV: "production",
        NODE_OPTIONS: "--max-old-space-size=3072 --expose-gc",
      },
    },
  ],
};
