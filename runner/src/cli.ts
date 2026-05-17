#!/usr/bin/env bun
import { CHAIN_SLUG_PATTERN } from "./chains.js";
import { loadConfig } from "./config.js";
import { runRunner } from "./runner.js";
import type { CliOptions } from "./types.js";
import { parseRequiredInteger } from "./utils.js";

export function parseCli(argv: string[]): CliOptions {
  const options: CliOptions = {
    once: false,
    maxReplayRangeBlocks: 10_000,
    dryRunWebhook: false,
    noWebhook: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case "--env-file":
      case "--config": {
        const value = argv[++i];
        if (!value) {
          throw new Error(`${arg} requires a value`);
        }
        options.envFile = value;
        break;
      }
      case "--start-block": {
        const value = argv[++i];
        if (!value) {
          throw new Error("--start-block requires a value");
        }
        options.startBlock = parseRequiredInteger("--start-block", value);
        break;
      }
      case "--once":
        options.once = true;
        break;
      case "--replay-block": {
        const value = argv[++i];
        if (!value) {
          throw new Error("--replay-block requires a value");
        }
        options.replayBlock = parseRequiredInteger("--replay-block", value);
        break;
      }
      case "--replay-range": {
        const value = argv[++i];
        if (!value) {
          throw new Error("--replay-range requires a value");
        }
        const [fromRaw, toRaw] = value.split(":");
        if (!fromRaw || !toRaw) {
          throw new Error("--replay-range must be <from>:<to>");
        }
        const from = parseRequiredInteger("--replay-range.from", fromRaw);
        const to = parseRequiredInteger("--replay-range.to", toRaw);
        if (to < from) {
          throw new Error("--replay-range to must be >= from");
        }
        if (to - from + 1 > (options.maxReplayRangeBlocks ?? 10_000)) {
          throw new Error(`--replay-range exceeds max span of ${options.maxReplayRangeBlocks ?? 10_000} blocks`);
        }
        options.replayRange = { from, to };
        break;
      }
      case "--dry-run-webhook":
        options.dryRunWebhook = true;
        break;
      case "--no-webhook":
        options.noWebhook = true;
        break;
      case "--rules": {
        const value = argv[++i];
        if (!value) {
          throw new Error("--rules requires a value");
        }
        options.rulesPath = value;
        break;
      }
      case "--chain": {
        const value = argv[++i];
        if (!value) {
          throw new Error("--chain requires a value");
        }
        options.chain = value;
        break;
      }
      default:
        throw new Error(`unknown flag: ${arg}`);
    }
  }

  validateCliOptions(options);
  return options;
}

export function validateCliOptions(options: CliOptions): void {
  if (options.startBlock !== undefined && options.startBlock < 0) {
    throw new Error("--start-block must be >= 0");
  }
  if (options.replayBlock !== undefined && options.replayBlock < 0) {
    throw new Error("--replay-block must be >= 0");
  }
  if (options.replayRange && (options.replayRange.from < 0 || options.replayRange.to < 0)) {
    throw new Error("--replay-range values must be >= 0");
  }
  if (options.replayBlock !== undefined && options.replayRange) {
    throw new Error("--replay-block and --replay-range are mutually exclusive");
  }
  if (options.chain !== undefined && !CHAIN_SLUG_PATTERN.test(options.chain)) {
    throw new Error("--chain must match ^[a-z0-9][a-z0-9-]{0,40}$");
  }
}

export async function main(): Promise<void> {
  const options = parseCli(process.argv.slice(2));
  const config = await loadConfig(process.cwd(), options);
  await runRunner(config, options);
}

if (import.meta.main) {
  await main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  });
}
