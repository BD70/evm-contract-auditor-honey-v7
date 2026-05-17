import { nowIso } from "./utils.js";

const LEVELS: Record<"debug" | "info" | "warn" | "error", number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

type LogLevel = "debug" | "info" | "warn" | "error";
type UiMode = "auto" | "tui" | "plain" | "json";

interface DashboardState {
  chainId?: number;
  confirmations?: number;
  rulesPath?: string;
  rulesFingerprint?: string;
  startBlock?: number;
  lastBlock?: number;
  txCount?: number;
  topLevelCreateTxCount?: number;
  internalCreateCount?: number;
  deploymentCount?: number;
  traceMode?: string;
  traceAvailable?: boolean;
  recentEvents: Array<{
    ts: string;
    level: LogLevel;
    message: string;
    txHash?: string;
    contractAddress?: string;
    blockNumber?: number;
    targetKind?: unknown;
    detectionSource?: unknown;
    failureReason?: unknown;
  }>;
}

export class Logger {
  private readonly uiMode: UiMode;
  private readonly dashboardEnabled: boolean;
  private readonly dashboard: DashboardState = { recentEvents: [] };
  private cursorHidden = false;

  constructor(private readonly level: LogLevel, uiMode: UiMode = "auto") {
    this.uiMode = uiMode;
    this.dashboardEnabled =
      uiMode === "tui" || (uiMode === "auto" && Boolean(process.stdout.isTTY) && process.env.TERM !== "dumb" && !process.env.CI);
  }

  debug(message: string, fields: Record<string, unknown> = {}): void {
    this.emit("debug", message, fields);
  }

  info(message: string, fields: Record<string, unknown> = {}): void {
    this.emit("info", message, fields);
  }

  warn(message: string, fields: Record<string, unknown> = {}): void {
    this.emit("warn", message, fields);
  }

  error(message: string, fields: Record<string, unknown> = {}): void {
    this.emit("error", message, fields);
  }

  close(): void {
    if (this.dashboardEnabled && this.cursorHidden) {
      process.stdout.write("\x1b[?25h\n");
      this.cursorHidden = false;
    }
  }

  private emit(level: LogLevel, message: string, fields: Record<string, unknown>): void {
    if (LEVELS[level] < LEVELS[this.level]) {
      return;
    }
    const payload = {
      ts: nowIso(),
      level,
      message,
      ...fields,
    };
    if (this.dashboardEnabled && this.uiMode !== "json") {
      this.updateDashboard(payload);
      this.renderDashboard();
      return;
    }
    process.stdout.write(`${JSON.stringify(payload)}\n`);
  }

  private updateDashboard(payload: Record<string, unknown> & { ts: string; level: LogLevel; message: string }): void {
    if (payload.message === "runner_started") {
      this.dashboard.chainId = asNumber(payload.chainId);
      this.dashboard.confirmations = asNumber(payload.confirmations);
      this.dashboard.rulesPath = asString(payload.rulesPath);
      this.dashboard.rulesFingerprint = asString(payload.rulesFingerprint);
      this.dashboard.startBlock = asNumber(payload.startBlock);
    }
    if (payload.message === "block_scanned") {
      this.dashboard.lastBlock = asNumber(payload.blockNumber);
      this.dashboard.txCount = asNumber(payload.txCount);
      this.dashboard.topLevelCreateTxCount = asNumber(payload.topLevelCreateTxCount);
      this.dashboard.internalCreateCount = asNumber(payload.internalCreateCount);
      this.dashboard.deploymentCount = asNumber(payload.deploymentCount);
      this.dashboard.traceMode = asString(payload.traceMode);
      this.dashboard.traceAvailable = asBoolean(payload.traceAvailable);
    }

    this.dashboard.recentEvents.unshift({
      ts: payload.ts,
      level: payload.level,
      message: payload.message,
      txHash: asString(payload.txHash),
      contractAddress: asString(payload.contractAddress),
      blockNumber: asNumber(payload.blockNumber),
      targetKind: payload.targetKind,
      detectionSource: payload.detectionSource,
      failureReason: payload.failureReason,
    });
    this.dashboard.recentEvents = this.dashboard.recentEvents.slice(0, 8);
  }

  private renderDashboard(): void {
    if (!this.cursorHidden) {
      process.stdout.write("\x1b[?25l");
      this.cursorHidden = true;
    }
    const lines: string[] = [];
    lines.push("EVM Audit Runner");
    lines.push(
      `chain=${this.dashboard.chainId ?? "-"} start=${this.dashboard.startBlock ?? "-"} conf=${this.dashboard.confirmations ?? "-"}`,
    );
    lines.push(
      `block=${this.dashboard.lastBlock ?? "-"} txs=${this.dashboard.txCount ?? 0} top_level=${this.dashboard.topLevelCreateTxCount ?? 0} internal=${this.dashboard.internalCreateCount ?? 0} deployments=${this.dashboard.deploymentCount ?? 0}`,
    );
    lines.push(
      `trace=${this.dashboard.traceMode ?? "-"} available=${String(this.dashboard.traceAvailable ?? false)} rules=${this.dashboard.rulesPath ?? "-"}`,
    );
    lines.push(`fingerprint=${truncate(this.dashboard.rulesFingerprint ?? "-", 24)}`);
    lines.push("");
    lines.push("Recent");
    for (const event of this.dashboard.recentEvents) {
      lines.push(
        [
          event.ts.slice(11, 19),
          event.level.toUpperCase(),
          event.message,
          event.blockNumber !== undefined ? `b=${event.blockNumber}` : "",
          event.txHash ? `tx=${truncate(event.txHash, 12)}` : "",
          event.contractAddress ? `addr=${truncate(event.contractAddress, 14)}` : "",
          event.detectionSource ? `src=${String(event.detectionSource)}` : "",
          event.failureReason ? `reason=${String(event.failureReason)}` : "",
        ]
          .filter(Boolean)
          .join(" "),
      );
    }
    process.stdout.write(`\x1b[H\x1b[J${lines.join("\n")}`);
  }
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function asNumber(value: unknown): number | undefined {
  return typeof value === "number" ? value : undefined;
}

function asBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function truncate(value: string, length: number): string {
  return value.length <= length ? value : `${value.slice(0, length - 1)}…`;
}
