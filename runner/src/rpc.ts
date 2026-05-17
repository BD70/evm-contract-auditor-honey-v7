import type { RpcBlock, RpcReceipt, TraceCreateDeployment } from "./types.js";
import { hexToNumber, isTransientNetworkError, normalizeHex, retry, sleep } from "./utils.js";

interface JsonRpcPayload {
  jsonrpc: "2.0";
  id: number;
  method: string;
  params: unknown[];
}

export class JsonRpcClient {
  private id = 1;

  constructor(
    private readonly httpUrl: string,
    private readonly wsUrl?: string,
    private readonly pollIntervalMs = 3_000,
    private readonly maxAttempts = 3,
    private readonly retryBaseDelayMs = 250,
  ) {}

  async getChainId(): Promise<number> {
    return hexToNumber(await this.request<string>("eth_chainId", []));
  }

  async getLatestBlockNumber(): Promise<number> {
    return hexToNumber(await this.request<string>("eth_blockNumber", []));
  }

  async getBlockByNumber(blockNumber: number, includeTransactions = true): Promise<RpcBlock> {
    const block = await this.request<RpcBlock | null>("eth_getBlockByNumber", [toHex(blockNumber), includeTransactions]);
    if (!block) {
      throw new Error(`block ${blockNumber} not found`);
    }
    return block;
  }

  async getTransactionReceipt(txHash: string): Promise<RpcReceipt | null> {
    return this.request<RpcReceipt | null>("eth_getTransactionReceipt", [txHash]);
  }

  async getTransactionByHash(txHash: string) {
    return this.request<{ hash: string; from: string; to: string | null; input?: string; data?: string } | null>(
      "eth_getTransactionByHash",
      [txHash],
    );
  }

  async getCode(address: string, blockNumber: number): Promise<string> {
    return normalizeHex(await this.request<string>("eth_getCode", [address, toHex(blockNumber)]));
  }

  async getStorageAt(address: string, slot: string, blockNumber: number): Promise<string> {
    return normalizeHex(await this.request<string>("eth_getStorageAt", [address, slot, toHex(blockNumber)]));
  }

  async ethCall(to: string, data: string, blockNumber: number): Promise<string> {
    return normalizeHex(await this.request<string>("eth_call", [{ to, data }, toHex(blockNumber)]));
  }

  async getInternalDeployments(blockNumber: number): Promise<{
    deployments: TraceCreateDeployment[];
    mode: "debug_traceBlockByNumber" | "trace_block";
  } | null> {
    const blockTag = toHex(blockNumber);
    try {
      const traces = await this.request<unknown[]>("debug_traceBlockByNumber", [blockTag, { tracer: "callTracer" }]);
      return {
        deployments: extractCreateDeploymentsFromDebugTraceArray(traces),
        mode: "debug_traceBlockByNumber",
      };
    } catch {
      try {
        const traces = await this.request<unknown[]>("trace_block", [blockTag]);
        return {
          deployments: extractCreateDeploymentsFromParityTrace(traces),
          mode: "trace_block",
        };
      } catch {
        return null;
      }
    }
  }

  async waitForNextLatestBlock(previousLatest: number): Promise<number> {
    if (this.wsUrl) {
      try {
        return await this.waitForNextLatestBlockWs(previousLatest);
      } catch {
        return this.waitForNextLatestBlockPoll(previousLatest);
      }
    }
    return this.waitForNextLatestBlockPoll(previousLatest);
  }

  private async waitForNextLatestBlockPoll(previousLatest: number): Promise<number> {
    for (;;) {
      const latest = await this.getLatestBlockNumber();
      if (latest > previousLatest) {
        return latest;
      }
      await sleep(this.pollIntervalMs);
    }
  }

  private waitForNextLatestBlockWs(previousLatest: number): Promise<number> {
    return new Promise((resolve, reject) => {
      const socket = new WebSocket(this.wsUrl!);
      let subscriptionId = "";
      let settled = false;
      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          socket.close();
          reject(new Error("websocket wait timeout"));
        }
      }, Math.max(this.pollIntervalMs * 4, 10_000));

      socket.addEventListener("open", () => {
        socket.send(
          JSON.stringify({
            jsonrpc: "2.0",
            id: 1,
            method: "eth_subscribe",
            params: ["newHeads"],
          }),
        );
      });

      socket.addEventListener("message", (event) => {
        const message = JSON.parse(String(event.data)) as Record<string, unknown>;
        if (typeof message.result === "string" && !subscriptionId) {
          subscriptionId = message.result;
          return;
        }
        const params = message.params as { subscription?: string; result?: { number?: string } } | undefined;
        if (!params || params.subscription !== subscriptionId) {
          return;
        }
        const blockHex = params.result?.number;
        if (!blockHex) {
          return;
        }
        const latest = hexToNumber(blockHex);
        if (latest > previousLatest && !settled) {
          settled = true;
          clearTimeout(timer);
          socket.close();
          resolve(latest);
        }
      });

      socket.addEventListener("error", () => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          socket.close();
          reject(new Error("websocket error"));
        }
      });
    });
  }

  private async request<T>(method: string, params: unknown[]): Promise<T> {
    return retry(
      async () => {
        const payload: JsonRpcPayload = {
          jsonrpc: "2.0",
          id: this.id++,
          method,
          params,
        };
        const response = await fetch(this.httpUrl, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(payload),
        });
        if (!response.ok) {
          throw new Error(`rpc ${method} http ${response.status}`);
        }
        const json = (await response.json()) as { error?: { message?: string }; result?: T };
        if (json.error) {
          throw new Error(`rpc ${method} failed: ${json.error.message ?? "unknown error"}`);
        }
        return json.result as T;
      },
      {
        attempts: this.maxAttempts,
        baseDelayMs: this.retryBaseDelayMs,
        shouldRetry: (error) => isTransientNetworkError(error),
      },
    );
  }
}

function toHex(value: number): string {
  return `0x${value.toString(16)}`;
}

function extractCreateDeploymentsFromDebugTraceArray(value: unknown[]): TraceCreateDeployment[] {
  const deployments: TraceCreateDeployment[] = [];
  for (const entry of value) {
    const root = asRecord(entry);
    const txHash = asString(root?.txHash) ?? asString(root?.transactionHash);
    const callRoot = asRecord(root?.result) ?? root;
    if (!callRoot || !txHash) {
      continue;
    }
    walkDebugTraceFrame(callRoot, txHash, deployments);
  }
  return deployments;
}

function walkDebugTraceFrame(frame: Record<string, unknown>, txHash: string, out: TraceCreateDeployment[]): void {
  const type = asString(frame.type)?.toUpperCase();
  if ((type === "CREATE" || type === "CREATE2") && asString(frame.to)) {
    out.push({
      txHash,
      from: asString(frame.from) ?? "0x",
      to: undefined,
      createdAddress: asString(frame.to)!,
      initCode: normalizeHex(asString(frame.input) ?? ""),
      kind: type === "CREATE2" ? "create2" : "create",
    });
  }
  const calls = Array.isArray(frame.calls) ? frame.calls : [];
  for (const child of calls) {
    const childFrame = asRecord(child);
    if (childFrame) {
      walkDebugTraceFrame(childFrame, txHash, out);
    }
  }
}

function extractCreateDeploymentsFromParityTrace(value: unknown[]): TraceCreateDeployment[] {
  const deployments: TraceCreateDeployment[] = [];
  for (const entry of value) {
    const trace = asRecord(entry);
    if (!trace) {
      continue;
    }
    const type = asString(trace.type)?.toLowerCase();
    if (type !== "create" && type !== "create2") {
      continue;
    }
    const action = asRecord(trace.action);
    const result = asRecord(trace.result);
    const address = asString(result?.address);
    const txHash = asString(trace.transactionHash);
    if (!action || !address || !txHash) {
      continue;
    }
    deployments.push({
      txHash,
      from: asString(action.from) ?? "0x",
      to: asString(action.to) ?? null,
      createdAddress: address,
      initCode: normalizeHex(asString(action.init) ?? ""),
      kind: type === "create2" ? "create2" : "create",
    });
  }
  return deployments;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : null;
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}
