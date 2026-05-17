import { spawn } from "node:child_process";

export interface ProcessRunnerPort {
  run(cmd: string, args: string[], timeoutMs: number, maxOutputBytes: number): Promise<{
    code: number | null;
    timedOut: boolean;
    outputLimitExceeded: boolean;
    stdout: string;
    stderr: string;
  }>;
}

export class NodeProcessRunner implements ProcessRunnerPort {
  async run(cmd: string, args: string[], timeoutMs: number, maxOutputBytes: number): Promise<{
    code: number | null;
    timedOut: boolean;
    outputLimitExceeded: boolean;
    stdout: string;
    stderr: string;
  }> {
    const child = spawn(cmd, args, {
      cwd: process.cwd(),
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let outputLimitExceeded = false;

    const captureChunk = (target: Buffer[], chunk: Buffer, kind: "stdout" | "stderr"): void => {
      if (outputLimitExceeded) {
        return;
      }
      const nextBytes = (kind === "stdout" ? stdoutBytes : stderrBytes) + chunk.length;
      if (kind === "stdout") {
        stdoutBytes = nextBytes;
      } else {
        stderrBytes = nextBytes;
      }
      if (stdoutBytes + stderrBytes > maxOutputBytes) {
        outputLimitExceeded = true;
        child.kill("SIGKILL");
        return;
      }
      target.push(Buffer.from(chunk));
    };

    child.stdout.on("data", (chunk) => captureChunk(stdoutChunks, Buffer.from(chunk), "stdout"));
    child.stderr.on("data", (chunk) => captureChunk(stderrChunks, Buffer.from(chunk), "stderr"));

    const result = await new Promise<{ code: number | null; timedOut: boolean }>((resolve) => {
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        resolve({ code: null, timedOut: true });
      }, timeoutMs);
      child.on("exit", (exitCode) => {
        clearTimeout(timer);
        resolve({ code: exitCode, timedOut: false });
      });
    });

    return {
      ...result,
      outputLimitExceeded,
      stdout: Buffer.concat(stdoutChunks).toString("utf8").trim(),
      stderr: Buffer.concat(stderrChunks).toString("utf8").trim(),
    };
  }
}
