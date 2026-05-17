import path from "node:path";
import { open, readFile, rm } from "node:fs/promises";

type LeaseRecord = {
  pid: number;
  acquiredAt: string;
};

export class StateDirectoryLease {
  private readonly lockPath: string;
  private constructor(lockPath: string) {
    this.lockPath = lockPath;
  }

  static async acquire(stateDir: string): Promise<StateDirectoryLease> {
    const lockPath = path.join(stateDir, ".runner.lock");
    const payload: LeaseRecord = {
      pid: process.pid,
      acquiredAt: new Date().toISOString(),
    };

    const attempt = async () => {
      const handle = await open(lockPath, "wx");
      try {
        await handle.writeFile(`${JSON.stringify(payload, null, 2)}\n`, "utf8");
      } finally {
        await handle.close();
      }
      return new StateDirectoryLease(lockPath);
    };

    try {
      return await attempt();
    } catch (error) {
      const err = error as NodeJS.ErrnoException;
      if (err.code !== "EEXIST") {
        throw error;
      }

      const owner = await readLockOwner(lockPath);
      if (owner && !isProcessRunning(owner.pid)) {
        await rm(lockPath, { force: true });
        return await attempt();
      }

      const ownerSummary = owner ? ` (pid=${owner.pid}, acquiredAt=${owner.acquiredAt})` : "";
      throw new Error(`state directory is already in use: ${lockPath}${ownerSummary}`);
    }
  }

  async release(): Promise<void> {
    await rm(this.lockPath, { force: true });
  }
}

async function readLockOwner(lockPath: string): Promise<LeaseRecord | null> {
  try {
    const content = await readFile(lockPath, "utf8");
    const parsed = JSON.parse(content) as Partial<LeaseRecord>;
    if (typeof parsed.pid !== "number" || typeof parsed.acquiredAt !== "string") {
      return null;
    }
    return {
      pid: parsed.pid,
      acquiredAt: parsed.acquiredAt,
    };
  } catch {
    return null;
  }
}

function isProcessRunning(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error: any) {
    return error.code === "EPERM";
  }
}
