import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { loadChainsFile, parseChainsDocument, selectChain } from "../src/chains.js";
import { loadConfig } from "../src/config.js";

let tempRoot = "";
let savedRpc: string | undefined;

afterEach(async () => {
  if (savedRpc === undefined) delete process.env.RPC_HTTP_URL;
  else process.env.RPC_HTTP_URL = savedRpc;
  savedRpc = undefined;
  if (tempRoot) {
    await rm(tempRoot, { recursive: true, force: true });
    tempRoot = "";
  }
});

const DOC = JSON.stringify({
  version: 1,
  chains: [
    { slug: "eth-mainnet", name: "Ethereum", rpcHttpUrl: "https://eth.invalid", confirmations: 5 },
    { slug: "base", name: "Base", enabled: false, rpcHttpUrl: "https://base.invalid" },
  ],
});

describe("chains.json parsing", () => {
  test("parses valid document", () => {
    const entries = parseChainsDocument(DOC);
    expect(entries).toHaveLength(2);
    expect(entries[0].slug).toBe("eth-mainnet");
    expect(entries[0].enabled).toBe(true);
    expect(entries[1].enabled).toBe(false);
  });

  test("rejects bad version", () => {
    expect(() => parseChainsDocument(JSON.stringify({ version: 2, chains: [] }))).toThrow(
      "invalid_chains_version",
    );
  });

  test("rejects bad slug", () => {
    expect(() =>
      parseChainsDocument(
        JSON.stringify({ version: 1, chains: [{ slug: "Bad Slug", name: "x", rpcHttpUrl: "https://x.invalid" }] }),
      ),
    ).toThrow("invalid_chains_slug:Bad Slug");
  });

  test("rejects duplicate slug", () => {
    expect(() =>
      parseChainsDocument(
        JSON.stringify({
          version: 1,
          chains: [
            { slug: "a", name: "x", rpcHttpUrl: "https://x.invalid" },
            { slug: "a", name: "y", rpcHttpUrl: "https://y.invalid" },
          ],
        }),
      ),
    ).toThrow("duplicate_chains_slug:a");
  });

  test("rejects non-http rpc", () => {
    expect(() =>
      parseChainsDocument(
        JSON.stringify({ version: 1, chains: [{ slug: "a", name: "x", rpcHttpUrl: "ftp://x" }] }),
      ),
    ).toThrow("invalid_chains_rpc:a");
  });

  test("selectChain finds and rejects", () => {
    const entries = parseChainsDocument(DOC);
    expect(selectChain(entries, "base").name).toBe("Base");
    expect(() => selectChain(entries, "nope")).toThrow("unknown_chain_slug:nope");
  });

  test("loadChainsFile returns null when absent", async () => {
    tempRoot = await mkdtemp(path.join(os.tmpdir(), "chains-"));
    expect(await loadChainsFile(tempRoot)).toBeNull();
  });
});

describe("config layering with chains.json", () => {
  test("--chain overrides env-derived rpc and isolates state dir", async () => {
    tempRoot = await mkdtemp(path.join(os.tmpdir(), "chains-cfg-"));
    const envFile = path.join(tempRoot, ".env");
    await writeFile(envFile, "RPC_HTTP_URL=http://127.0.0.1:8545\nSTATE_DIR=runner-state\n", "utf8");
    await writeFile(path.join(tempRoot, "chains.json"), DOC, "utf8");

    const config = await loadConfig(tempRoot, {
      once: true,
      dryRunWebhook: false,
      noWebhook: false,
      envFile,
      chain: "eth-mainnet",
    });
    expect(config.rpcHttpUrl).toBe("https://eth.invalid");
    expect(config.confirmations).toBe(5);
    expect(config.stateDir).toBe(path.join(tempRoot, "runner-state", "eth-mainnet"));
  });

  test("auto-selects single enabled chain when no --chain", async () => {
    tempRoot = await mkdtemp(path.join(os.tmpdir(), "chains-cfg-"));
    const envFile = path.join(tempRoot, ".env");
    await writeFile(envFile, "RPC_HTTP_URL=http://127.0.0.1:8545\n", "utf8");
    await writeFile(
      path.join(tempRoot, "chains.json"),
      JSON.stringify({
        version: 1,
        chains: [{ slug: "only", name: "Only", rpcHttpUrl: "https://only.invalid" }],
      }),
      "utf8",
    );
    const config = await loadConfig(tempRoot, { once: true, dryRunWebhook: false, noWebhook: false, envFile });
    expect(config.rpcHttpUrl).toBe("https://only.invalid");
    expect(config.stateDir).toBe(path.join(tempRoot, "runner-state", "only"));
  });

  test("multiple enabled chains without --chain throws", async () => {
    tempRoot = await mkdtemp(path.join(os.tmpdir(), "chains-cfg-"));
    const envFile = path.join(tempRoot, ".env");
    await writeFile(envFile, "RPC_HTTP_URL=http://127.0.0.1:8545\n", "utf8");
    await writeFile(
      path.join(tempRoot, "chains.json"),
      JSON.stringify({
        version: 1,
        chains: [
          { slug: "a", name: "A", rpcHttpUrl: "https://a.invalid" },
          { slug: "b", name: "B", rpcHttpUrl: "https://b.invalid" },
        ],
      }),
      "utf8",
    );
    await expect(
      loadConfig(tempRoot, { once: true, dryRunWebhook: false, noWebhook: false, envFile }),
    ).rejects.toThrow("multiple enabled chains");
  });

  test("no chains.json leaves single-runner behavior unchanged", async () => {
    tempRoot = await mkdtemp(path.join(os.tmpdir(), "chains-cfg-"));
    const envFile = path.join(tempRoot, ".env");
    await writeFile(envFile, "RPC_HTTP_URL=http://127.0.0.1:9999\nSTATE_DIR=runner-state\n", "utf8");
    savedRpc = process.env.RPC_HTTP_URL;
    delete process.env.RPC_HTTP_URL;
    const config = await loadConfig(tempRoot, { once: true, dryRunWebhook: false, noWebhook: false, envFile });
    expect(config.rpcHttpUrl).toBe("http://127.0.0.1:9999");
    expect(config.stateDir).toBe(path.join(tempRoot, "runner-state"));
  });
});
