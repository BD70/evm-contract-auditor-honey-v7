// Shared EVM RPC helpers used by every verifier. Centralised so the probe /
// receipt / storage utilities have a single implementation and we don't
// fork-and-rot in each driver.

import { rpcRequest, ATTACKER_ADDRESS, RELAYER_ADDRESS } from "./anvil-pool";

export const ZERO32 = "0".repeat(64);
export const ZERO32_HEX = "0x" + ZERO32;
export const ZERO_ADDRESS = "0x" + "0".repeat(40);

export interface Receipt {
  status?: string;
  contractAddress?: string;
  transactionHash?: string;
  gasUsed?: string;
  blockNumber?: string;
}

export async function waitForReceipt(url: string, txHash: string, maxMs = 8_000): Promise<Receipt | null> {
  const deadline = Date.now() + maxMs;
  let wait = 20;
  while (Date.now() < deadline) {
    const r = await rpcRequest<Receipt | null>(url, "eth_getTransactionReceipt", [txHash]).catch(() => null);
    if (r && r.transactionHash) return r;
    await new Promise((r) => setTimeout(r, wait));
    wait = Math.min(250, wait * 2);
  }
  return null;
}

export async function sendFromAttacker(
  url: string,
  to: string,
  calldata: string,
  opts: { value?: string; gas?: string } = {},
): Promise<{ txHash: string; receipt: Receipt | null }> {
  const tx = {
    from: ATTACKER_ADDRESS,
    to,
    data: calldata,
    gas: opts.gas ?? "0x500000",
    value: opts.value ?? "0x0",
  };
  const txHash = await rpcRequest<string>(url, "eth_sendTransaction", [tx]);
  const receipt = await waitForReceipt(url, txHash).catch(() => null);
  return { txHash, receipt };
}

export async function sendFromRelayer(
  url: string,
  to: string,
  calldata: string,
  opts: { value?: string; gas?: string } = {},
): Promise<{ txHash: string; receipt: Receipt | null }> {
  const tx = {
    from: RELAYER_ADDRESS,
    to,
    data: calldata,
    gas: opts.gas ?? "0x500000",
    value: opts.value ?? "0x0",
  };
  const txHash = await rpcRequest<string>(url, "eth_sendTransaction", [tx]);
  const receipt = await waitForReceipt(url, txHash).catch(() => null);
  return { txHash, receipt };
}

export async function sendFromAddress(
  url: string,
  from: string,
  to: string,
  calldata: string,
  opts: { value?: string; gas?: string } = {},
): Promise<{ txHash: string; receipt: Receipt | null }> {
  await rpcRequest(url, "anvil_impersonateAccount", [from]).catch(() => null);
  await rpcRequest(url, "anvil_setBalance", [from, "0x" + (10n ** 19n).toString(16)]).catch(() => null);
  const tx = {
    from,
    to,
    data: calldata,
    gas: opts.gas ?? "0x500000",
    value: opts.value ?? "0x0",
  };
  const txHash = await rpcRequest<string>(url, "eth_sendTransaction", [tx]);
  const receipt = await waitForReceipt(url, txHash).catch(() => null);
  return { txHash, receipt };
}

export async function deployBytecode(url: string, creationBytecodeHex: string): Promise<string> {
  const tx = {
    from: ATTACKER_ADDRESS,
    data: creationBytecodeHex,
    gas: "0x200000",
  };
  const txHash = await rpcRequest<string>(url, "eth_sendTransaction", [tx]);
  const receipt = await waitForReceipt(url, txHash);
  if (!receipt || receipt.status !== "0x1" || !receipt.contractAddress) {
    throw new Error(`deploy receipt invalid: ${JSON.stringify(receipt)?.slice(0, 200)}`);
  }
  return receipt.contractAddress;
}

export async function setStorage(url: string, address: string, slotHex: string, value32Hex: string): Promise<void> {
  await rpcRequest(url, "anvil_setStorageAt", [address, slotHex, value32Hex]);
}

export async function getStorage(url: string, address: string, slotHex: string): Promise<string> {
  return rpcRequest<string>(url, "eth_getStorageAt", [address, slotHex, "latest"]);
}

export async function getCode(url: string, address: string): Promise<string> {
  return rpcRequest<string>(url, "eth_getCode", [address, "latest"]);
}

/** Extract the last 20 bytes of a 32-byte storage slot as a lowercase
 *  0x-prefixed address. Returns null when the slot is zero/unset. */
export function storageSlotToAddress(raw: string | null | undefined): string | null {
  if (!raw || raw === "0x" || raw === ZERO32_HEX) return null;
  const hex = raw.replace(/^0x/, "").padStart(64, "0");
  if (hex === ZERO32) return null;
  const addr = "0x" + hex.slice(24).toLowerCase();
  if (addr === ZERO_ADDRESS) return null;
  return addr;
}

/** Snapshot then revert helper. Returns a revert callback you must invoke. */
export async function snapshot(url: string): Promise<() => Promise<void>> {
  const id = await rpcRequest<string>(url, "evm_snapshot", []);
  return async () => {
    await rpcRequest<boolean>(url, "evm_revert", [id]).catch(() => false);
  };
}
