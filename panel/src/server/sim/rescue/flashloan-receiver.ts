// Flash-loan receiver registry.
//
// Parses RESCUE_FLASHLOAN_RECEIVER from env (format
// "chainId:0xaddr,chainId:0xaddr,...") and exposes a per-chain lookup so
// the broadcaster knows whether to:
//
//   (a) refuse live broadcast for requires_flashloan_helper PoEs (when no
//       receiver is configured for this chain — current state), or
//
//   (b) build a single batched call to the deployed receiver passing the
//       PoE drain plan as the encoded payload (when an address IS
//       configured).
//
// The Solidity source for a minimal receiver compatible with this wiring
// lives at `contracts/rescue/FlashLoanRescue.sol`. Operators deploy it
// per-chain themselves (we don't ship deployment automation in v4) and
// register the address here via env.
//
// On-chain interface this module assumes:
//
//   function executeRescue(
//     address asset,       // borrow asset (e.g. WETH)
//     uint256 amount,      // borrow amount
//     address[] calldata targets,
//     bytes[] calldata calldatas,
//     uint256[] calldata values,
//     address escrow
//   ) external;
//
// The receiver performs the Aave v3 flashLoanSimple call, then in
// executeOperation iterates `(targets[i], calldatas[i], values[i])` and
// finally transfers the post-repayment balance to escrow.

export interface FlashloanReceiverEntry {
  chainId: number;
  address: string;
}

/** Parse env and return the registry. Invalid entries are dropped. */
export function loadFlashloanReceivers(): FlashloanReceiverEntry[] {
  const raw = (process.env.RESCUE_FLASHLOAN_RECEIVER ?? "").trim();
  if (!raw) return [];
  const out: FlashloanReceiverEntry[] = [];
  for (const entry of raw.split(",")) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    const idx = trimmed.indexOf(":");
    if (idx < 1) continue;
    const cid = Number(trimmed.slice(0, idx));
    const addr = trimmed.slice(idx + 1).trim();
    if (!Number.isFinite(cid) || cid <= 0) continue;
    if (!/^0x[0-9a-fA-F]{40}$/.test(addr)) continue;
    out.push({ chainId: cid, address: addr.toLowerCase() });
  }
  return out;
}

export function flashloanReceiverFor(chainId: number): string | null {
  const all = loadFlashloanReceivers();
  return all.find((r) => r.chainId === chainId)?.address ?? null;
}
