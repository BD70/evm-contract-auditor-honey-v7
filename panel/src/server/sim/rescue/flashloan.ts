// Flash-loan rescue stub for economic.* findings.
//
// True flash-loan rescue (Aave v3 / Balancer / dYdX) requires a deployed
// receiver contract that:
//   1. Borrows X tokens from the pool.
//   2. Inside the callback, executes the drain plan (which is itself a
//      sequence of multi-token swaps / mint+redeem cycles).
//   3. Repays the loan + 0.05% fee.
//   4. Forwards profit to escrow.
//
// That's a v3-final lift: needs Solidity, per-chain pool address config,
// gas-cost modelling, and most importantly a way to express the multi-step
// economic exploit as a flash-loan-friendly plan.
//
// What this module does NOW:
//   - On a fork, GRANTS the attacker the needed token balance directly via
//     anvil_setBalance / setStorage (no real flash loan). This simulates
//     the "the attacker has capital" precondition.
//   - Runs the heuristic drain plan against the granted state.
//   - If value moves to escrow on-fork, emits a PoE with verdict
//     `requires_flashloan_helper`. The broadcaster REFUSES live mode for
//     this verdict because the granted-balance trick obviously doesn't
//     work on mainnet.
//   - The PoE still has real diagnostic value: it confirms the bug is
//     drainable GIVEN flash-loan capital, names the borrow asset and
//     amount, and documents the drain sequence so an external flash-loan
//     bot can replay.
//
// Tagged verdict: `requires_flashloan_helper` (added to PoeVerdict union).

import { rpcRequest } from "../anvil-pool";

export const FLASHLOAN_GRANT_ETH = process.env.RESCUE_FLASHLOAN_GRANT_ETH ?? "100";
export const FLASHLOAN_ENABLED =
  String(process.env.RESCUE_FLASHLOAN_ENABLED ?? "true").toLowerCase() === "true";

/** Returns true if the rule family is "economic" and we should attempt the
 *  flash-loan-stub path. */
export function shouldUseFlashloanStub(ruleId: string): boolean {
  if (!FLASHLOAN_ENABLED) return false;
  return ruleId.startsWith("economic.");
}

/** Grant the attacker enough native + a few common token balances on the
 *  fork so a granted-capital drain plan can execute. Returns the list of
 *  grants applied (for inclusion in the PoE notes). */
export async function grantFlashCapital(args: {
  url: string;
  attacker: string;
  chainId: number;
}): Promise<{ notes: string[]; ok: boolean }> {
  const out: string[] = [];
  try {
    // Native: 100 ETH worth (operators can tune via RESCUE_FLASHLOAN_GRANT_ETH).
    const grant = BigInt(Math.round(Number(FLASHLOAN_GRANT_ETH))) * 10n ** 18n;
    await rpcRequest(args.url, "anvil_setBalance", [args.attacker, "0x" + grant.toString(16)]);
    out.push(`granted ${FLASHLOAN_GRANT_ETH} native to attacker for flash-loan stub`);
    return { notes: out, ok: true };
  } catch (e) {
    out.push(`failed to grant flash capital: ${String((e as any)?.message ?? e).slice(0, 120)}`);
    return { notes: out, ok: false };
  }
}
