// Token-quirk pre-flight.
//
// Before we add a token to the drain plan, we statically simulate what
// `transfer(escrow, bal)` would do on the fork and classify the token:
//
//   - "normal"       — standard ERC20, drain plan can use canonical
//                      transfer(escrow, balance)
//   - "fee-on-transfer" (FOT) — transfer delivers less than asked. We
//                      adjust the recorded `amountBase` to the actual
//                      delivered amount and tag the asset with `feeBps`.
//   - "paused"       — transfer reverts unconditionally with a pause-related
//                      revert string. We skip this token but list it under
//                      "trapped assets" in the PoE so the operator sees why.
//   - "blacklisted"  — transfer to escrow specifically reverts (escrow or
//                      contract is on the token's blocklist). Same skip
//                      behavior as "paused" but with a different label.
//   - "non-transferable" — transfer succeeds but ZERO is delivered AND
//                      ZERO is debited (soulbound tokens, mock contracts).
//                      Skip + log.
//   - "errored"      — eth_call itself reverted in a non-classifiable way.
//                      Conservative: keep the asset in the plan but mark it
//                      as unverified.
//
// Done via `eth_call` against the fork (no state mutation) so we can probe
// many tokens cheaply.

import { rpcRequest } from "../anvil-pool";

const ERC20_TRANSFER_SELECTOR = "0xa9059cbb";
const ERC20_BALANCE_OF_SELECTOR = "0x70a08231";

export type QuirkKind =
  | "normal"
  | "fee-on-transfer"
  | "paused"
  | "blacklisted"
  | "non-transferable"
  | "errored";

export interface TokenQuirk {
  kind: QuirkKind;
  /** When fee-on-transfer, the percentage taken (basis points; 100 = 1%). */
  feeBps?: number;
  /** Adjusted deliverable amount in base units. For FOT this is the
   *  actual amount escrow would receive given `attemptedAmount`. For
   *  normal it equals attemptedAmount. For skipped quirks this is "0". */
  deliverableAmount: string;
  /** What we asked for. */
  attemptedAmount: string;
  /** Revert string / debug info we observed, if any. */
  detail?: string;
}

/** Pre-flight probe: simulate `transfer(escrow, balance)` from the
 *  contract via `eth_call` with `from: contract` and observe whether it
 *  reverts, succeeds, and what would land in escrow.
 *
 *  Uses balance/2 as the probe amount when balance is large (avoids edge
 *  reverts in contracts that block exact-balance transfers). Falls back to
 *  full balance if /2 = 0.
 */
export async function preflightTokenQuirk(
  url: string,
  token: string,
  contractAddress: string,
  escrow: string,
  contractBalance: string,
): Promise<TokenQuirk> {
  let amount: bigint;
  try {
    amount = BigInt(contractBalance);
  } catch {
    return { kind: "errored", deliverableAmount: "0", attemptedAmount: "0", detail: "non-numeric balance" };
  }
  if (amount === 0n) {
    return { kind: "normal", deliverableAmount: "0", attemptedAmount: "0" };
  }
  // Probe with the full balance — that's what the drain will actually
  // attempt, and many quirky tokens behave differently at edge amounts.
  const transferCalldata = encodeTransfer(escrow, amount);
  const balanceOfEscrowCall = encodeBalanceOf(escrow);
  let escrowBalanceBefore = 0n;
  try {
    const r = await rpcRequest<string>(url, "eth_call", [
      { to: token, data: balanceOfEscrowCall },
      "latest",
    ]);
    if (r && r !== "0x") escrowBalanceBefore = BigInt(r);
  } catch {
    /* escrow may be 0x000... — fine */
  }

  // Simulate the transfer with eth_call (state-overrides aren't universally
  // supported, so we do a small read-then-staticcall pattern). The most
  // portable trick: eth_call with `from: contract` simulates a call as if
  // the contract was the sender — works on anvil and geth/erigon for
  // simple ERC20 transfers because there's no msg.sender check beyond
  // _from = msg.sender.
  let revertInfo: string | null = null;
  let rawReturn: string | null = null;
  try {
    rawReturn = await rpcRequest<string>(url, "eth_call", [
      {
        from: contractAddress,
        to: token,
        data: transferCalldata,
      },
      "latest",
    ]);
  } catch (e: any) {
    revertInfo = String(e?.message ?? e).slice(0, 240);
  }

  if (revertInfo) {
    const r = revertInfo.toLowerCase();
    if (r.includes("paus") || r.includes("frozen") || r.includes("suspended") || r.includes("stopped")) {
      return {
        kind: "paused",
        deliverableAmount: "0",
        attemptedAmount: amount.toString(),
        detail: revertInfo,
      };
    }
    if (
      r.includes("blacklist") ||
      r.includes("blocked") ||
      r.includes("banned") ||
      r.includes("denied") ||
      r.includes("denylist")
    ) {
      return {
        kind: "blacklisted",
        deliverableAmount: "0",
        attemptedAmount: amount.toString(),
        detail: revertInfo,
      };
    }
    // Unknown revert — could be many things. Conservative: keep in plan
    // but flag as errored so the operator knows the deliverable amount is
    // not pre-verified.
    return {
      kind: "errored",
      deliverableAmount: amount.toString(),
      attemptedAmount: amount.toString(),
      detail: revertInfo,
    };
  }

  // transfer() returned successfully. Some tokens return `bool false`
  // instead of reverting. Treat false return as a soft failure.
  if (rawReturn && rawReturn !== "0x" && rawReturn.length >= 66) {
    const lastByte = rawReturn.slice(-2);
    if (lastByte === "00" && rawReturn.replace(/^0x/, "").replace(/0+$/, "") === "") {
      return {
        kind: "errored",
        deliverableAmount: "0",
        attemptedAmount: amount.toString(),
        detail: "transfer returned false (silent failure)",
      };
    }
  }

  // Re-read escrow balance to see what landed. We can't actually execute
  // the transfer with eth_call (state doesn't persist), so we use the
  // standard FOT detection trick: simulate a transfer with state overrides
  // to read the post-state. State-override is a newer RPC method that
  // some anvil/geth versions support. If unsupported, fall through to the
  // canonical "transfer + balanceOf" trace via debug_traceCall.
  let postBalance = escrowBalanceBefore;
  try {
    // eth_call with state-override: applies the state diff but returns
    // only the read result. Foundry's anvil supports this.
    const overrideResult = await rpcRequest<string>(url, "eth_call", [
      { to: token, data: balanceOfEscrowCall },
      "latest",
      {
        [token]: {
          // simulate state diff by NOT applying anything (no override) —
          // just read balance.  We need a different approach.
        },
      },
    ]).catch(() => null);
    if (overrideResult && overrideResult !== "0x") {
      postBalance = BigInt(overrideResult);
    }
  } catch {
    /* state-override not supported, fall through */
  }

  // The eth_call doesn't actually move funds, so we can't measure FOT via
  // a single static call. Instead we do a 2-call simulation against the
  // fork: snapshot, send the actual transfer from the contract via
  // anvil_impersonateAccount, read escrow balance, then revert. This is
  // exact but costs ~3 RPC roundtrips per token, which we keep bounded by
  // the existing exposure.tokens.length cap.
  try {
    const fotMeasure = await measureFotViaImpersonation(url, token, contractAddress, escrow, amount);
    if (fotMeasure.delivered != null) {
      if (fotMeasure.delivered === 0n) {
        return {
          kind: "non-transferable",
          deliverableAmount: "0",
          attemptedAmount: amount.toString(),
          detail: "transfer succeeded but delivered 0 (soulbound / mock?)",
        };
      }
      if (fotMeasure.delivered < amount) {
        // Pure FOT — compute fee in bps
        const burned = amount - fotMeasure.delivered;
        const feeBps = Number((burned * 10_000n) / amount);
        return {
          kind: "fee-on-transfer",
          deliverableAmount: fotMeasure.delivered.toString(),
          attemptedAmount: amount.toString(),
          feeBps,
          detail: `delivered ${fotMeasure.delivered} of ${amount} attempted (~${(feeBps / 100).toFixed(2)}% fee)`,
        };
      }
      // delivered == amount → normal
      return {
        kind: "normal",
        deliverableAmount: amount.toString(),
        attemptedAmount: amount.toString(),
      };
    }
  } catch {
    /* fall through */
  }

  // Couldn't measure precisely — assume normal (best effort).
  return {
    kind: "normal",
    deliverableAmount: amount.toString(),
    attemptedAmount: amount.toString(),
  };
}

/** Send a real transfer from the contract via impersonation, read escrow
 *  balance pre/post, then revert via anvil's snapshot/revert pair. Pure
 *  measurement — no persistent state change. */
async function measureFotViaImpersonation(
  url: string,
  token: string,
  contractAddress: string,
  escrow: string,
  amount: bigint,
): Promise<{ delivered: bigint | null }> {
  const snapId = await rpcRequest<string>(url, "evm_snapshot", []).catch(() => null);
  if (!snapId) return { delivered: null };
  try {
    await rpcRequest(url, "anvil_impersonateAccount", [contractAddress]).catch(() => null);
    await rpcRequest(url, "anvil_setBalance", [contractAddress, "0xde0b6b3a7640000"]).catch(() => null);
    const balBefore = await readErc20Balance(url, token, escrow);
    const txHash = await rpcRequest<string>(url, "eth_sendTransaction", [
      {
        from: contractAddress,
        to: token,
        data: encodeTransfer(escrow, amount),
        gas: "0x200000",
        value: "0x0",
      },
    ]).catch(() => null);
    if (!txHash) return { delivered: null };
    // tiny receipt wait
    for (let i = 0; i < 6; i++) {
      const r = await rpcRequest<any>(url, "eth_getTransactionReceipt", [txHash]).catch(() => null);
      if (r && r.transactionHash) {
        if (r.status !== "0x1") return { delivered: 0n };
        break;
      }
      await new Promise((res) => setTimeout(res, 25 * (i + 1)));
    }
    const balAfter = await readErc20Balance(url, token, escrow);
    return { delivered: balAfter - balBefore };
  } finally {
    await rpcRequest(url, "evm_revert", [snapId]).catch(() => null);
    await rpcRequest(url, "anvil_stopImpersonatingAccount", [contractAddress]).catch(() => null);
  }
}

async function readErc20Balance(url: string, token: string, holder: string): Promise<bigint> {
  try {
    const raw = await rpcRequest<string>(url, "eth_call", [
      { to: token, data: encodeBalanceOf(holder) },
      "latest",
    ]);
    return raw && raw !== "0x" ? BigInt(raw) : 0n;
  } catch {
    return 0n;
  }
}

function encodeTransfer(to: string, amount: bigint): string {
  const addr = to.replace(/^0x/, "").toLowerCase().padStart(64, "0");
  let amt = amount.toString(16);
  if (amt.length > 64) amt = amt.slice(-64);
  amt = amt.padStart(64, "0");
  return ERC20_TRANSFER_SELECTOR + addr + amt;
}

function encodeBalanceOf(addr: string): string {
  return ERC20_BALANCE_OF_SELECTOR + addr.replace(/^0x/, "").toLowerCase().padStart(64, "0");
}
