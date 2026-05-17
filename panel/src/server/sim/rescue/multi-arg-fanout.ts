// Multi-arg address-substitution fanout.
//
// v2's rescue-prove substituted only the WITNESSED address position. But
// many forwarders ALSO take a secondary address argument that gates the
// call (e.g. `onSwap(address router, address recipient, ...)`). If we only
// substitute the witnessed slot, the call reverts because `recipient`
// stayed as the original attacker probe.
//
// This module generates calldata variants that substitute MULTIPLE address
// slots at once — every reasonable pair / triple combination of
// (token-slot, escrow-slot, attacker-slot) — and bounds the explosion at
// MAX_FANOUT_VARIANTS per (selector, args) pair.

import { buildAbiCalldata, type ArgValue } from "../abi";

const MAX_FANOUT_VARIANTS = 8;

export interface FanoutInput {
  selector: string;
  argTypes: string[];
  /** Each set of {token, escrow} we want to fill into address slots. */
  substitutions: Array<{ token: string; escrow: string; amount: bigint }>;
  /** The default "filler" address for slots we don't substitute. Usually
   *  the attacker EOA so that gate-checks like `require(msg.sender ==
   *  user)` are satisfied when the slot represents an "approved user". */
  filler: string;
}

export interface FanoutVariant {
  calldata: string;
  /** Description of which slots got which address — surfaces in PoE notes. */
  shape: string;
}

/** Enumerate (slotA, slotB) address-position pairs and emit calldata where:
 *    slotA = token, slotB = escrow
 *  for every distinct ordered pair. Bounded by MAX_FANOUT_VARIANTS. */
export function multiArgFanout(input: FanoutInput): FanoutVariant[] {
  const addressPositions: number[] = [];
  for (let i = 0; i < input.argTypes.length; i++) {
    if (input.argTypes[i] === "address") addressPositions.push(i);
  }
  if (addressPositions.length < 2) return [];
  const out: FanoutVariant[] = [];
  // Pair fanout: (tokenSlot, escrowSlot)
  for (const sub of input.substitutions) {
    for (const tokenSlot of addressPositions) {
      for (const escrowSlot of addressPositions) {
        if (tokenSlot === escrowSlot) continue;
        const cd = buildWithSubs(input.selector, input.argTypes, {
          [tokenSlot]: sub.token,
          [escrowSlot]: sub.escrow,
        }, input.filler, sub.amount);
        if (cd) {
          out.push({
            calldata: cd,
            shape: `pos[${tokenSlot}]=token pos[${escrowSlot}]=escrow rest=attacker`,
          });
          if (out.length >= MAX_FANOUT_VARIANTS) return out;
        }
      }
    }
  }
  return out;
}

function buildWithSubs(
  selector: string,
  argTypes: string[],
  subs: Record<number, string>,
  filler: string,
  amount: bigint,
): string | null {
  const args: ArgValue[] = [];
  for (let i = 0; i < argTypes.length; i++) {
    const t = argTypes[i];
    if (t === "address") {
      args.push({ kind: "address", value: subs[i] ?? filler });
    } else if (/^uint/.test(t)) {
      args.push({ kind: "uint", value: amount });
    } else if (t === "bool") {
      args.push({ kind: "bool", value: false });
    } else if (t === "bytes") {
      args.push({ kind: "bytes", value: "0x" });
    } else if (t === "string") {
      args.push({ kind: "string", value: "" });
    } else if (t === "address[]") {
      args.push({ kind: "address[]", value: [] });
    } else if (t === "uint[]") {
      args.push({ kind: "uint[]", value: [] });
    } else {
      return null;
    }
  }
  try {
    return buildAbiCalldata(selector, args);
  } catch {
    return null;
  }
}
