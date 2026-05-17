// Bespoke proxy storage layout scanner.
//
// The init-takeover verifier and admin-name heuristic together cover
// ERC-1967, OpenZeppelin Initializable v4/v5, and the canonical numeric
// owner slots (0..3, 49..51, 100..101). Custom proxy layouts (ERC-7201
// namespaced slots, manually-chosen slot numbers, custom storage libs)
// fall outside this set.
//
// This module reads extra slots from RESCUE_EXTRA_ADMIN_SLOTS (comma-
// separated, hex 0x... or decimal) and surfaces three things for the
// rescue-prove dispatcher:
//
//   1. Pre-image of each slot — useful when we later try ownership
//      transfer attempts; if a slot holds the current owner address we
//      can target our takeover at that slot.
//   2. A list of `(slot -> address-currently-stored)` pairs which we add
//      to the PoE notes.
//   3. Lets the init-takeover module's post-call scan check these slots
//      ALONGSIDE the hardcoded ones.

import { rpcRequest } from "../anvil-pool";

const ADDRESS_MASK_HEX = "0xffffffffffffffffffffffffffffffffffffffff";

/** Parse RESCUE_EXTRA_ADMIN_SLOTS into a list of 32-byte-padded hex slot
 *  identifiers. Tolerates "0x..", "0X..", and plain decimal entries. */
export function parseExtraAdminSlots(): string[] {
  const raw = (process.env.RESCUE_EXTRA_ADMIN_SLOTS ?? "").trim();
  if (!raw) return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => {
      if (s.toLowerCase().startsWith("0x")) {
        const clean = s.slice(2).toLowerCase();
        if (!/^[0-9a-f]+$/.test(clean)) return null;
        return "0x" + clean.padStart(64, "0");
      }
      try {
        const n = BigInt(s);
        return "0x" + n.toString(16).padStart(64, "0");
      } catch {
        return null;
      }
    })
    .filter((s): s is string => s != null);
}

export interface ExtraSlotProbe {
  slot: string;
  raw: string | null;
  /** When the slot's low 20 bytes look like a non-zero address, this is it
   *  (lowercased, 0x-prefixed). */
  probableAddress: string | null;
}

/** Read every configured extra slot off the fork. Returns one entry per
 *  slot, with `probableAddress` set when the lower 20 bytes form a non-
 *  zero address. */
export async function probeExtraAdminSlots(args: {
  url: string;
  contractAddress: string;
}): Promise<ExtraSlotProbe[]> {
  const slots = parseExtraAdminSlots();
  if (slots.length === 0) return [];
  const out: ExtraSlotProbe[] = [];
  for (const slot of slots) {
    let raw: string | null = null;
    try {
      raw = await rpcRequest<string>(args.url, "eth_getStorageAt", [
        args.contractAddress,
        slot,
        "latest",
      ]);
    } catch {
      raw = null;
    }
    out.push({
      slot,
      raw,
      probableAddress: rawSlotToAddress(raw),
    });
  }
  return out;
}

function rawSlotToAddress(raw: string | null | undefined): string | null {
  if (!raw || raw === "0x" || raw === "0x0") return null;
  const clean = raw.replace(/^0x/, "").toLowerCase().padStart(64, "0");
  if (clean.length < 64) return null;
  const low20 = "0x" + clean.slice(-40);
  if (low20 === "0x0000000000000000000000000000000000000000") return null;
  return low20;
}

export { ADDRESS_MASK_HEX };
