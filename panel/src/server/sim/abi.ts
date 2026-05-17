// Minimal ABI v2 encoder used by the exploit drivers. We only support the
// argument shapes our verifiers actually need (address, uint256, bytes), but
// the encoding is the real spec (offsets relative to start of arguments,
// dynamic-length data padded to 32 bytes) so functions parse it correctly
// instead of reverting on malformed calldata.
//
// We intentionally avoid pulling viem in here: the dependency surface for the
// simulation worker should stay tiny so it can keep running even when the
// rest of the panel is hot-reloaded.

export type ArgValue =
  | { kind: "address"; value: string }
  | { kind: "uint"; value: bigint | number | string }
  | { kind: "bytes"; value: string /* hex with or without 0x */ }
  | { kind: "bool"; value: boolean }
  | { kind: "string"; value: string }
  | { kind: "bytes32"; value: string /* exactly 32 bytes, padded */ }
  | { kind: "address[]"; value: string[] }
  | { kind: "uint[]"; value: Array<bigint | number | string> }
  | { kind: "bytes[]"; value: string[] }
  | { kind: "tuple"; types: string[]; values: ArgValue[] };

const ZERO32 = "0".repeat(64);

function padLeft64(hex: string): string {
  const clean = hex.replace(/^0x/, "");
  if (clean.length >= 64) return clean.slice(-64);
  return clean.padStart(64, "0");
}

function padRight64(hex: string, lengthBytes: number): string {
  // pad to next 32-byte boundary (length is bytes of data)
  const padded = Math.ceil(lengthBytes / 32) * 32;
  return hex.padEnd(padded * 2, "0");
}

function uintHex(v: bigint | number | string): string {
  let bi: bigint;
  if (typeof v === "bigint") bi = v;
  else if (typeof v === "number") bi = BigInt(v);
  else if (v.startsWith("0x") || v.startsWith("0X")) bi = BigInt(v);
  else bi = BigInt(v);
  return padLeft64(bi.toString(16));
}

function addressHex(a: string): string {
  const clean = a.replace(/^0x/, "").toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(clean)) throw new Error(`invalid address: ${a}`);
  return padLeft64(clean);
}

function bytesHex(b: string): { length: number; padded: string } {
  const clean = b.replace(/^0x/, "");
  const lengthBytes = clean.length / 2;
  const padded = padRight64(clean, lengthBytes);
  return { length: lengthBytes, padded };
}

/** True iff this value is encoded as a dynamic type (offset in head, data in tail). */
function isDynamic(a: ArgValue): boolean {
  switch (a.kind) {
    case "bytes":
    case "string":
    case "address[]":
    case "uint[]":
    case "bytes[]":
      return true;
    case "tuple":
      return a.values.some(isDynamic);
    default:
      return false;
  }
}

/** Encode a single non-tuple value as a packed payload (no offsets). */
function encodeTail(a: ArgValue): string {
  switch (a.kind) {
    case "bytes": {
      const enc = bytesHex(a.value);
      return padLeft64(enc.length.toString(16)) + (enc.length > 0 ? enc.padded : "");
    }
    case "string": {
      const utf8 = new TextEncoder().encode(a.value);
      const hex = Array.from(utf8).map((b) => b.toString(16).padStart(2, "0")).join("");
      const len = utf8.length;
      const padded = padRight64(hex, len);
      return padLeft64(len.toString(16)) + (len > 0 ? padded : "");
    }
    case "address[]": {
      const parts = [padLeft64(a.value.length.toString(16))];
      for (const ad of a.value) parts.push(addressHex(ad));
      return parts.join("");
    }
    case "uint[]": {
      const parts = [padLeft64(a.value.length.toString(16))];
      for (const v of a.value) parts.push(uintHex(v));
      return parts.join("");
    }
    case "bytes[]": {
      // outer-length + N inner offsets + each inner length+data
      const n = a.value.length;
      const inners = a.value.map((bv) => {
        const e = bytesHex(bv);
        return padLeft64(e.length.toString(16)) + (e.length > 0 ? e.padded : "");
      });
      let off = n * 32;
      const offsets: string[] = [];
      for (const inner of inners) {
        offsets.push(padLeft64(off.toString(16)));
        off += inner.length / 2;
      }
      return padLeft64(n.toString(16)) + offsets.join("") + inners.join("");
    }
    case "tuple":
      return abiEncode(a.values);
    default:
      throw new Error(`encodeTail unsupported for ${(a as any).kind}`);
  }
}

/**
 * Encode an array of typed arguments per ABI v2. Returns hex (no leading 0x).
 *
 * Layout: head (32 bytes per arg — static value OR offset pointer for
 * dynamic args), then tail (dynamic data, each starting at its head-offset
 * relative to the start of the encoded args). Tuples participate in their
 * containing arg's static/dynamic decision.
 */
export function abiEncode(args: ArgValue[]): string {
  const head: string[] = [];
  const tail: string[] = [];
  const headBytes = args.length * 32;
  let tailOffset = headBytes;
  for (const a of args) {
    if (!isDynamic(a)) {
      switch (a.kind) {
        case "address":
          head.push(addressHex(a.value));
          break;
        case "uint":
          head.push(uintHex(a.value));
          break;
        case "bool":
          head.push(padLeft64(a.value ? "1" : "0"));
          break;
        case "bytes32":
          head.push(padLeft64(a.value.replace(/^0x/, "")));
          break;
        case "tuple": {
          // Static tuple: encode in-place. Each inner value occupies 32 bytes
          // and is concatenated (head-only, no tail).
          let inner = "";
          for (const v of a.values) inner += abiEncode([v]);
          head.push(inner);
          break;
        }
        default:
          throw new Error(`abiEncode: static encoding not supported for ${(a as any).kind}`);
      }
    } else {
      head.push(padLeft64(tailOffset.toString(16)));
      const encoded = encodeTail(a);
      tail.push(encoded);
      tailOffset += encoded.length / 2;
    }
  }
  return head.join("") + tail.join("");
}

/**
 * Build calldata: selector + ABI-encoded args. `selector` may be 0x-prefixed.
 */
export function buildAbiCalldata(selector: string, args: ArgValue[]): string {
  const sel = selector.startsWith("0x") ? selector.slice(2) : selector;
  if (!/^[0-9a-f]{8}$/i.test(sel)) throw new Error(`invalid selector: ${selector}`);
  return "0x" + sel.toLowerCase() + abiEncode(args);
}

/**
 * Convenience: build calldata that places `probeAddr` at one specific argument
 * position. Other positions are filled per `argTypes` (when present we encode
 * a real value of that type; when unknown we default to a zero uint256 slot).
 *
 * argTypes may be empty (e.g. for stripped decompiler output) — in that case
 * every position is treated as uint256 with the address-position swapped in.
 * This is the calldata our v1 driver used; we keep it as a fallback.
 */
export function buildCalldataAddressAt(
  selector: string,
  argTypes: string[],
  argCount: number,
  addressAtPos: number,
  probeAddr: string,
  opts: { dataBytes?: string } = {},
): string {
  const n = Math.max(1, Math.min(Math.max(argCount, argTypes.length), 12));
  const args: ArgValue[] = [];
  for (let i = 0; i < n; i++) {
    if (i === addressAtPos) {
      args.push({ kind: "address", value: probeAddr });
      continue;
    }
    const t = (argTypes[i] ?? "").toLowerCase();
    if (t === "address") {
      args.push({ kind: "address", value: "0x" + "0".repeat(40) });
    } else if (t.startsWith("uint") || t.startsWith("int")) {
      args.push({ kind: "uint", value: 0 });
    } else if (t === "bytes" || t.startsWith("bytes ")) {
      args.push({ kind: "bytes", value: opts.dataBytes ?? "0x" });
    } else if (t === "bool") {
      args.push({ kind: "uint", value: 0 });
    } else {
      // Unknown / static — fill with a zero 32-byte slot. This is the calldata
      // shape the v1 driver used; safe default.
      args.push({ kind: "uint", value: 0 });
    }
  }
  return buildAbiCalldata(selector, args);
}

/**
 * Build calldata using a RESOLVED signature's argument types. This is the
 * preferred path when we know the real signature (via openchain.xyz /
 * 4byte.directory) because we generate spec-compliant calldata that won't
 * revert in the ABI decoder. Substitutes `probeAddr` at `addressAtPos`;
 * fills all other args with sensible defaults.
 *
 * Supports the common Ethereum types found in vulnerable forwarders:
 *   - address, uint*, int*, bool, bytes32 (static)
 *   - bytes, string (dynamic)
 *   - address[], uint*[], bytes[] (dynamic arrays)
 *   - simple tuples like (address,uint256,address,bytes)
 *
 * Unknown types fall back to a zero uint256 slot (safe default that won't
 * break head/tail alignment).
 */
export function buildCalldataFromSignature(
  selector: string,
  argTypes: string[],
  addressAtPos: number | "all", // "all" puts the probe at EVERY address position
  probeAddr: string,
  opts: {
    /** payload for `bytes` argument slots. Defaults to "0x". */
    dataBytes?: string;
    /** uint fill value for non-probe positions. Many functions gate on
     *  `require(amount > 0)` or `require(deadline > block.timestamp)` so a
     *  non-zero default unblocks them. Set to a string for >Number.MAX_SAFE. */
    uintFiller?: bigint | number | string;
  } = {},
): string {
  const args: ArgValue[] = [];
  const fillUint = opts.uintFiller ?? 0;
  const allAddresses = addressAtPos === "all";
  for (let i = 0; i < argTypes.length; i++) {
    const t = argTypes[i].trim();
    const isProbeHere = allAddresses ? t === "address" || t === "address[]" : i === addressAtPos;
    if (isProbeHere && (t === "address" || isUintType(t))) {
      args.push({ kind: "address", value: probeAddr });
      continue;
    }
    args.push(
      defaultValueForType(t, isProbeHere ? probeAddr : null, opts.dataBytes ?? "0x", fillUint),
    );
  }
  return buildAbiCalldata(selector, args);
}

function isUintType(t: string): boolean {
  return /^u?int(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?$/.test(
    t,
  );
}

function defaultValueForType(
  t: string,
  probeOverride: string | null,
  dataBytes: string,
  uintFiller: bigint | number | string = 0,
): ArgValue {
  if (t === "address") {
    return { kind: "address", value: probeOverride ?? "0x" + "0".repeat(40) };
  }
  if (isUintType(t)) return { kind: "uint", value: uintFiller };
  if (t === "bool") return { kind: "bool", value: false };
  if (t === "string") return { kind: "string", value: "" };
  if (t === "bytes") return { kind: "bytes", value: dataBytes };
  if (/^bytes\d+$/.test(t)) {
    const bytesLen = Number(t.slice(5));
    const z = "0".repeat(bytesLen * 2);
    return { kind: "bytes32", value: "0x" + z.padEnd(64, "0") };
  }
  if (t === "address[]") {
    return {
      kind: "address[]",
      value: probeOverride ? [probeOverride] : [],
    };
  }
  if (/^u?int\d*\[\]$/.test(t)) {
    return { kind: "uint[]", value: [] };
  }
  if (t === "bytes[]") {
    return { kind: "bytes[]", value: [] };
  }
  if (t.startsWith("(") && t.endsWith(")")) {
    const inner = t.slice(1, -1);
    const innerTypes = splitTopLevel(inner);
    const innerArgs = innerTypes.map((it) => defaultValueForType(it, null, dataBytes, uintFiller));
    return { kind: "tuple", types: innerTypes, values: innerArgs };
  }
  const fixedM = /^(.*)\[(\d+)\]$/.exec(t);
  if (fixedM) {
    const base = fixedM[1];
    const n = Number(fixedM[2]);
    const vals: ArgValue[] = [];
    for (let i = 0; i < n; i++) vals.push(defaultValueForType(base, null, dataBytes, uintFiller));
    return { kind: "tuple", types: Array(n).fill(base), values: vals };
  }
  return { kind: "uint", value: uintFiller };
}

/** Same as splitTopLevel in selector-resolver but local so we don't cycle imports. */
function splitTopLevel(s: string): string[] {
  if (!s.trim()) return [];
  const out: string[] = [];
  let depth = 0;
  let buf = "";
  for (const ch of s) {
    if (ch === "(" || ch === "[") depth++;
    else if (ch === ")" || ch === "]") depth--;
    if (ch === "," && depth === 0) {
      if (buf.trim()) out.push(buf.trim());
      buf = "";
      continue;
    }
    buf += ch;
  }
  if (buf.trim()) out.push(buf.trim());
  return out;
}

/**
 * Heuristic: walk a resolved signature and return ALL argument positions
 * where substituting the probe address is meaningful (positions of type
 * `address`, `address[]`, OR plain `uint256` since EVM doesn't distinguish
 * — many forwarders take `uint256 target` and cast).
 */
export function probePositionsFromSignature(argTypes: string[]): number[] {
  const ps: number[] = [];
  for (let i = 0; i < argTypes.length; i++) {
    const t = argTypes[i];
    if (t === "address" || t === "address[]") ps.push(i);
  }
  // Then add the uint positions as secondary candidates (less common).
  for (let i = 0; i < argTypes.length; i++) {
    if (argTypes[i] === "uint256" && !ps.includes(i)) ps.push(i);
  }
  return ps;
}

export const ABI_ZERO32 = ZERO32;
