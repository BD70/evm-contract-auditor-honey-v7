// Multicall envelope helper.
//
// Some contracts only expose drain-shaped surfaces through a `multicall`
// dispatcher. If we detect either of the canonical multicall selectors in
// the contract bytecode, we wrap each drain step in a multicall envelope
// and add the wrapped variant to the plan. The wrapped step is tried in
// addition to the raw step — if the raw works we use that, otherwise
// the wrapped attempt may succeed.
//
// Canonical multicall surfaces detected:
//   - multicall(bytes[])                                        0xac9650d8
//   - multicall(uint256 deadline, bytes[] data)                 0x5ae401dc
//   - multicallWithDeadline(uint256, bytes[])                   0x1f0464d1
//   - aggregate((address,bytes)[])  (UniV3 SwapRouter / MakerDAO multicall)
//
// We only emit envelopes for selectors PUSHed in the contract bytecode.

import { buildAbiCalldata, type ArgValue } from "../abi";

export type MulticallSurface = {
  selector: string;
  signature: string;
  /** How to build the envelope calldata given inner-drain bytes. */
  wrap(innerCalldataList: string[]): string;
};

const MULTICALL_SURFACES: MulticallSurface[] = [
  {
    selector: "0xac9650d8",
    signature: "multicall(bytes[])",
    wrap: (inner) => buildAbiCalldata("0xac9650d8", [{ kind: "bytes[]", value: inner }] as ArgValue[]),
  },
  {
    selector: "0x5ae401dc",
    signature: "multicall(uint256,bytes[])",
    // (deadline=max, bytes[])
    wrap: (inner) =>
      buildAbiCalldata("0x5ae401dc", [
        { kind: "uint", value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffn },
        { kind: "bytes[]", value: inner },
      ] as ArgValue[]),
  },
  {
    selector: "0x1f0464d1",
    signature: "multicallWithDeadline(uint256,bytes[])",
    wrap: (inner) =>
      buildAbiCalldata("0x1f0464d1", [
        { kind: "uint", value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffn },
        { kind: "bytes[]", value: inner },
      ] as ArgValue[]),
  },
];

/** Return the subset of MULTICALL_SURFACES whose selector is PUSHed in
 *  the given runtime bytecode. */
export function detectMulticallSurfaces(runtimeBytecode: string): MulticallSurface[] {
  if (!runtimeBytecode || runtimeBytecode === "0x") return [];
  const lower = runtimeBytecode.toLowerCase();
  return MULTICALL_SURFACES.filter((s) => lower.includes(s.selector.slice(2)));
}
