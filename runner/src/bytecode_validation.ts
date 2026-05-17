export type BytecodeValidationKind =
  | "proceed"
  | "skip_empty"
  | "skip_trivial"
  | "eof"
  | "skip_proxy_shell";

export interface BytecodeValidation {
  kind: BytecodeValidationKind;
  reason: string;
  shouldAudit: boolean;
  bytecodeBytes: number;
}

// EIP-1167 minimal proxy: exactly 45 bytes
// 363d3d373d3d3d363d73<20-byte-addr>5af43d82803e903d91602b57fd5bf3
const EIP1167_RE = /^363d3d373d3d3d363d73[0-9a-f]{40}5af43d82803e903d91602b57fd5bf3$/i;

export function validateBytecode(hex: string): BytecodeValidation {
  const raw = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;

  if (raw.length === 0) {
    return { kind: "skip_empty", reason: "empty_runtime_bytecode", shouldAudit: false, bytecodeBytes: 0 };
  }

  const byteLen = Math.floor(raw.length / 2);

  if (byteLen < 4) {
    return { kind: "skip_trivial", reason: `bytecode_too_short:${byteLen}_bytes`, shouldAudit: false, bytecodeBytes: byteLen };
  }

  // Self-destructed or zeroed-out contract — only applies when there is enough
  // content that all-zeros is meaningful (single STOP opcode 0x00 is trivial, not empty)
  if (/^0+$/.test(raw)) {
    return { kind: "skip_empty", reason: "all_zero_bytecode_self_destructed", shouldAudit: false, bytecodeBytes: byteLen };
  }

  // EIP-3541 EOF container
  if (raw.toLowerCase().startsWith("ef00")) {
    return { kind: "eof", reason: "eip3541_eof_container", shouldAudit: true, bytecodeBytes: byteLen };
  }

  // EIP-1167 minimal proxy shell (45 bytes)
  if (EIP1167_RE.test(raw)) {
    return { kind: "skip_proxy_shell", reason: "eip1167_minimal_proxy_shell", shouldAudit: false, bytecodeBytes: byteLen };
  }

  return { kind: "proceed", reason: "ok", shouldAudit: true, bytecodeBytes: byteLen };
}
