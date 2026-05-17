import { describe, expect, test } from "bun:test";
import { validateBytecode } from "../src/bytecode_validation.js";

describe("validateBytecode", () => {
  test("empty hex string → skip_empty", () => {
    const r = validateBytecode("0x");
    expect(r.kind).toBe("skip_empty");
    expect(r.shouldAudit).toBe(false);
  });

  test("empty string without prefix → skip_empty", () => {
    const r = validateBytecode("");
    expect(r.kind).toBe("skip_empty");
    expect(r.shouldAudit).toBe(false);
  });

  test("all-zero bytecode (self-destructed) → skip_empty", () => {
    const r = validateBytecode("0x0000000000000000");
    expect(r.kind).toBe("skip_empty");
    expect(r.shouldAudit).toBe(false);
  });

  test("single zero byte → skip_trivial (< 4 bytes, not skip_empty)", () => {
    // 0x00 is a STOP opcode — 1 byte — too short to audit, but not the same as
    // a self-destructed contract (which has >= 4 bytes all-zero)
    const r = validateBytecode("0x00");
    expect(r.kind).toBe("skip_trivial");
    expect(r.shouldAudit).toBe(false);
  });

  test("3-byte bytecode → skip_trivial", () => {
    const r = validateBytecode("0x600000");
    expect(r.kind).toBe("skip_trivial");
    expect(r.shouldAudit).toBe(false);
  });

  test("4-byte bytecode → proceed", () => {
    const r = validateBytecode("0x60806040");
    expect(r.kind).toBe("proceed");
    expect(r.shouldAudit).toBe(true);
    expect(r.bytecodeBytes).toBe(4);
  });

  test("EIP-3541 EOF prefix 0xEF00 → eof (shouldAudit=true)", () => {
    const r = validateBytecode("0xef000101000402000100010400000000800001e4");
    expect(r.kind).toBe("eof");
    expect(r.shouldAudit).toBe(true);
  });

  test("EIP-3541 EOF prefix case-insensitive", () => {
    const r = validateBytecode("0xEF00010100");
    expect(r.kind).toBe("eof");
  });

  test("EIP-1167 minimal proxy (45 bytes) → skip_proxy_shell", () => {
    // canonical 45-byte EIP-1167 with a valid-ish implementation address
    const impl = "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"; // USDC address
    const eip1167 = `363d3d373d3d3d363d73${impl}5af43d82803e903d91602b57fd5bf3`;
    expect(eip1167.length / 2).toBe(45);
    const r = validateBytecode(`0x${eip1167}`);
    expect(r.kind).toBe("skip_proxy_shell");
    expect(r.shouldAudit).toBe(false);
    expect(r.bytecodeBytes).toBe(45);
  });

  test("EIP-1167 pattern with wrong address length → proceed (not matched)", () => {
    // Truncated address — not a valid EIP-1167
    const bad = "363d3d373d3d3d363d73" + "aa".repeat(19) + "5af43d82803e903d91602b57fd5bf3";
    const r = validateBytecode(`0x${bad}`);
    expect(r.kind).not.toBe("skip_proxy_shell");
  });

  test("normal runtime bytecode → proceed", () => {
    // Typical short contract bytecode
    const r = validateBytecode("0x6080604052600436106100295760003560e01c80638da5cb5b1461002e575b600080fd5b");
    expect(r.kind).toBe("proceed");
    expect(r.shouldAudit).toBe(true);
  });

  test("bytecodeBytes reflects correct byte length", () => {
    const r = validateBytecode("0x6080604052");
    expect(r.bytecodeBytes).toBe(5);
  });

  test("hex without 0x prefix works", () => {
    const r = validateBytecode("6080604052");
    expect(r.kind).toBe("proceed");
    expect(r.bytecodeBytes).toBe(5);
  });
});
