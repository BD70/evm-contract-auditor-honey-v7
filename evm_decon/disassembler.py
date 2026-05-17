"""
Linear sweep disassembler for EVM bytecode.

Converts raw hex bytecode into a structured list of instructions.
Handles variable-length PUSH instructions and annotates well-known patterns.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

from .opcodes import lookup, OpcodeInfo
from .keccak import keccak256_hex


@dataclass
class Instruction:
    offset: int           # byte offset in bytecode
    opcode: str           # mnemonic (e.g. "PUSH1", "ADD")
    opcode_byte: int      # raw opcode byte value
    operand: Optional[str]  # hex string of operand (for PUSH only), e.g. "0x80"
    operand_value: Optional[int]  # integer value of operand
    raw: str              # raw hex bytes of entire instruction
    size: int             # total bytes consumed (opcode + operand)
    info: OpcodeInfo      # full opcode metadata
    annotation: Optional[str] = None  # human-readable note

    def __repr__(self):
        op_str = f" {self.operand}" if self.operand else ""
        ann = f"  ; {self.annotation}" if self.annotation else ""
        return f"0x{self.offset:04x}: {self.opcode}{op_str}{ann}"


@dataclass
class DisassemblyResult:
    instructions: list[Instruction]
    bytecode_size: int
    bytecode_hash: str     # Ethereum Keccak-256 hash
    errors: list[str] = field(default_factory=list)


def disassemble(bytecode_hex: str) -> DisassemblyResult:
    """
    Disassemble EVM bytecode from a hex string.

    Args:
        bytecode_hex: Hex string of bytecode, with or without '0x' prefix.

    Returns:
        DisassemblyResult with list of Instruction objects.
    """
    # Normalize
    hex_str = bytecode_hex.strip()
    if hex_str.startswith("0x") or hex_str.startswith("0X"):
        hex_str = hex_str[2:]

    # Remove any whitespace/newlines
    hex_str = hex_str.replace(" ", "").replace("\n", "").replace("\r", "")

    # Validate hex
    if len(hex_str) % 2 != 0:
        hex_str = "0" + hex_str  # pad if odd length

    try:
        bytecode = bytes.fromhex(hex_str)
    except ValueError as e:
        return DisassemblyResult(
            instructions=[],
            bytecode_size=0,
            bytecode_hash="",
            errors=[f"Invalid hex input: {e}"],
        )

    # EIP-3541 EOF container — 0xEF00 prefix marks bytecode the legacy
    # disassembler cannot safely parse. Return early with a structured error
    # so the pipeline knows to skip CFG/sim/storage steps.
    if len(bytecode) >= 2 and bytecode[0] == 0xEF and bytecode[1] == 0x00:
        bc_hash = "0x" + keccak256_hex(bytecode)
        eof_version = bytecode[2] if len(bytecode) > 2 else 0
        return DisassemblyResult(
            instructions=[],
            bytecode_size=len(bytecode),
            bytecode_hash=bc_hash,
            errors=[f"eof_format_detected:version=0x{eof_version:02x}"],
        )

    # Ethereum bytecode identity uses Keccak-256, not SHA-256/NIST SHA3.
    bc_hash = "0x" + keccak256_hex(bytecode)

    instructions: list[Instruction] = []
    errors: list[str] = []
    pc = 0

    while pc < len(bytecode):
        opcode_byte = bytecode[pc]
        info = lookup(opcode_byte)

        if info.data_bytes > 0:
            # PUSH instruction — read inline data
            data_start = pc + 1
            data_end = data_start + info.data_bytes

            if data_end > len(bytecode):
                # Truncated PUSH — bytecode ends mid-instruction
                remaining = bytecode[data_start:]
                operand_hex = "0x" + remaining.hex()
                operand_val = int.from_bytes(remaining, "big") if remaining else 0
                raw_hex = bytecode[pc:len(bytecode)].hex()
                errors.append(
                    f"Truncated {info.mnemonic} at offset 0x{pc:04x}: "
                    f"expected {info.data_bytes} bytes, got {len(remaining)}"
                )
                instructions.append(Instruction(
                    offset=pc,
                    opcode=info.mnemonic,
                    opcode_byte=opcode_byte,
                    operand=operand_hex,
                    operand_value=operand_val,
                    raw=raw_hex,
                    size=1 + len(remaining),
                    info=info,
                ))
                pc = len(bytecode)
            else:
                operand_bytes = bytecode[data_start:data_end]
                operand_hex = "0x" + operand_bytes.hex()
                operand_val = int.from_bytes(operand_bytes, "big")
                raw_hex = bytecode[pc:data_end].hex()

                instructions.append(Instruction(
                    offset=pc,
                    opcode=info.mnemonic,
                    opcode_byte=opcode_byte,
                    operand=operand_hex,
                    operand_value=operand_val,
                    raw=raw_hex,
                    size=1 + info.data_bytes,
                    info=info,
                ))
                pc = data_end
        else:
            # Single-byte instruction (including PUSH0 which has data_bytes=0)
            raw_hex = f"{opcode_byte:02x}"
            operand = None
            operand_val = None

            # PUSH0 special case — operand is implicitly 0
            if info.mnemonic == "PUSH0":
                operand = "0x00"
                operand_val = 0

            instructions.append(Instruction(
                offset=pc,
                opcode=info.mnemonic,
                opcode_byte=opcode_byte,
                operand=operand,
                operand_value=operand_val,
                raw=raw_hex,
                size=1,
                info=info,
            ))
            pc += 1

    # Annotate well-known patterns
    _annotate_patterns(instructions)

    return DisassemblyResult(
        instructions=instructions,
        bytecode_size=len(bytecode),
        bytecode_hash=bc_hash,
        errors=errors,
    )


def _annotate_patterns(instructions: list[Instruction]):
    """Add human-readable annotations for well-known EVM patterns."""

    for i, inst in enumerate(instructions):
        # Free memory pointer initialization: PUSH1 0x80 PUSH1 0x40 MSTORE
        if (
            inst.opcode == "PUSH1"
            and inst.operand_value == 0x80
            and i + 2 < len(instructions)
            and instructions[i + 1].opcode == "PUSH1"
            and instructions[i + 1].operand_value == 0x40
            and instructions[i + 2].opcode == "MSTORE"
        ):
            inst.annotation = "free memory pointer init"
            instructions[i + 2].annotation = "store free memory pointer"

        # Non-payable check: CALLVALUE DUP1 ISZERO ... JUMPI
        if inst.opcode == "CALLVALUE" and i + 1 < len(instructions):
            next_inst = instructions[i + 1]
            if next_inst.opcode in ("DUP1", "ISZERO"):
                inst.annotation = "non-payable check (msg.value == 0)"

        # Selector extraction: PUSH1 0xe0 SHR (or PUSH1 0xe0 PUSH1 0x02 EXP ...)
        if (
            inst.opcode in ("PUSH1", "PUSH2")
            and inst.operand_value == 0xE0
            and i + 1 < len(instructions)
            and instructions[i + 1].opcode == "SHR"
        ):
            inst.annotation = "extract function selector (calldata >> 224)"

        # Function selector comparison: PUSH4 ... EQ
        if inst.opcode == "PUSH4" and i + 1 < len(instructions):
            if instructions[i + 1].opcode == "EQ":
                inst.annotation = f"function selector comparison"
            elif (
                i + 2 < len(instructions)
                and instructions[i + 1].opcode == "DUP2"
                and instructions[i + 2].opcode == "EQ"
            ):
                inst.annotation = f"function selector comparison"

        # JUMPDEST after dispatcher
        if inst.opcode == "JUMPDEST":
            inst.annotation = f"jump target"

        # Revert with reason
        if inst.opcode == "REVERT":
            inst.annotation = "revert execution"

        # Return
        if inst.opcode == "RETURN":
            inst.annotation = "return data"

        # SELFDESTRUCT warning
        if inst.opcode == "SELFDESTRUCT":
            inst.annotation = "⚠️ CONTRACT SELF-DESTRUCT"

        # DELEGATECALL indicator
        if inst.opcode == "DELEGATECALL":
            inst.annotation = "⚠️ DELEGATECALL (proxy pattern)"

        # CREATE / CREATE2
        if inst.opcode == "CREATE":
            inst.annotation = "deploy child contract"
        if inst.opcode == "CREATE2":
            inst.annotation = "deploy child contract (deterministic address)"

        # ORIGIN check
        if inst.opcode == "ORIGIN":
            inst.annotation = "⚠️ tx.origin (avoid for auth)"

        # SSTORE / SLOAD
        if inst.opcode == "SSTORE":
            inst.annotation = "write to storage"
        if inst.opcode == "SLOAD":
            inst.annotation = "read from storage"


def compute_opcode_frequency(result: DisassemblyResult) -> dict[str, int]:
    """Compute frequency of each opcode in the disassembly."""
    freq: dict[str, int] = {}
    for inst in result.instructions:
        freq[inst.opcode] = freq.get(inst.opcode, 0) + 1
    return dict(sorted(freq.items(), key=lambda x: -x[1]))
