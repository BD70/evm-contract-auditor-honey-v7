"""
Complete EVM opcode table.

Each opcode maps to: (mnemonic, stack_inputs, stack_outputs, inline_data_bytes, description)
Covers all opcodes through Shanghai/Cancun (PUSH0, TLOAD, TSTORE, MCOPY, BLOBHASH, BLOBBASEFEE).
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class OpcodeInfo:
    hex: int
    mnemonic: str
    stack_in: int
    stack_out: int
    data_bytes: int  # number of inline bytes consumed (only PUSH1-PUSH32 have >0)
    description: str
    category: str  # e.g. "arithmetic", "stack", "memory", "storage", "flow", "system", "log", "push", "dup", "swap", "env"


# fmt: off
OPCODES: dict[int, OpcodeInfo] = {}

def _op(hex_val: int, name: str, si: int, so: int, db: int, desc: str, cat: str):
    OPCODES[hex_val] = OpcodeInfo(hex_val, name, si, so, db, desc, cat)

# ── Stop & Arithmetic ────────────────────────────────────────────
_op(0x00, "STOP",         0, 0, 0, "Halts execution",                              "flow")
_op(0x01, "ADD",          2, 1, 0, "Addition",                                      "arithmetic")
_op(0x02, "MUL",          2, 1, 0, "Multiplication",                                "arithmetic")
_op(0x03, "SUB",          2, 1, 0, "Subtraction",                                   "arithmetic")
_op(0x04, "DIV",          2, 1, 0, "Integer division",                               "arithmetic")
_op(0x05, "SDIV",         2, 1, 0, "Signed integer division",                        "arithmetic")
_op(0x06, "MOD",          2, 1, 0, "Modulo remainder",                               "arithmetic")
_op(0x07, "SMOD",         2, 1, 0, "Signed modulo remainder",                        "arithmetic")
_op(0x08, "ADDMOD",       3, 1, 0, "Modular addition",                               "arithmetic")
_op(0x09, "MULMOD",       3, 1, 0, "Modular multiplication",                          "arithmetic")
_op(0x0A, "EXP",          2, 1, 0, "Exponentiation",                                 "arithmetic")
_op(0x0B, "SIGNEXTEND",   2, 1, 0, "Extend length of signed integer",                "arithmetic")

# ── Comparison & Bitwise Logic ────────────────────────────────────
_op(0x10, "LT",           2, 1, 0, "Less-than comparison",                            "comparison")
_op(0x11, "GT",           2, 1, 0, "Greater-than comparison",                          "comparison")
_op(0x12, "SLT",          2, 1, 0, "Signed less-than",                                "comparison")
_op(0x13, "SGT",          2, 1, 0, "Signed greater-than",                              "comparison")
_op(0x14, "EQ",           2, 1, 0, "Equality check",                                   "comparison")
_op(0x15, "ISZERO",       1, 1, 0, "Is zero",                                          "comparison")
_op(0x16, "AND",          2, 1, 0, "Bitwise AND",                                      "bitwise")
_op(0x17, "OR",           2, 1, 0, "Bitwise OR",                                       "bitwise")
_op(0x18, "XOR",          2, 1, 0, "Bitwise XOR",                                      "bitwise")
_op(0x19, "NOT",          1, 1, 0, "Bitwise NOT",                                      "bitwise")
_op(0x1A, "BYTE",         2, 1, 0, "Retrieve single byte from word",                   "bitwise")
_op(0x1B, "SHL",          2, 1, 0, "Shift left",                                       "bitwise")
_op(0x1C, "SHR",          2, 1, 0, "Logical shift right",                              "bitwise")
_op(0x1D, "SAR",          2, 1, 0, "Arithmetic shift right",                           "bitwise")

# ── Keccak256 ─────────────────────────────────────────────────────
_op(0x20, "KECCAK256",    2, 1, 0, "Compute Keccak-256 hash",                          "crypto")

# ── Environmental Information ─────────────────────────────────────
_op(0x30, "ADDRESS",      0, 1, 0, "Get address of current contract",                  "env")
_op(0x31, "BALANCE",      1, 1, 0, "Get balance of account",                           "env")
_op(0x32, "ORIGIN",       0, 1, 0, "Get execution origination address (tx.origin)",    "env")
_op(0x33, "CALLER",       0, 1, 0, "Get caller address (msg.sender)",                  "env")
_op(0x34, "CALLVALUE",    0, 1, 0, "Get deposited value (msg.value)",                  "env")
_op(0x35, "CALLDATALOAD", 1, 1, 0, "Load input data (calldata)",                       "env")
_op(0x36, "CALLDATASIZE", 0, 1, 0, "Get size of input data",                           "env")
_op(0x37, "CALLDATACOPY", 3, 0, 0, "Copy input data to memory",                        "env")
_op(0x38, "CODESIZE",     0, 1, 0, "Get size of code",                                 "env")
_op(0x39, "CODECOPY",     3, 0, 0, "Copy code to memory",                              "env")
_op(0x3A, "GASPRICE",     0, 1, 0, "Get gas price",                                    "env")
_op(0x3B, "EXTCODESIZE",  1, 1, 0, "Get size of external code",                        "env")
_op(0x3C, "EXTCODECOPY",  4, 0, 0, "Copy external code to memory",                     "env")
_op(0x3D, "RETURNDATASIZE", 0, 1, 0, "Get size of return data",                        "env")
_op(0x3E, "RETURNDATACOPY", 3, 0, 0, "Copy return data to memory",                     "env")
_op(0x3F, "EXTCODEHASH",  1, 1, 0, "Get hash of external code",                        "env")

# ── Block Information ─────────────────────────────────────────────
_op(0x40, "BLOCKHASH",    1, 1, 0, "Get block hash",                                   "block")
_op(0x41, "COINBASE",     0, 1, 0, "Get block's beneficiary address",                  "block")
_op(0x42, "TIMESTAMP",    0, 1, 0, "Get block's timestamp",                            "block")
_op(0x43, "NUMBER",       0, 1, 0, "Get block's number",                               "block")
_op(0x44, "PREVRANDAO",   0, 1, 0, "Get previous RANDAO value (was DIFFICULTY)",        "block")
_op(0x45, "GASLIMIT",     0, 1, 0, "Get block's gas limit",                            "block")
_op(0x46, "CHAINID",      0, 1, 0, "Get chain ID",                                     "block")
_op(0x47, "SELFBALANCE",  0, 1, 0, "Get balance of current contract",                  "block")
_op(0x48, "BASEFEE",      0, 1, 0, "Get block's base fee",                             "block")
_op(0x49, "BLOBHASH",     1, 1, 0, "Get versioned hash of blob (Cancun)",              "block")
_op(0x4A, "BLOBBASEFEE",  0, 1, 0, "Get blob base fee (Cancun)",                       "block")

# ── Stack, Memory, Storage, Flow ──────────────────────────────────
_op(0x50, "POP",          1, 0, 0, "Remove item from stack",                            "stack")
_op(0x51, "MLOAD",        1, 1, 0, "Load word from memory",                             "memory")
_op(0x52, "MSTORE",       2, 0, 0, "Store word to memory",                              "memory")
_op(0x53, "MSTORE8",      2, 0, 0, "Store byte to memory",                              "memory")
_op(0x54, "SLOAD",        1, 1, 0, "Load word from storage",                            "storage")
_op(0x55, "SSTORE",       2, 0, 0, "Store word to storage",                             "storage")
_op(0x56, "JUMP",         1, 0, 0, "Unconditional jump",                                "flow")
_op(0x57, "JUMPI",        2, 0, 0, "Conditional jump",                                  "flow")
_op(0x58, "PC",           0, 1, 0, "Get program counter",                               "flow")
_op(0x59, "MSIZE",        0, 1, 0, "Get size of active memory",                         "memory")
_op(0x5A, "GAS",          0, 1, 0, "Get remaining gas",                                 "env")
_op(0x5B, "JUMPDEST",     0, 0, 0, "Mark valid jump destination",                       "flow")
_op(0x5C, "TLOAD",        1, 1, 0, "Load from transient storage (Cancun)",              "storage")
_op(0x5D, "TSTORE",       2, 0, 0, "Store to transient storage (Cancun)",               "storage")
_op(0x5E, "MCOPY",        3, 0, 0, "Copy memory areas (Cancun)",                        "memory")

# ── Push Operations ───────────────────────────────────────────────
_op(0x5F, "PUSH0",        0, 1, 0, "Push zero onto stack (Shanghai)",                   "push")

for i in range(1, 33):
    _op(0x5F + i, f"PUSH{i}", 0, 1, i, f"Push {i}-byte value onto stack",              "push")

# ── Dup Operations ────────────────────────────────────────────────
for i in range(1, 17):
    _op(0x7F + i, f"DUP{i}",  i, i + 1, 0, f"Duplicate {i}th stack item",              "dup")

# ── Swap Operations ───────────────────────────────────────────────
for i in range(1, 17):
    _op(0x8F + i, f"SWAP{i}", i + 1, i + 1, 0, f"Swap top with {i+1}th stack item",    "swap")

# ── Log Operations ────────────────────────────────────────────────
for i in range(5):
    _op(0xA0 + i, f"LOG{i}",  i + 2, 0, 0, f"Append log record with {i} topics",       "log")

# ── System Operations ─────────────────────────────────────────────
_op(0xF0, "CREATE",        3, 1, 0, "Create a new contract",                             "system")
_op(0xF1, "CALL",          7, 1, 0, "Message-call into an account",                      "system")
_op(0xF2, "CALLCODE",      7, 1, 0, "Message-call with another account's code",          "system")
_op(0xF3, "RETURN",        2, 0, 0, "Halt execution returning data",                     "flow")
_op(0xF4, "DELEGATECALL",  6, 1, 0, "Delegate call (preserves sender/value)",            "system")
_op(0xF5, "CREATE2",       4, 1, 0, "Create contract with deterministic address",        "system")
_op(0xFA, "STATICCALL",    6, 1, 0, "Static message-call (read-only)",                   "system")
_op(0xFD, "REVERT",        2, 0, 0, "Halt execution, revert state changes",              "flow")
_op(0xFE, "INVALID",       0, 0, 0, "Designated invalid instruction",                    "flow")
_op(0xFF, "SELFDESTRUCT",  1, 0, 0, "Halt and register for deletion",                    "system")
# fmt: on


def lookup(opcode_byte: int) -> OpcodeInfo:
    """Look up an opcode by its byte value. Returns INVALID info for unknown opcodes."""
    if opcode_byte in OPCODES:
        return OPCODES[opcode_byte]
    return OpcodeInfo(
        hex=opcode_byte,
        mnemonic=f"UNKNOWN_0x{opcode_byte:02x}",
        stack_in=0,
        stack_out=0,
        data_bytes=0,
        description=f"Unknown opcode 0x{opcode_byte:02x}",
        category="unknown",
    )


# Set of opcodes that terminate a basic block
BLOCK_TERMINATORS = frozenset({
    "STOP", "JUMP", "JUMPI", "RETURN", "REVERT", "INVALID", "SELFDESTRUCT"
})

# Set of opcodes that are block entry points
BLOCK_ENTRIES = frozenset({"JUMPDEST"})
