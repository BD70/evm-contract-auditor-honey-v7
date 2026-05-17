"""
Pattern detector for EVM bytecode.

Detects proxy patterns, security-relevant opcodes, ERC standard compliance,
and other structural patterns from disassembled bytecode.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from .disassembler import Instruction, DisassemblyResult
from .known_signatures import detect_standards


# EIP-1167 Minimal Proxy template (without the 20-byte address)
_EIP1167_PREFIX = bytes.fromhex("363d3d373d3d3d363d73")
_EIP1167_SUFFIX = bytes.fromhex("5af43d82803e903d91602b57fd5bf3")
_EIP1167_TOTAL_LENGTH = 45  # 10 + 20 + 15

# EIP-1967 implementation storage slot
_EIP1967_IMPL_SLOT = "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
_EIP1967_ADMIN_SLOT = "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
_EIP1967_BEACON_SLOT = "a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"


@dataclass
class ProxyInfo:
    is_proxy: bool
    proxy_type: Optional[str]  # "EIP-1167", "EIP-1967", "DELEGATECALL-based", None
    implementation_address: Optional[str]  # for EIP-1167
    details: dict = field(default_factory=dict)


@dataclass
class SecurityFlags:
    has_selfdestruct: bool
    has_delegatecall: bool
    has_callcode: bool
    has_create: bool
    has_create2: bool
    has_origin: bool       # tx.origin usage
    has_staticcall: bool
    has_send_or_transfer: bool  # heuristic
    selfdestruct_offsets: list[int] = field(default_factory=list)
    delegatecall_offsets: list[int] = field(default_factory=list)


@dataclass
class StringLiteral:
    offset: int
    value: str
    encoding: str  # "utf8", "ascii"
    length: int


@dataclass
class PatternResult:
    proxy: ProxyInfo
    security: SecurityFlags
    standards: list[dict]
    strings: list[StringLiteral]
    opcode_frequency: dict[str, int]
    opcode_categories: dict[str, int]  # category → count


def detect_patterns(
    disasm: DisassemblyResult,
    bytecode_hex: str,
    selector_set: set[str],
) -> PatternResult:
    """
    Run all pattern detectors on disassembled bytecode.

    Args:
        disasm: Disassembly result
        bytecode_hex: Original hex bytecode (for raw pattern matching)
        selector_set: Set of extracted function selectors (hex, no 0x prefix)
    """
    proxy = _detect_proxy(disasm, bytecode_hex)
    security = _detect_security_flags(disasm)
    standards = detect_standards(selector_set)
    strings = _extract_strings(bytecode_hex)
    opcode_freq = _compute_opcode_frequency(disasm)
    opcode_cats = _compute_category_frequency(disasm)

    return PatternResult(
        proxy=proxy,
        security=security,
        standards=standards,
        strings=strings,
        opcode_frequency=opcode_freq,
        opcode_categories=opcode_cats,
    )


def _detect_proxy(disasm: DisassemblyResult, bytecode_hex: str) -> ProxyInfo:
    """Detect proxy contract patterns."""

    hex_str = bytecode_hex.strip().lower()
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]

    try:
        bytecode = bytes.fromhex(hex_str)
    except ValueError:
        return ProxyInfo(is_proxy=False, proxy_type=None, implementation_address=None)

    # 1. EIP-1167 Minimal Proxy
    if len(bytecode) == _EIP1167_TOTAL_LENGTH:
        if (
            bytecode[:10] == _EIP1167_PREFIX
            and bytecode[30:] == _EIP1167_SUFFIX
        ):
            impl_addr = "0x" + bytecode[10:30].hex()
            return ProxyInfo(
                is_proxy=True,
                proxy_type="EIP-1167",
                implementation_address=impl_addr,
                details={"pattern": "minimal_proxy", "exact_match": True},
            )

    # Also check for EIP-1167 embedded in larger bytecode
    eip1167_idx = hex_str.find("363d3d373d3d3d363d73")
    if eip1167_idx >= 0:
        # Check if the suffix follows 20 bytes later
        addr_start = eip1167_idx + 20  # 10 bytes * 2 hex chars
        suffix_start = addr_start + 40  # 20 bytes * 2 hex chars
        expected_suffix = "5af43d82803e903d91602b57fd5bf3"
        if hex_str[suffix_start:suffix_start + len(expected_suffix)] == expected_suffix:
            impl_addr = "0x" + hex_str[addr_start:addr_start + 40]
            return ProxyInfo(
                is_proxy=True,
                proxy_type="EIP-1167",
                implementation_address=impl_addr,
                details={"pattern": "minimal_proxy", "embedded": True},
            )

    # 2. EIP-1967 storage slot pattern
    has_eip1967 = False
    for inst in disasm.instructions:
        if inst.opcode == "PUSH32" and inst.operand:
            operand = inst.operand.lower().replace("0x", "")
            if operand == _EIP1967_IMPL_SLOT:
                has_eip1967 = True
                break
            if operand == _EIP1967_ADMIN_SLOT:
                has_eip1967 = True
                break
            if operand == _EIP1967_BEACON_SLOT:
                has_eip1967 = True
                break

    if has_eip1967:
        # Check for DELEGATECALL
        has_delegatecall = any(i.opcode == "DELEGATECALL" for i in disasm.instructions)
        if has_delegatecall:
            return ProxyInfo(
                is_proxy=True,
                proxy_type="EIP-1967",
                implementation_address=None,  # stored in slot, can't read from bytecode alone
                details={"pattern": "upgradeable_proxy", "slot_detected": True},
            )

    # 3. Generic DELEGATECALL-based proxy heuristic
    # If contract is small and has DELEGATECALL, it's likely a proxy
    has_delegatecall = any(i.opcode == "DELEGATECALL" for i in disasm.instructions)
    if has_delegatecall and disasm.bytecode_size < 500:
        return ProxyInfo(
            is_proxy=True,
            proxy_type="DELEGATECALL-based",
            implementation_address=None,
            details={"pattern": "generic_proxy", "heuristic": True},
        )

    return ProxyInfo(is_proxy=False, proxy_type=None, implementation_address=None)


def _detect_security_flags(disasm: DisassemblyResult) -> SecurityFlags:
    """Detect security-relevant opcodes."""

    selfdestruct_offsets = []
    delegatecall_offsets = []
    flags = {
        "selfdestruct": False,
        "delegatecall": False,
        "callcode": False,
        "create": False,
        "create2": False,
        "origin": False,
        "staticcall": False,
        "send_transfer": False,
    }

    for inst in disasm.instructions:
        if inst.opcode == "SELFDESTRUCT":
            flags["selfdestruct"] = True
            selfdestruct_offsets.append(inst.offset)
        elif inst.opcode == "DELEGATECALL":
            flags["delegatecall"] = True
            delegatecall_offsets.append(inst.offset)
        elif inst.opcode == "CALLCODE":
            flags["callcode"] = True
        elif inst.opcode == "CREATE":
            flags["create"] = True
        elif inst.opcode == "CREATE2":
            flags["create2"] = True
        elif inst.opcode == "ORIGIN":
            flags["origin"] = True
        elif inst.opcode == "STATICCALL":
            flags["staticcall"] = True
        elif inst.opcode == "CALL":
            # Heuristic: if CALL is preceded by PUSH with gas=2300, it's send/transfer
            idx = disasm.instructions.index(inst)
            if idx >= 1:
                prev = disasm.instructions[idx - 1]
                if prev.opcode in ("PUSH2", "PUSH3") and prev.operand_value == 2300:
                    flags["send_transfer"] = True

    return SecurityFlags(
        has_selfdestruct=flags["selfdestruct"],
        has_delegatecall=flags["delegatecall"],
        has_callcode=flags["callcode"],
        has_create=flags["create"],
        has_create2=flags["create2"],
        has_origin=flags["origin"],
        has_staticcall=flags["staticcall"],
        has_send_or_transfer=flags["send_transfer"],
        selfdestruct_offsets=selfdestruct_offsets,
        delegatecall_offsets=delegatecall_offsets,
    )


def _extract_strings(bytecode_hex: str) -> list[StringLiteral]:
    """
    Extract embedded string literals from bytecode.

    Solidity stores string literals as PUSH32 sequences or in memory.
    We use a heuristic: look for sequences of printable ASCII bytes >= 4 chars.
    """
    hex_str = bytecode_hex.strip().lower()
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]

    try:
        raw = bytes.fromhex(hex_str)
    except ValueError:
        return []

    strings = []
    current = bytearray()
    start_offset = 0

    for i, b in enumerate(raw):
        if 0x20 <= b <= 0x7e:  # printable ASCII
            if not current:
                start_offset = i
            current.append(b)
        else:
            if len(current) >= 6:  # minimum 6 chars to avoid noise
                text = current.decode("ascii")
                # Filter out hex-looking strings and obvious noise
                if not all(c in "0123456789abcdef" for c in text.lower()):
                    strings.append(StringLiteral(
                        offset=start_offset,
                        value=text,
                        encoding="ascii",
                        length=len(text),
                    ))
            current = bytearray()

    # Don't forget trailing
    if len(current) >= 6:
        text = current.decode("ascii")
        if not all(c in "0123456789abcdef" for c in text.lower()):
            strings.append(StringLiteral(
                offset=start_offset,
                value=text,
                encoding="ascii",
                length=len(text),
            ))

    return strings


def _compute_opcode_frequency(disasm: DisassemblyResult) -> dict[str, int]:
    """Compute frequency of each opcode."""
    freq: dict[str, int] = {}
    for inst in disasm.instructions:
        freq[inst.opcode] = freq.get(inst.opcode, 0) + 1
    return dict(sorted(freq.items(), key=lambda x: -x[1]))


def _compute_category_frequency(disasm: DisassemblyResult) -> dict[str, int]:
    """Compute frequency by opcode category."""
    freq: dict[str, int] = {}
    for inst in disasm.instructions:
        cat = inst.info.category
        freq[cat] = freq.get(cat, 0) + 1
    return dict(sorted(freq.items(), key=lambda x: -x[1]))
