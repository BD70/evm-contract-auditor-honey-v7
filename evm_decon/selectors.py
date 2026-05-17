"""
Function selector extraction from bytecode dispatcher.

Scans disassembled instructions for the function selector dispatch pattern
that Solidity (and other compilers) generate at the start of contract bytecode.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from .disassembler import Instruction, DisassemblyResult


@dataclass
class FunctionEntry:
    selector: str          # e.g. "0xa9059cbb"
    selector_value: int    # integer value of selector
    jump_target: Optional[int]   # JUMPDEST offset this selector routes to
    instruction_offset: int      # offset of the PUSH4 instruction


@dataclass
class DispatcherInfo:
    type: str                     # "linear_switch", "binary_search", "unknown"
    start_offset: int
    end_offset: int
    num_branches: int
    has_fallback: bool
    fallback_offset: Optional[int]
    has_receive: bool              # special case: no selector = receive()


@dataclass
class SelectorResult:
    selectors: list[FunctionEntry]
    dispatcher: Optional[DispatcherInfo]
    errors: list[str] = field(default_factory=list)


def extract_selectors(disasm: DisassemblyResult) -> SelectorResult:
    """
    Extract function selectors from the dispatcher pattern in disassembled bytecode.

    Handles these dispatcher patterns:
    1. DUP1 PUSH4 <sel> EQ PUSH2 <dest> JUMPI  (common Solidity)
    2. PUSH4 <sel> EQ PUSH2 <dest> JUMPI        (simplified)
    3. PUSH4 <sel> DUP2 EQ PUSH2 <dest> JUMPI   (alternative)
    """
    instructions = disasm.instructions
    selectors: list[FunctionEntry] = []
    seen_selectors: set[int] = set()
    errors: list[str] = []

    dispatcher_start = 0
    dispatcher_end = 0
    fallback_offset = None
    has_receive = False

    i = 0
    in_dispatcher = False

    while i < len(instructions):
        inst = instructions[i]

        # Pattern 1: DUP1 PUSH4 <sel> EQ PUSH1/PUSH2 <dest> JUMPI
        if (
            inst.opcode == "DUP1"
            and i + 4 < len(instructions)
            and instructions[i + 1].opcode == "PUSH4"
            and instructions[i + 2].opcode == "EQ"
            and instructions[i + 3].opcode in ("PUSH1", "PUSH2", "PUSH3")
            and instructions[i + 4].opcode == "JUMPI"
        ):
            sel_val = instructions[i + 1].operand_value
            jump_dest = instructions[i + 3].operand_value

            if sel_val is not None and sel_val not in seen_selectors:
                selectors.append(FunctionEntry(
                    selector=f"0x{sel_val:08x}",
                    selector_value=sel_val,
                    jump_target=jump_dest,
                    instruction_offset=instructions[i + 1].offset,
                ))
                seen_selectors.add(sel_val)

            if not in_dispatcher:
                in_dispatcher = True
                dispatcher_start = inst.offset
            dispatcher_end = instructions[i + 4].offset + instructions[i + 4].size

            i += 5
            continue

        # Pattern 2: PUSH4 <sel> EQ PUSH1/PUSH2 <dest> JUMPI
        if (
            inst.opcode == "PUSH4"
            and i + 3 < len(instructions)
            and instructions[i + 1].opcode == "EQ"
            and instructions[i + 2].opcode in ("PUSH1", "PUSH2", "PUSH3")
            and instructions[i + 3].opcode == "JUMPI"
        ):
            sel_val = inst.operand_value
            jump_dest = instructions[i + 2].operand_value

            if sel_val is not None and sel_val not in seen_selectors:
                selectors.append(FunctionEntry(
                    selector=f"0x{sel_val:08x}",
                    selector_value=sel_val,
                    jump_target=jump_dest,
                    instruction_offset=inst.offset,
                ))
                seen_selectors.add(sel_val)

            if not in_dispatcher:
                in_dispatcher = True
                dispatcher_start = inst.offset
            dispatcher_end = instructions[i + 3].offset + instructions[i + 3].size

            i += 4
            continue

        # Pattern 3: PUSH4 <sel> DUP2 EQ PUSH1/PUSH2 <dest> JUMPI
        if (
            inst.opcode == "PUSH4"
            and i + 4 < len(instructions)
            and instructions[i + 1].opcode == "DUP2"
            and instructions[i + 2].opcode == "EQ"
            and instructions[i + 3].opcode in ("PUSH1", "PUSH2", "PUSH3")
            and instructions[i + 4].opcode == "JUMPI"
        ):
            sel_val = inst.operand_value
            jump_dest = instructions[i + 3].operand_value

            if sel_val is not None and sel_val not in seen_selectors:
                selectors.append(FunctionEntry(
                    selector=f"0x{sel_val:08x}",
                    selector_value=sel_val,
                    jump_target=jump_dest,
                    instruction_offset=inst.offset,
                ))
                seen_selectors.add(sel_val)

            if not in_dispatcher:
                in_dispatcher = True
                dispatcher_start = inst.offset
            dispatcher_end = instructions[i + 4].offset + instructions[i + 4].size

            i += 5
            continue

        # Detect fallback: after dispatcher, a JUMP or JUMPI to a fallback
        if in_dispatcher and inst.opcode in ("JUMP", "JUMPI", "STOP", "REVERT"):
            if inst.opcode == "JUMP" and i > 0:
                prev = instructions[i - 1]
                if prev.opcode in ("PUSH1", "PUSH2") and prev.operand_value is not None:
                    fallback_offset = prev.operand_value
            # Dispatcher ends after last selector check
            in_dispatcher = False

        i += 1

    # Check for receive function pattern (calldatasize is 0 → receive)
    for j, inst in enumerate(instructions[:20]):  # only check early instructions
        if (
            inst.opcode == "CALLDATASIZE"
            and j + 2 < len(instructions)
            and instructions[j + 1].opcode == "ISZERO"
        ):
            has_receive = True
            break

    # Build dispatcher info
    dispatcher_info = None
    if selectors:
        dispatcher_info = DispatcherInfo(
            type="linear_switch",  # We only detect linear for now
            start_offset=dispatcher_start,
            end_offset=dispatcher_end,
            num_branches=len(selectors),
            has_fallback=fallback_offset is not None,
            fallback_offset=fallback_offset,
            has_receive=has_receive,
        )

    return SelectorResult(
        selectors=selectors,
        dispatcher=dispatcher_info,
        errors=errors,
    )
