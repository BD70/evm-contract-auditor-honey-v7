"""
ABI / Type recovery from bytecode patterns.

Infers function attributes (mutability, argument count, types, return types)
purely from bytecode analysis — no ABI JSON needed.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from .blocks import BasicBlock, BlockAnalysis
from .stack_sim import SimulationResult, BlockTrace
from .function_slicer import FunctionUnit, FunctionSliceResult

# Solidity functions never have more than ~32 calldata-word arguments.
# Any inferred count above this is a symbolic/hash-derived offset artifact.
MAX_SANE_ARG_COUNT = 32
# Maximum reasonable calldata byte offset (32 * MAX_ARGS + 4 selector bytes)
MAX_SANE_CALLDATA_OFFSET = 4 + MAX_SANE_ARG_COUNT * 32


@dataclass
class RecoveredABI:
    """Recovered ABI information for a single function."""
    selector: str
    name: Optional[str]
    mutability: str                    # "nonpayable", "view", "payable", "pure"
    arg_count: int
    arg_types: list[str]               # ["address", "uint256", ...]
    return_type: Optional[str]         # "bool", "uint256", "address", "string", "bytes", None
    has_return: bool
    confidence: float
    evidence: list[str]


def recover_abi(
    slice_result: FunctionSliceResult,
    block_analysis: BlockAnalysis,
    sim_result: SimulationResult,
) -> list[RecoveredABI]:
    """
    Recover ABI information for all sliced functions.
    """
    block_map = {b.id: b for b in block_analysis.blocks}
    results = []

    for func in slice_result.functions:
        abi = _recover_function_abi(func, block_map, sim_result)
        results.append(abi)

        # Also update the FunctionUnit with recovered info
        func.mutability = abi.mutability
        func.arg_count = abi.arg_count

    return results


def _recover_function_abi(
    func: FunctionUnit,
    block_map: dict[int, BasicBlock],
    sim_result: SimulationResult,
) -> RecoveredABI:
    """Recover ABI for a single function."""
    evidence: list[str] = []
    
    # Collect all instructions and traces for this function's blocks
    all_opcodes = set()
    has_sstore = False
    has_sload = False
    has_log = False
    has_call_with_value = False
    has_callvalue_check = False
    has_return = False
    max_calldatasize_check = 0
    address_mask_positions = set()  # calldata byte offsets that are address-masked
    calldata_load_offsets = set()   # all calldata offsets loaded

    for bid in func.body_blocks:
        block = block_map.get(bid)
        if block is None:
            continue

        for inst in block.instructions:
            all_opcodes.add(inst.opcode)

            if inst.opcode == "SSTORE":
                has_sstore = True
            elif inst.opcode == "SLOAD":
                has_sload = True
            elif inst.opcode.startswith("LOG"):
                has_log = True
            elif inst.opcode == "RETURN":
                has_return = True
            elif inst.opcode == "CALLVALUE":
                has_callvalue_check = True

        # Check simulation traces for more detail
        trace = sim_result.traces.get(bid)
        if trace:
            for op in trace.operations:
                desc = op.description.lower()
                if "call" in desc and "value" in desc:
                    has_call_with_value = True

            # Check for calldatasize comparisons
            if trace.branch_condition:
                cond = str(trace.branch_condition)
                if "calldatasize" in cond:
                    import re
                    m = re.search(r'0x([0-9a-fA-F]+)', cond)
                    if m:
                        try:
                            size = int(m.group(1), 16)
                            if size > max_calldatasize_check and size <= MAX_SANE_CALLDATA_OFFSET:
                                max_calldatasize_check = size
                        except ValueError:
                            pass

            # Track calldata load positions
            for ann_off, ann_text in trace.stack_annotations.items():
                if "calldata[" in ann_text:
                    import re
                    m = re.search(r'calldata\[0x([0-9a-fA-F]+)\]', ann_text)
                    if m:
                        try:
                            offset = int(m.group(1), 16)
                            if offset <= MAX_SANE_CALLDATA_OFFSET:
                                calldata_load_offsets.add(offset)
                        except ValueError:
                            pass

    # ── Determine mutability ──────────────────────────────────
    mutability = "nonpayable"  # default

    if has_callvalue_check:
        # Check if the CALLVALUE check is a "must be zero" check (nonpayable)
        # or a "use the value" pattern (payable)
        # For now, heuristic: if CALLVALUE + ISZERO pattern exists → nonpayable
        entry_block = block_map.get(func.entry_block_id)
        if entry_block:
            trace = sim_result.traces.get(func.entry_block_id)
            if trace and trace.branch_condition:
                cond = str(trace.branch_condition)
                if "msg.value" in cond and ("!" in cond or "== 0" in cond.replace(" ", "")):
                    mutability = "nonpayable"
                    evidence.append("CALLVALUE check reverts on non-zero → nonpayable")
                else:
                    mutability = "payable"
                    evidence.append("CALLVALUE used without revert-on-nonzero → payable")
    else:
        if not has_sstore and not has_log and not has_call_with_value:
            if has_sload or has_return:
                mutability = "view"
                evidence.append("no SSTORE/LOG, has SLOAD → view")
                if not has_sload:
                    mutability = "pure"
                    evidence.append("no SLOAD either → pure")
            else:
                mutability = "nonpayable"
        else:
            evidence.append("has SSTORE or LOG → state-changing")

    # ── Determine argument count ─────────────────────────────
    arg_count = 0
    if max_calldatasize_check > 4:
        arg_count = min((max_calldatasize_check - 4) // 32, MAX_SANE_ARG_COUNT)
        evidence.append(f"calldatasize >= {max_calldatasize_check} → {arg_count} args")
    elif calldata_load_offsets:
        max_offset = max(calldata_load_offsets)
        if max_offset >= 4:
            arg_count = min((max_offset - 4) // 32 + 1, MAX_SANE_ARG_COUNT)
            evidence.append(f"calldata loaded up to offset 0x{max_offset:02x} → {arg_count} args")

    # ── Determine argument types ─────────────────────────────
    # Pre-build a set of calldata offsets that have address masks
    # to avoid O(args × blocks × annotations) inner loop.
    address_masked_offsets: set[int] = set()
    for bid in func.body_blocks:
        trace = sim_result.traces.get(bid)
        if trace:
            for _ann_off, ann_text in trace.stack_annotations.items():
                if "ffffffffffffffffffffffffffffffffffffffff" in ann_text and "calldata[" in ann_text:
                    import re as _re
                    for m in _re.finditer(r'calldata\[0x([0-9a-fA-F]+)\]', ann_text):
                        try:
                            address_masked_offsets.add(int(m.group(1), 16))
                        except ValueError:
                            pass

    arg_types = []
    for i in range(arg_count):
        offset = 0x04 + i * 0x20  # 4 + i*32
        if offset in address_masked_offsets:
            arg_types.append("address")
        else:
            arg_types.append("uint256")  # default assumption

    # Pad if needed
    while len(arg_types) < arg_count:
        arg_types.append("uint256")

    # ── Determine return type ────────────────────────────────
    return_type = None
    if has_return:
        # Check return data size from traces
        for bid in func.body_blocks:
            trace = sim_result.traces.get(bid)
            if trace:
                for op in trace.operations:
                    if "return" in op.description.lower():
                        if "0x20" in op.description:
                            return_type = "uint256"  # or bool or address
                            break

    # Calculate confidence
    confidence = 0.5
    if evidence:
        confidence = min(0.5 + len(evidence) * 0.1, 0.95)

    return RecoveredABI(
        selector=func.selector,
        name=func.name,
        mutability=mutability,
        arg_count=arg_count,
        arg_types=arg_types,
        return_type=return_type,
        has_return=has_return,
        confidence=confidence,
        evidence=evidence,
    )
