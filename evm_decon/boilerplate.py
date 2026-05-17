"""
Boilerplate classifier.

Identifies and tags compiler-generated code sequences so the semantic
output can filter them from the main view. EVM bytecode is ~60%
compiler infrastructure — this module marks it so analysts see only
the contract logic.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from .blocks import BasicBlock, BlockAnalysis
from .stack_sim import SimulationResult, BlockTrace


@dataclass
class BoilerplateTag:
    """A tag for a block or instruction range that is compiler boilerplate."""
    block_id: int
    category: str           # "free_mem_init", "selector_extraction", "abi_decode",
                            # "abi_encode", "revert_helper", "string_getter_loop",
                            # "safemath", "modifier_setup"
    description: str
    hide_in_output: bool = True


def classify_boilerplate(
    block_analysis: BlockAnalysis,
    sim_result: SimulationResult,
) -> list[BoilerplateTag]:
    """
    Classify blocks as boilerplate or meaningful logic.
    """
    tags = []
    block_map = {b.id: b for b in block_analysis.blocks}

    for block in block_analysis.blocks:
        trace = sim_result.traces.get(block.id)
        if trace is None:
            continue

        # ── Free memory pointer initialization ──────────────
        # Block 0 usually starts with PUSH1 0x80 PUSH1 0x40 MSTORE
        if block.id == 0 and len(block.instructions) >= 3:
            first_three = [i.opcode for i in block.instructions[:3]]
            if first_three == ["PUSH1", "PUSH1", "MSTORE"]:
                vals = [block.instructions[0].operand_value, block.instructions[1].operand_value]
                if vals == [0x80, 0x40]:
                    tags.append(BoilerplateTag(
                        block_id=block.id,
                        category="free_mem_init",
                        description="Free memory pointer initialization (0x80 → 0x40)",
                    ))

        # ── ABI encoding/decoding ───────────────────────────
        # Blocks that are primarily memory writes for return data encoding
        if trace.operations:
            mem_writes = sum(1 for op in trace.operations if op.category == "memory")
            total_ops = len(trace.operations)
            if total_ops > 2 and mem_writes / total_ops > 0.8:
                # Check if this is just ABI encoding
                is_abi = any("memory[" in op.description and "return" in str(trace.operations).lower()
                             for op in trace.operations)
                if is_abi:
                    tags.append(BoilerplateTag(
                        block_id=block.id,
                        category="abi_encode",
                        description="ABI return data encoding",
                    ))

        # ── Revert helper patterns ──────────────────────────
        # Small blocks that just push error data and revert
        if block.terminator == "REVERT" and len(block.instructions) <= 8:
            has_push32 = any(i.opcode == "PUSH32" for i in block.instructions)
            if has_push32:
                tags.append(BoilerplateTag(
                    block_id=block.id,
                    category="revert_helper",
                    description="Revert with error signature",
                ))

        # ── String getter loop ──────────────────────────────
        # Blocks in loops that read from keccak256(slot) for string data
        for ann_off, ann_text in trace.stack_annotations.items():
            if "keccak256" in ann_text and "storage" in str(trace.storage_ops):
                # Check if this is in a loop context
                from .cfg import CFGAnalysis
                # (simplified heuristic)
                if len(block.instructions) > 10:
                    has_mstore_loop = sum(1 for i in block.instructions if i.opcode == "MSTORE") > 1
                    if has_mstore_loop:
                        tags.append(BoilerplateTag(
                            block_id=block.id,
                            category="string_getter_loop",
                            description="Dynamic string/bytes getter loop",
                        ))
                break

        # ── SafeMath wrappers ────────────────────────────────
        # Pattern: a op b, then check result vs operand, then revert
        if trace.operations and len(trace.operations) <= 4:
            ops_text = " ".join(op.description for op in trace.operations)
            if ("*" in ops_text or "+" in ops_text) and block.terminator == "JUMPI":
                # Could be a SafeMath assert(c / a == b) or assert(c >= a)
                if trace.branch_condition:
                    cond = str(trace.branch_condition)
                    if ("==" in cond or ">=" in cond) and "0x" not in cond:
                        tags.append(BoilerplateTag(
                            block_id=block.id,
                            category="safemath",
                            description="SafeMath overflow/underflow check",
                            hide_in_output=False,  # Keep but annotate
                        ))

    return tags


def is_boilerplate(block_id: int, tags: list[BoilerplateTag]) -> bool:
    """Check if a block is tagged as boilerplate that should be hidden."""
    for tag in tags:
        if tag.block_id == block_id and tag.hide_in_output:
            return True
    return False


def get_boilerplate_tag(block_id: int, tags: list[BoilerplateTag]) -> Optional[BoilerplateTag]:
    """Get the boilerplate tag for a block, if any."""
    for tag in tags:
        if tag.block_id == block_id:
            return tag
    return None


def summarize_boilerplate(tags: list[BoilerplateTag]) -> dict[str, int]:
    """Summarize boilerplate classification counts."""
    counts: dict[str, int] = {}
    for tag in tags:
        counts[tag.category] = counts.get(tag.category, 0) + 1
    return counts
