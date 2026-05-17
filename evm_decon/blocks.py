"""
Basic block builder for EVM bytecode.

Segments the linear instruction stream into basic blocks based on
control flow opcodes (JUMP, JUMPI, STOP, RETURN, REVERT, etc.)
and JUMPDEST markers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from .disassembler import Instruction, DisassemblyResult
from .opcodes import BLOCK_TERMINATORS, BLOCK_ENTRIES


@dataclass
class BasicBlock:
    id: int
    start_offset: int
    end_offset: int           # offset of last instruction's last byte
    instructions: list[Instruction]
    exits_to: list[int]       # block IDs this block can jump to
    exit_offsets: list[int]   # byte offsets of exit targets
    block_type: str           # "entry", "jumpdest", "fallthrough", "unreachable"
    terminator: Optional[str] # opcode that ends this block


@dataclass
class BlockAnalysis:
    blocks: list[BasicBlock]
    jumpdest_offsets: set[int]
    entry_block_id: int
    total_blocks: int


def build_basic_blocks(disasm: DisassemblyResult) -> BlockAnalysis:
    """
    Segment disassembled instructions into basic blocks.

    A basic block is a maximal sequence of instructions where:
    - Only the first instruction can be a jump target (JUMPDEST)
    - Only the last instruction can be a branch (JUMP, JUMPI, STOP, etc.)
    """
    instructions = disasm.instructions
    if not instructions:
        return BlockAnalysis(blocks=[], jumpdest_offsets=set(), entry_block_id=0, total_blocks=0)

    # Find all JUMPDEST offsets (valid jump targets)
    jumpdest_offsets: set[int] = set()
    for inst in instructions:
        if inst.opcode == "JUMPDEST":
            jumpdest_offsets.add(inst.offset)

    # Find block boundaries
    # Blocks start at: offset 0, any JUMPDEST, instruction after a terminator
    # Blocks end at: any terminator, instruction before a JUMPDEST

    blocks: list[BasicBlock] = []
    current_block_instructions: list[Instruction] = []
    block_id = 0

    for i, inst in enumerate(instructions):
        is_block_start = (
            i == 0
            or inst.opcode in BLOCK_ENTRIES
            or (i > 0 and instructions[i - 1].opcode in BLOCK_TERMINATORS)
        )

        if is_block_start and current_block_instructions:
            # Close previous block
            _close_block(blocks, block_id, current_block_instructions, jumpdest_offsets)
            block_id += 1
            current_block_instructions = []

        current_block_instructions.append(inst)

        if inst.opcode in BLOCK_TERMINATORS:
            # Close this block
            _close_block(blocks, block_id, current_block_instructions, jumpdest_offsets)
            block_id += 1
            current_block_instructions = []

    # Close any remaining block
    if current_block_instructions:
        _close_block(blocks, block_id, current_block_instructions, jumpdest_offsets)

    # Resolve exit edges (simple pushed-jump resolution)
    _resolve_edges(blocks, jumpdest_offsets)

    return BlockAnalysis(
        blocks=blocks,
        jumpdest_offsets=jumpdest_offsets,
        entry_block_id=0,
        total_blocks=len(blocks),
    )


def _close_block(
    blocks: list[BasicBlock],
    block_id: int,
    instructions: list[Instruction],
    jumpdest_offsets: set[int],
):
    """Create a BasicBlock from accumulated instructions."""
    if not instructions:
        return

    first = instructions[0]
    last = instructions[-1]

    # Determine block type
    if block_id == 0:
        block_type = "entry"
    elif first.opcode == "JUMPDEST":
        block_type = "jumpdest"
    else:
        block_type = "fallthrough"

    terminator = last.opcode if last.opcode in BLOCK_TERMINATORS else None

    blocks.append(BasicBlock(
        id=block_id,
        start_offset=first.offset,
        end_offset=last.offset + last.size - 1,
        instructions=instructions,
        exits_to=[],
        exit_offsets=[],
        block_type=block_type,
        terminator=terminator,
    ))


def _resolve_edges(blocks: list[BasicBlock], jumpdest_offsets: set[int]):
    """
    Resolve basic block exit edges using simple pushed-jump analysis.

    For PUSH + JUMP patterns, we can statically determine the target.
    For JUMPI, we have both the jump target and the fall-through.
    """
    # Build offset → block_id map
    offset_to_block: dict[int, int] = {}
    for block in blocks:
        offset_to_block[block.start_offset] = block.id

    for i, block in enumerate(blocks):
        if not block.instructions:
            continue

        last = block.instructions[-1]

        if last.opcode == "JUMP":
            # Look for PUSH before JUMP
            if len(block.instructions) >= 2:
                prev = block.instructions[-2]
                if prev.opcode.startswith("PUSH") and prev.operand_value is not None:
                    target = prev.operand_value
                    if target in jumpdest_offsets and target in offset_to_block:
                        block.exits_to.append(offset_to_block[target])
                        block.exit_offsets.append(target)

        elif last.opcode == "JUMPI":
            # Conditional jump: two exits
            # 1. Jump target (from PUSH before JUMPI)
            if len(block.instructions) >= 2:
                prev = block.instructions[-2]
                if prev.opcode.startswith("PUSH") and prev.operand_value is not None:
                    target = prev.operand_value
                    if target in jumpdest_offsets and target in offset_to_block:
                        block.exits_to.append(offset_to_block[target])
                        block.exit_offsets.append(target)

            # 2. Fall-through to next block
            if i + 1 < len(blocks):
                block.exits_to.append(blocks[i + 1].id)
                block.exit_offsets.append(blocks[i + 1].start_offset)

        elif last.opcode in ("STOP", "RETURN", "REVERT", "INVALID", "SELFDESTRUCT"):
            # Terminal — no exits
            pass

        else:
            # Non-terminator end (shouldn't happen in well-formed blocks, 
            # but handle fallthrough)
            if i + 1 < len(blocks):
                block.exits_to.append(blocks[i + 1].id)
                block.exit_offsets.append(blocks[i + 1].start_offset)
