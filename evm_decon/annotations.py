"""
Enhanced instruction annotations using stack simulation context.

Replaces the basic annotations with rich, stack-aware annotations
that show what each instruction is actually doing with real values.
"""

from __future__ import annotations
from typing import Optional
from .disassembler import Instruction, DisassemblyResult
from .blocks import BasicBlock, BlockAnalysis
from .stack_sim import SimulationResult, BlockTrace, StackValue
from .cfg import CFGAnalysis, LoopInfo


def annotate_instructions(
    disasm: DisassemblyResult,
    block_analysis: BlockAnalysis,
    sim_result: SimulationResult,
    cfg: CFGAnalysis,
) -> dict[int, str]:
    """
    Generate rich annotations for each instruction offset.

    Returns a dict mapping byte offset → annotation string.
    """
    annotations: dict[int, str] = {}

    # Build offset → block_id map
    offset_to_block: dict[int, int] = {}
    for block in block_analysis.blocks:
        for inst in block.instructions:
            offset_to_block[inst.offset] = block.id

    # Build loop header info
    loop_headers = {l.header_block for l in cfg.loops}
    loop_by_header = {l.header_block: l for l in cfg.loops}
    back_edge_targets = {be.target for be in cfg.back_edges}
    back_edge_sources = {be.source for be in cfg.back_edges}

    # Gather all stack annotations from simulation
    for block_id, trace in sim_result.traces.items():
        for off, ann in trace.stack_annotations.items():
            if ann:
                annotations[off] = ann

    # Layer in structural annotations
    for inst in disasm.instructions:
        off = inst.offset
        block_id = offset_to_block.get(off)
        btype = cfg.block_types.get(block_id, "") if block_id is not None else ""

        existing = annotations.get(off, "")

        # JUMPDEST annotations
        if inst.opcode == "JUMPDEST":
            if block_id in loop_headers:
                loop = loop_by_header.get(block_id)
                if loop and loop.iterations:
                    annotations[off] = f"◆ LOOP HEADER ({loop.iterations} iterations)"
                else:
                    annotations[off] = "◆ LOOP HEADER"
            elif btype == "loop_body":
                annotations[off] = "loop body"
            elif btype == "loop_setup":
                annotations[off] = "loop setup"
            elif off in back_edge_targets:
                annotations[off] = "◆ loop target"
            else:
                annotations[off] = "jump target"

        # JUMP annotations (back edge detection)
        elif inst.opcode == "JUMP":
            block = block_analysis.blocks[block_id] if block_id is not None and block_id < len(block_analysis.blocks) else None
            if block_id in back_edge_sources:
                annotations[off] = "↩ back to loop header"
            elif not existing:
                annotations[off] = "jump"

        # JUMPI with condition context
        elif inst.opcode == "JUMPI":
            trace = sim_result.traces.get(block_id)
            if trace and trace.branch_condition:
                cond = str(trace.branch_condition)
                target = f"0x{trace.branch_true_target:04x}" if trace.branch_true_target else "?"
                annotations[off] = f"if ({cond}) → {target}"
            elif not existing:
                annotations[off] = "conditional jump"

        # RETURN with context
        elif inst.opcode == "RETURN":
            trace = sim_result.traces.get(block_id)
            if trace and trace.operations:
                for op in trace.operations:
                    if "return" in op.description.lower():
                        annotations[off] = op.description
                        break
            if off not in annotations:
                annotations[off] = "return data"

        # REVERT
        elif inst.opcode == "REVERT":
            if not existing:
                annotations[off] = "revert execution"

        # MSTORE with what's being stored
        elif inst.opcode == "MSTORE":
            if not existing:
                annotations[off] = "store to memory"

        # SSTORE/SLOAD
        elif inst.opcode == "SSTORE":
            if not existing:
                annotations[off] = "write to storage"
        elif inst.opcode == "SLOAD":
            if not existing:
                annotations[off] = "read from storage"

        # MUL/ADD/SUB with context
        elif inst.opcode in ("MUL", "ADD", "SUB", "DIV", "MOD", "EXP"):
            # Stack annotation already set by simulator, keep it
            pass

        # CALLVALUE check pattern
        elif inst.opcode == "CALLVALUE":
            annotations[off] = "msg.value (payable check)"

        elif inst.opcode == "CALLER":
            annotations[off] = "msg.sender"

        elif inst.opcode == "CALLDATASIZE":
            annotations[off] = "calldata length"

        elif inst.opcode == "CALLDATALOAD":
            if not existing:
                annotations[off] = "read calldata"

        elif inst.opcode == "SELFDESTRUCT":
            annotations[off] = "⚠️ SELFDESTRUCT"

        elif inst.opcode == "DELEGATECALL":
            annotations[off] = "⚠️ DELEGATECALL"

        elif inst.opcode == "ORIGIN":
            annotations[off] = "⚠️ tx.origin"

        # PUSH with constant context
        elif inst.opcode.startswith("PUSH") and inst.operand_value is not None:
            val = inst.operand_value
            # Check if the simulator gave us context
            for const in sim_result.constants:
                if const["offset"] == f"0x{off:04x}" and const["context"]:
                    annotations[off] = const["context"]
                    break

    return annotations
