"""
Pseudocode generator for EVM bytecode.

Transforms the analyzed CFG + stack traces into readable pseudo-code
with proper nesting, variable naming, and control structure recovery.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from .blocks import BasicBlock, BlockAnalysis
from .stack_sim import SimulationResult, BlockTrace, StackValue
from .cfg import CFGAnalysis, LoopInfo


@dataclass
class PseudoLine:
    indent: int
    text: str
    comment: Optional[str] = None
    block_id: Optional[int] = None


def generate_pseudocode(
    block_analysis: BlockAnalysis,
    sim_result: SimulationResult,
    cfg: CFGAnalysis,
) -> str:
    """Generate human-readable pseudocode from analyzed bytecode."""

    blocks = block_analysis.blocks
    if not blocks:
        return "// empty bytecode"

    lines: list[PseudoLine] = []

    # Build helper maps
    block_map = {b.id: b for b in blocks}
    loop_by_header = {l.header_block: l for l in cfg.loops}

    # Track which blocks we've already emitted
    emitted: set[int] = set()

    # Start from entry block
    _emit_block_recursive(
        block_id=0,
        blocks=block_map,
        cfg=cfg,
        sim=sim_result,
        lines=lines,
        emitted=emitted,
        indent=0,
        loop_by_header=loop_by_header,
    )

    return _format_lines(lines)


def _emit_block_recursive(
    block_id: int,
    blocks: dict[int, BasicBlock],
    cfg: CFGAnalysis,
    sim: SimulationResult,
    lines: list[PseudoLine],
    emitted: set[int],
    indent: int,
    loop_by_header: dict[int, LoopInfo],
    max_depth: int = 50,
):
    """Recursively emit pseudocode for a block and its successors."""
    if block_id in emitted or max_depth <= 0:
        return
    emitted.add(block_id)

    block = blocks.get(block_id)
    if block is None:
        return

    trace = sim.traces.get(block_id)
    btype = cfg.block_types.get(block_id, "unknown")
    label = cfg.block_labels.get(block_id, "")

    # ── Entry Block ───────────────────────────────────────
    if btype == "entry":
        lines.append(PseudoLine(indent, f"// Block {block_id}: {label}"))
        _emit_initializations(trace, lines, indent)

        # Follow to next block
        for succ in block.exits_to:
            _emit_block_recursive(succ, blocks, cfg, sim, lines, emitted, indent, loop_by_header, max_depth - 1)

    # ── Loop Header ───────────────────────────────────────
    elif btype == "loop_header":
        loop = loop_by_header.get(block_id)
        if loop:
            loop_line = _format_loop_header(loop, trace)
            lines.append(PseudoLine(indent, loop_line, block_id=block_id))

            # Emit the loop body blocks (blocks inside the loop, not the header)
            body_blocks = sorted(set(loop.body_blocks) - {block_id})

            for body_bid in body_blocks:
                if body_bid not in emitted:
                    _emit_block_recursive(
                        body_bid, blocks, cfg, sim, lines, emitted,
                        indent + 1, loop_by_header, max_depth - 1
                    )

            # Close loop
            lines.append(PseudoLine(indent, ""))

            # Emit exit blocks
            for exit_bid in loop.exit_blocks:
                if exit_bid not in emitted:
                    _emit_block_recursive(
                        exit_bid, blocks, cfg, sim, lines, emitted,
                        indent, loop_by_header, max_depth - 1
                    )
        else:
            # Fallback: just emit as conditional
            _emit_conditional(block_id, block, trace, cfg, blocks, sim, lines, emitted, indent, loop_by_header, max_depth)

    # ── Loop Body ─────────────────────────────────────────
    elif btype in ("loop_body", "loop_body_call", "loop_body_storage"):
        if trace and trace.operations:
            for op in trace.operations:
                lines.append(PseudoLine(indent, _simplify_operation(op.description), block_id=block_id))
        elif trace and trace.stack_annotations:
            # Use annotations as fallback
            for off, ann in sorted(trace.stack_annotations.items()):
                if any(c in ann for c in ["*", "+", "-", "=", "memory", "storage"]):
                    lines.append(PseudoLine(indent, _simplify_operation(ann), block_id=block_id))

    # ── Loop Setup ────────────────────────────────────────
    elif btype == "loop_setup":
        _emit_initializations(trace, lines, indent)
        for succ in block.exits_to:
            if succ not in emitted:
                _emit_block_recursive(succ, blocks, cfg, sim, lines, emitted, indent, loop_by_header, max_depth - 1)

    # ── Loop Increment ────────────────────────────────────
    elif btype == "loop_increment":
        if trace and trace.operations:
            for op in trace.operations:
                lines.append(PseudoLine(indent, _simplify_operation(op.description), block_id=block_id))
        # Don't follow the back edge — it's handled by the loop structure

    # ── Loop Tail ─────────────────────────────────────────
    elif btype == "loop_tail":
        if trace and trace.operations:
            for op in trace.operations:
                lines.append(PseudoLine(indent, _simplify_operation(op.description), block_id=block_id))

    # ── Return ────────────────────────────────────────────
    elif btype == "return":
        if trace and trace.operations:
            for op in trace.operations:
                lines.append(PseudoLine(indent, _simplify_operation(op.description), block_id=block_id))
        else:
            lines.append(PseudoLine(indent, "return", block_id=block_id))

    # ── Revert ────────────────────────────────────────────
    elif btype == "revert":
        lines.append(PseudoLine(indent, "revert()", block_id=block_id))

    # ── Conditional ───────────────────────────────────────
    elif btype == "conditional":
        _emit_conditional(block_id, block, trace, cfg, blocks, sim, lines, emitted, indent, loop_by_header, max_depth)

    # ── Generic ───────────────────────────────────────────
    else:
        if trace and trace.operations:
            for op in trace.operations:
                lines.append(PseudoLine(indent, _simplify_operation(op.description), block_id=block_id))
        for succ in block.exits_to:
            if succ not in emitted:
                _emit_block_recursive(succ, blocks, cfg, sim, lines, emitted, indent, loop_by_header, max_depth - 1)


def _emit_conditional(
    block_id, block, trace, cfg, blocks, sim, lines, emitted, indent, loop_by_header, max_depth
):
    """Emit an if/else conditional."""
    if trace and trace.branch_condition:
        cond_str = str(trace.branch_condition)
        lines.append(PseudoLine(indent, f"if ({cond_str}):", block_id=block_id))

        if trace.branch_true_target is not None:
            # Find block for true target
            true_block = _find_block_at_offset(trace.branch_true_target, blocks)
            if true_block is not None and true_block not in emitted:
                _emit_block_recursive(true_block, blocks, cfg, sim, lines, emitted, indent + 1, loop_by_header, max_depth - 1)

        # Fall-through (false branch)
        false_targets = [s for s in block.exits_to if s != _find_block_at_offset(trace.branch_true_target, blocks) if trace.branch_true_target]
        if false_targets:
            lines.append(PseudoLine(indent, "else:"))
            for ft in false_targets:
                if ft not in emitted:
                    _emit_block_recursive(ft, blocks, cfg, sim, lines, emitted, indent + 1, loop_by_header, max_depth - 1)
    else:
        for succ in block.exits_to:
            if succ not in emitted:
                _emit_block_recursive(succ, blocks, cfg, sim, lines, emitted, indent, loop_by_header, max_depth - 1)


def _emit_initializations(trace: Optional[BlockTrace], lines: list[PseudoLine], indent: int):
    """Emit variable initializations from a block's exit stack."""
    if not trace:
        return

    for i, sv in enumerate(trace.exit_stack):
        if sv.is_const:
            val_str = repr(sv)
            lines.append(PseudoLine(indent, f"var_{i} = {val_str}"))
        elif sv.kind == "expr":
            lines.append(PseudoLine(indent, f"var_{i} = {sv.value}"))

    # Emit memory/storage operations
    for op in trace.operations:
        lines.append(PseudoLine(indent, _simplify_operation(op.description)))


def _format_loop_header(loop: LoopInfo, trace: Optional[BlockTrace]) -> str:
    """Format a loop header as a for/while statement."""
    if loop.loop_type == "for" and loop.iterations is not None:
        init = loop.counter_init if loop.counter_init is not None else 0
        bound = loop.counter_bound if loop.counter_bound is not None else "?"
        step = loop.counter_step if loop.counter_step is not None else 1

        if init == 0 and step == 1:
            return f"for i_{loop.loop_id} in range({bound}):    // {loop.iterations} iterations"
        else:
            return f"for i_{loop.loop_id} = {init}; i_{loop.loop_id} < {bound}; i_{loop.loop_id} += {step}:    // {loop.iterations} iterations"
    else:
        cond = loop.condition if loop.condition else "..."
        return f"while ({cond}):"


def _simplify_operation(desc: str) -> str:
    """Clean up an operation description for pseudocode."""
    # Replace hex addresses
    desc = desc.replace("memory[0x40]", "result_ptr")
    desc = desc.replace("memory[0x00]", "scratch")

    # Simplify return statements
    if desc.startswith("return memory["):
        return "return result"

    return desc


def _find_block_at_offset(offset: Optional[int], blocks: dict[int, BasicBlock]) -> Optional[int]:
    """Find the block ID that starts at the given byte offset."""
    if offset is None:
        return None
    for bid, block in blocks.items():
        if block.start_offset == offset:
            return bid
    return None


def _format_lines(lines: list[PseudoLine]) -> str:
    """Format pseudocode lines into a string."""
    result = []
    for line in lines:
        indent_str = "    " * line.indent
        text = f"{indent_str}{line.text}"
        if line.comment:
            text += f"  // {line.comment}"
        result.append(text)

    # Clean up excessive blank lines
    cleaned = []
    prev_blank = False
    for line in result:
        is_blank = not line.strip()
        if is_blank and prev_blank:
            continue
        cleaned.append(line)
        prev_blank = is_blank

    return "\n".join(cleaned)
