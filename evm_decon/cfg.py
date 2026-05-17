"""
Control Flow Graph analyzer with loop detection.

Detects loops via back-edge analysis, computes loop bodies,
identifies nested loops, classifies blocks, and extracts
loop counter/bound/step information.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from .blocks import BasicBlock, BlockAnalysis
from .stack_sim import SimulationResult, BlockTrace, StackValue


@dataclass
class LoopInfo:
    loop_id: int
    header_block: int            # block ID of the loop header
    back_edge_from: int          # block ID that jumps back
    body_blocks: list[int]       # all blocks in the loop body
    exit_blocks: list[int]       # blocks that exit the loop
    counter_name: Optional[str]  # e.g. "var_1"
    counter_init: Optional[int]  # initial value
    counter_bound: Optional[int] # comparison bound
    counter_step: Optional[int]  # increment amount
    iterations: Optional[int]    # estimated iteration count
    loop_type: str               # "for", "while", "do-while"
    parent_loop: Optional[int]   # ID of enclosing loop, or None
    condition: Optional[str]     # human-readable condition


@dataclass
class BackEdge:
    source: int  # block ID
    target: int  # block ID (loop header)


@dataclass
class CFGAnalysis:
    loops: list[LoopInfo]
    back_edges: list[BackEdge]
    block_types: dict[int, str]      # block_id → type string
    block_labels: dict[int, str]     # block_id → human label
    dominators: dict[int, set[int]]  # block_id → set of dominators
    reachable: set[int]              # set of reachable block IDs


def analyze_cfg(
    block_analysis: BlockAnalysis,
    sim_result: SimulationResult,
) -> CFGAnalysis:
    """Full control flow analysis: loops, dominators, block classification."""

    blocks = block_analysis.blocks
    if not blocks:
        return CFGAnalysis([], [], {}, {}, {}, set())

    # Build adjacency
    successors: dict[int, list[int]] = {}
    predecessors: dict[int, list[int]] = {}
    all_ids = set()

    for b in blocks:
        all_ids.add(b.id)
        successors[b.id] = list(b.exits_to)
        for s in b.exits_to:
            predecessors.setdefault(s, []).append(b.id)

    for bid in all_ids:
        successors.setdefault(bid, [])
        predecessors.setdefault(bid, [])

    # 1. Compute reachability from entry
    reachable = _compute_reachable(0, successors, all_ids)

    # 2. Compute dominators
    dominators = _compute_dominators(0, successors, predecessors, reachable)

    # 3. Find back edges (edge A→B where B dominates A)
    back_edges = _find_back_edges(successors, dominators, reachable)

    # 4. Compute loop info from back edges
    loops = _compute_loops(back_edges, successors, predecessors, reachable, sim_result)

    # 5. Detect nested loops
    _detect_nesting(loops)

    # 6. Classify blocks
    block_types = _classify_blocks(blocks, loops, back_edges, sim_result)
    block_labels = _label_blocks(blocks, block_types, loops, sim_result)

    return CFGAnalysis(
        loops=loops,
        back_edges=back_edges,
        block_types=block_types,
        block_labels=block_labels,
        dominators=dominators,
        reachable=reachable,
    )


def _compute_reachable(entry: int, successors: dict[int, list[int]], all_ids: set[int]) -> set[int]:
    """BFS reachability from entry."""
    visited = set()
    queue = [entry]
    while queue:
        node = queue.pop(0)
        if node in visited or node not in all_ids:
            continue
        visited.add(node)
        for s in successors.get(node, []):
            if s not in visited:
                queue.append(s)
    return visited


def _compute_dominators(
    entry: int,
    successors: dict[int, list[int]],
    predecessors: dict[int, list[int]],
    reachable: set[int],
) -> dict[int, set[int]]:
    """Compute dominators using iterative algorithm."""
    doms: dict[int, set[int]] = {}

    # Initialize: entry dominated only by itself, others by all nodes
    for n in reachable:
        if n == entry:
            doms[n] = {entry}
        else:
            doms[n] = set(reachable)

    # Iterate until fixed point
    changed = True
    iterations = 0
    while changed and iterations < 100:
        changed = False
        iterations += 1
        for n in reachable:
            if n == entry:
                continue
            preds = [p for p in predecessors.get(n, []) if p in reachable]
            if not preds:
                continue
            new_dom = set(reachable)
            for p in preds:
                new_dom = new_dom & doms.get(p, set())
            new_dom.add(n)
            if new_dom != doms[n]:
                doms[n] = new_dom
                changed = True

    return doms


def _find_back_edges(
    successors: dict[int, list[int]],
    dominators: dict[int, set[int]],
    reachable: set[int],
) -> list[BackEdge]:
    """Find back edges: A→B where B dominates A."""
    back_edges = []
    for a in reachable:
        for b in successors.get(a, []):
            if b in dominators.get(a, set()):
                back_edges.append(BackEdge(source=a, target=b))
    return back_edges


def _compute_loops(
    back_edges: list[BackEdge],
    successors: dict[int, list[int]],
    predecessors: dict[int, list[int]],
    reachable: set[int],
    sim_result: SimulationResult,
) -> list[LoopInfo]:
    """Compute loop bodies and extract loop variable info."""
    loops = []

    for idx, be in enumerate(back_edges):
        header = be.target
        tail = be.source

        # Natural loop: all nodes that can reach tail without going through header
        body = _natural_loop_body(header, tail, predecessors)

        # Exit blocks: successors of body blocks that are NOT in the body
        exit_blocks = []
        for b in body:
            for s in successors.get(b, []):
                if s not in body and s not in exit_blocks:
                    exit_blocks.append(s)

        # Extract loop counter info from the header block's simulation trace
        counter_name = None
        counter_init = None
        counter_bound = None
        counter_step = None
        iterations = None
        loop_type = "while"
        condition = None

        trace = sim_result.traces.get(header)
        if trace and trace.branch_condition:
            cond = trace.branch_condition
            condition = str(cond)

            # Try to extract bound from condition like "(var < 10)"
            cond_str = str(cond)
            counter_bound = _extract_bound(cond_str, trace)

        # Try to find initialization: look at predecessor outside the loop
        header_preds = [p for p in predecessors.get(header, []) if p not in body]
        for pred_id in header_preds:
            pred_trace = sim_result.traces.get(pred_id)
            if pred_trace and pred_trace.exit_stack:
                # The last pushed value before entering the loop is likely the init
                for sv in reversed(pred_trace.exit_stack):
                    if sv.is_const and sv.value is not None:
                        if sv.value < 1000:  # reasonable counter init
                            counter_init = sv.value
                            break

        # Try to find step: look for ADD/SUB with constant in the tail block
        tail_trace = sim_result.traces.get(tail)
        if tail_trace:
            for op in tail_trace.operations:
                if "+" in op.description or "- " in op.description:
                    # Try to extract step from the operation
                    step = _extract_step(op.description)
                    if step is not None:
                        counter_step = step

        # For blocks in body, look for increment patterns
        if counter_step is None:
            for bid in body:
                bt = sim_result.traces.get(bid)
                if bt:
                    for ann_off, ann_text in bt.stack_annotations.items():
                        if "+ 0x01" in ann_text or "+ 1" in ann_text:
                            counter_step = 1
                            break
                    if counter_step:
                        break

        # Estimate iterations
        if counter_bound is not None and counter_init is not None and counter_step:
            try:
                iterations = (counter_bound - counter_init) // counter_step
                if iterations > 0:
                    loop_type = "for"
            except ZeroDivisionError:
                pass

        loops.append(LoopInfo(
            loop_id=idx,
            header_block=header,
            back_edge_from=tail,
            body_blocks=sorted(body),
            exit_blocks=exit_blocks,
            counter_name=f"var_{idx}",
            counter_init=counter_init,
            counter_bound=counter_bound,
            counter_step=counter_step,
            iterations=iterations,
            loop_type=loop_type,
            parent_loop=None,
            condition=condition,
        ))

    return loops


def _natural_loop_body(header: int, tail: int, predecessors: dict[int, list[int]]) -> set[int]:
    """Compute the natural loop body given header and tail of a back edge."""
    body = {header, tail}
    if header == tail:
        return body

    worklist = [tail]
    while worklist:
        node = worklist.pop()
        for pred in predecessors.get(node, []):
            if pred not in body:
                body.add(pred)
                worklist.append(pred)
    return body


def _detect_nesting(loops: list[LoopInfo]):
    """Detect nested loops by checking if a loop's header is in another loop's body."""
    for inner in loops:
        for outer in loops:
            if inner.loop_id == outer.loop_id:
                continue
            if inner.header_block in outer.body_blocks:
                inner.parent_loop = outer.loop_id


def _classify_blocks(
    blocks: list[BasicBlock],
    loops: list[LoopInfo],
    back_edges: list[BackEdge],
    sim_result: SimulationResult,
) -> dict[int, str]:
    """Classify each block by its role in the control flow."""
    types: dict[int, str] = {}

    loop_headers = {l.header_block for l in loops}
    loop_bodies = set()
    for l in loops:
        loop_bodies.update(l.body_blocks)
    loop_exits = set()
    for l in loops:
        loop_exits.update(l.exit_blocks)
    back_edge_sources = {be.source for be in back_edges}

    for b in blocks:
        bid = b.id
        trace = sim_result.traces.get(bid)

        if bid == 0:
            types[bid] = "entry"
        elif bid in loop_headers:
            types[bid] = "loop_header"
        elif bid in back_edge_sources and bid in loop_bodies:
            # Check if it's an increment block (has ADD in operations)
            if trace and any("+" in op.description for op in trace.operations):
                types[bid] = "loop_increment"
            else:
                types[bid] = "loop_tail"
        elif bid in loop_bodies:
            # Check what kind of body block
            if trace and trace.operations:
                has_mul = any("*" in op.description for op in trace.operations)
                has_mem = any(op.category == "memory" for op in trace.operations)
                has_stor = any(op.category == "storage" for op in trace.operations)
                has_call = any(op.category == "call" for op in trace.operations)

                if has_call:
                    types[bid] = "loop_body_call"
                elif has_stor:
                    types[bid] = "loop_body_storage"
                elif has_mul or has_mem:
                    types[bid] = "loop_body"
                else:
                    # Setup block (initializes inner loop counter, etc.)
                    types[bid] = "loop_setup"
            else:
                types[bid] = "loop_setup"
        elif b.terminator == "RETURN":
            types[bid] = "return"
        elif b.terminator == "REVERT":
            types[bid] = "revert"
        elif b.terminator == "STOP":
            types[bid] = "halt"
        elif b.terminator == "JUMPI":
            types[bid] = "conditional"
        else:
            types[bid] = "basic"

    return types


def _label_blocks(
    blocks: list[BasicBlock],
    block_types: dict[int, str],
    loops: list[LoopInfo],
    sim_result: SimulationResult,
) -> dict[int, str]:
    """Generate human-readable labels for blocks."""
    labels: dict[int, str] = {}

    # Map loop headers to loops
    header_to_loop = {l.header_block: l for l in loops}

    for b in blocks:
        bid = b.id
        btype = block_types.get(bid, "unknown")
        trace = sim_result.traces.get(bid)

        if btype == "entry":
            labels[bid] = "Initialize"
        elif btype == "loop_header":
            loop = header_to_loop.get(bid)
            if loop and loop.condition:
                labels[bid] = f"Loop check: {loop.condition}"
            else:
                labels[bid] = "Loop header"
        elif btype == "loop_body":
            if trace and trace.operations:
                ops = ", ".join(op.description for op in trace.operations[:3])
                labels[bid] = f"Loop body: {ops}"
            else:
                labels[bid] = "Loop body"
        elif btype == "loop_setup":
            labels[bid] = "Loop setup"
        elif btype == "loop_increment":
            labels[bid] = "Loop increment"
        elif btype == "loop_tail":
            labels[bid] = "Back to loop header"
        elif btype == "return":
            if trace and trace.operations:
                labels[bid] = trace.operations[-1].description
            else:
                labels[bid] = "Return"
        elif btype == "revert":
            labels[bid] = "Revert"
        elif btype == "conditional":
            if trace and trace.branch_condition:
                labels[bid] = f"Conditional: {trace.branch_condition}"
            else:
                labels[bid] = "Conditional branch"
        else:
            labels[bid] = "Basic block"

    return labels


def _extract_bound(cond_str: str, trace: BlockTrace) -> Optional[int]:
    """Try to extract the loop bound from a condition string."""
    # Look for constants in the condition's entry stack that look like bounds
    for sv in trace.entry_stack:
        pass  # entry stack is pre-comparison

    # Check stack annotations for comparison
    for off, ann in trace.stack_annotations.items():
        if "<" in ann or ">" in ann:
            # Try to find the constant in the comparison
            parts = ann.replace("(", "").replace(")", "").split()
            for p in parts:
                if p.startswith("0x"):
                    try:
                        val = int(p, 16)
                        if 0 < val < 10000:  # reasonable bound
                            return val
                    except ValueError:
                        pass
                elif p.isdigit():
                    val = int(p)
                    if 0 < val < 10000:
                        return val

    return None


def _extract_step(description: str) -> Optional[int]:
    """Try to extract step value from an operation description."""
    import re
    # Look for patterns like "x + 1" or "x + 0x01"
    match = re.search(r'\+\s*(\d+|0x[0-9a-fA-F]+)', description)
    if match:
        val_str = match.group(1)
        try:
            if val_str.startswith("0x"):
                return int(val_str, 16)
            return int(val_str)
        except ValueError:
            pass
    return None
