"""
Function slicer — splits a contract into per-function analysis units.

Instead of treating the entire contract as one monolithic pseudocode block,
this module identifies the dispatcher, slices the CFG by dispatcher jump
targets, and produces isolated FunctionUnit objects for each public function.

Dispatcher blocks are tagged as infrastructure and hidden from semantic output.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from .blocks import BasicBlock, BlockAnalysis
from .selectors import SelectorResult, FunctionEntry
from .stack_sim import SimulationResult


@dataclass
class FunctionUnit:
    """A single public function extracted from the contract."""
    selector: str                    # "0xa9059cbb"
    name: Optional[str]              # "transfer(address,uint256)"
    entry_pc: int                    # bytecode offset of the function body start
    entry_block_id: Optional[int]    # block ID of the entry point
    body_blocks: list[int]           # block IDs belonging to this function
    is_fallback: bool = False
    is_receive: bool = False
    is_constructor: bool = False

    # Recovered attributes (filled by later phases)
    mutability: Optional[str] = None       # "nonpayable", "view", "payable", "pure"
    arg_count: Optional[int] = None
    guards: list[str] = field(default_factory=list)
    state_reads: list[str] = field(default_factory=list)
    state_writes: list[str] = field(default_factory=list)
    external_calls: list[str] = field(default_factory=list)
    events: list[str] = field(default_factory=list)
    branches: list[str] = field(default_factory=list)
    risk_flags: list[str] = field(default_factory=list)


@dataclass
class FunctionSliceResult:
    """Result of function slicing."""
    functions: list[FunctionUnit]
    dispatcher_blocks: list[int]       # blocks that are pure dispatcher infrastructure
    shared_blocks: list[int]           # blocks reachable from multiple functions (internal helpers)
    block_to_function: dict[int, str]  # block_id → selector (for blocks owned by one function)


def slice_functions(
    block_analysis: BlockAnalysis,
    selectors: SelectorResult,
    sim_result: SimulationResult,
    resolved_map: dict[str, str] = None,
) -> FunctionSliceResult:
    """
    Slice the contract CFG into per-function units.

    Strategy:
    1. Identify dispatcher blocks (blocks before function bodies)
    2. For each selector's jump target, BFS through the CFG
    3. Blocks reachable from only one selector → owned by that function
    4. Blocks reachable from multiple → shared helpers
    """
    if not block_analysis.blocks or not selectors.selectors:
        return FunctionSliceResult(
            functions=[], dispatcher_blocks=[], shared_blocks=[],
            block_to_function={},
        )

    if resolved_map is None:
        resolved_map = {}

    blocks = block_analysis.blocks
    block_map = {b.id: b for b in blocks}

    # Build adjacency (successors)
    successors: dict[int, list[int]] = {}
    for b in blocks:
        successors[b.id] = list(b.exits_to)

    # Build offset → block_id map
    offset_to_block: dict[int, int] = {}
    for b in blocks:
        offset_to_block[b.start_offset] = b.id

    # Resolve internal subroutine return addresses so BFS can follow
    # Solidity-style internal function calls (PUSH ret_addr … PUSH target JUMP).
    _resolve_return_address_edges(
        blocks, offset_to_block,
        block_analysis.jumpdest_offsets, successors,
    )

    # ── Step 1: Find dispatcher blocks ────────────────────────
    # The dispatcher is the chain of selector comparisons at the start.
    # We mark blocks from 0 up to the first function body as dispatcher.
    dispatcher_blocks = _find_dispatcher_blocks(
        blocks, selectors, successors, offset_to_block, sim_result,
    )

    # ── Step 2: BFS from each function entry ──────────────────
    function_reachable: dict[str, set[int]] = {}  # selector → reachable block IDs

    for entry in selectors.selectors:
        if entry.jump_target is None:
            continue

        entry_block_id = offset_to_block.get(entry.jump_target)
        if entry_block_id is None:
            continue

        reachable = _bfs_reachable(
            entry_block_id, successors, block_map,
            exclude=set(dispatcher_blocks),
        )
        function_reachable[entry.selector] = reachable

    # ── Step 3: Classify blocks ──────────────────────────────
    # Count how many functions can reach each block
    block_owners: dict[int, list[str]] = {}  # block_id → [selectors that reach it]
    for selector, reachable in function_reachable.items():
        for bid in reachable:
            block_owners.setdefault(bid, []).append(selector)

    shared_blocks = []
    block_to_function: dict[int, str] = {}

    for bid, owners in block_owners.items():
        if len(owners) == 1:
            block_to_function[bid] = owners[0]
        else:
            shared_blocks.append(bid)

    # ── Step 4: Build FunctionUnit objects ────────────────────
    functions: list[FunctionUnit] = []

    for entry in selectors.selectors:
        if entry.jump_target is None:
            continue

        entry_block_id = offset_to_block.get(entry.jump_target)
        reachable = function_reachable.get(entry.selector, set())

        # Body blocks = blocks owned by this function + shared blocks reachable from it
        body_blocks = sorted(
            bid for bid in reachable
            if bid not in dispatcher_blocks
        )

        name = resolved_map.get(entry.selector)

        functions.append(FunctionUnit(
            selector=entry.selector,
            name=name,
            entry_pc=entry.jump_target,
            entry_block_id=entry_block_id,
            body_blocks=body_blocks,
        ))

    # Sort by selector for stable output
    functions.sort(key=lambda f: f.selector)

    return FunctionSliceResult(
        functions=functions,
        dispatcher_blocks=sorted(dispatcher_blocks),
        shared_blocks=sorted(shared_blocks),
        block_to_function=block_to_function,
    )


def _find_dispatcher_blocks(
    blocks: list[BasicBlock],
    selectors: SelectorResult,
    successors: dict[int, list[int]],
    offset_to_block: dict[int, int],
    sim_result: SimulationResult,
) -> list[int]:
    """
    Find blocks that are part of the dispatcher (selector comparison chain).
    
    Heuristic: blocks from block 0 that contain PUSH4 + EQ patterns,
    or blocks before any function body entry point.
    """
    dispatcher_ids = set()

    if not selectors.dispatcher:
        return []

    # All function entry offsets
    function_entry_offsets = set()
    for entry in selectors.selectors:
        if entry.jump_target is not None:
            function_entry_offsets.add(entry.jump_target)

    # Walk from block 0 — any block that is NOT a function entry
    # and is reachable via the dispatcher chain is a dispatcher block.
    # The dispatcher ends when we hit a function body or a terminal.
    visited = set()
    queue = [0]

    while queue:
        bid = queue.pop(0)
        if bid in visited:
            continue
        visited.add(bid)

        block = None
        for b in blocks:
            if b.id == bid:
                block = b
                break
        if block is None:
            continue

        # If this block's start offset is a function entry, it's NOT dispatcher
        if block.start_offset in function_entry_offsets and bid != 0:
            continue

        # Check if this block has selector comparison patterns
        has_selector_cmp = False
        for inst in block.instructions:
            if inst.opcode == "PUSH4":
                has_selector_cmp = True
                break
            if inst.opcode in ("CALLDATALOAD", "CALLDATASIZE"):
                has_selector_cmp = True
                break

        # Block 0 is always dispatcher (entry/init)
        # Blocks with PUSH4 comparisons are dispatcher
        # Blocks between entry and first function body are dispatcher
        if bid == 0 or has_selector_cmp or bid < len(blocks) // 4:
            # Only add if it's early in the code (dispatcher is at the start)
            if block.start_offset < selectors.dispatcher.end_offset + 0x100:
                dispatcher_ids.add(bid)
                for succ in successors.get(bid, []):
                    if succ not in visited:
                        queue.append(succ)

    return sorted(dispatcher_ids)


def _resolve_return_address_edges(
    blocks: list[BasicBlock],
    offset_to_block: dict[int, int],
    jumpdest_offsets: set[int],
    successors: dict[int, list[int]],
) -> None:
    """Add edges for Solidity internal subroutine return addresses.

    Solidity compiles internal function calls as::

        PUSH return_addr      ; continuation after subroutine
        [PUSH args ...]       ; subroutine arguments
        PUSH subroutine_entry ; where the subroutine starts
        JUMP

    ``_resolve_edges`` in ``blocks.py`` only captures the *last* PUSH before
    JUMP as an exit (the subroutine entry).  The return address (an earlier
    PUSH whose value is a valid JUMPDEST) stays on the stack and is consumed
    by the subroutine's terminal ``JUMP`` to return to the caller.

    This function detects the pattern and adds the return addresses as extra
    successor edges so the function slicer's BFS discovers the full body.
    """
    for b in blocks:
        if not b.instructions:
            continue
        last = b.instructions[-1]
        if last.opcode != "JUMP":
            continue

        push_vals: list[int] = []
        for inst in b.instructions:
            if inst.opcode.startswith("PUSH") and inst.operand_value is not None:
                push_vals.append(inst.operand_value)

        if len(push_vals) < 2:
            continue

        # Last PUSH → JUMP target (already in exits_to from _resolve_edges).
        # Earlier PUSHes pointing to valid JUMPDESTs are return addresses.
        for val in push_vals[:-1]:
            if val in jumpdest_offsets:
                target_bid = offset_to_block.get(val)
                if target_bid is not None and target_bid not in successors.get(b.id, []):
                    successors[b.id].append(target_bid)


def _bfs_reachable(
    start_block: int,
    successors: dict[int, list[int]],
    block_map: dict[int, BasicBlock],
    exclude: set[int] = None,
    max_blocks: int = 500,
) -> set[int]:
    """BFS to find all blocks reachable from a starting block."""
    if exclude is None:
        exclude = set()

    visited = set()
    queue = [start_block]

    while queue and len(visited) < max_blocks:
        bid = queue.pop(0)
        if bid in visited or bid in exclude:
            continue
        visited.add(bid)

        for succ in successors.get(bid, []):
            if succ not in visited and succ not in exclude:
                queue.append(succ)

    return visited


def get_function_name_short(func: FunctionUnit) -> str:
    """Get a short display name for a function."""
    if func.name:
        # Extract just the name part: "transfer(address,uint256)" → "transfer"
        paren = func.name.find("(")
        if paren > 0:
            return func.name[:paren]
        return func.name
    return func.selector
