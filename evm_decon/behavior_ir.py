"""
Bytecode behavior IR.

This is the canonical bridge between low-level stack/basic-block traces and
the production audit behavior JSON. It intentionally models behavior without
requiring function names.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .behavior_sections import (
    control_flow,
    dataflow,
    detect_bytecode_guards,
    external_interactions,
    path_summary,
    reachable_blocks,
    state_effects,
    trust,
)
from .blocks import BlockAnalysis
from .function_slicer import FunctionSliceResult, FunctionUnit
from .stack_sim import SimulationResult


@dataclass
class BehaviorAction:
    id: str
    type: str
    block: int
    offset: str
    order: int
    reads: list[str] = field(default_factory=list)
    writes: list[str] = field(default_factory=list)
    expression: Optional[str] = None
    target: Optional[str] = None
    value: Optional[str] = None
    args: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)


def build_behavior_ir(
    slice_result: Optional[FunctionSliceResult],
    sim_result: Optional[SimulationResult],
    block_analysis: Optional[BlockAnalysis],
    semantic_analysis=None,
) -> dict[str, Any]:
    if not slice_result or not sim_result or not block_analysis:
        return {"functions": {}, "edges": [], "global_tags": []}

    cards = {}
    if semantic_analysis:
        cards = {c.selector: c for c in semantic_analysis.function_cards}

    block_map = {b.id: b for b in block_analysis.blocks}
    functions: dict[str, Any] = {}
    graph_edges: list[dict[str, Any]] = []

    for func in slice_result.functions:
        card = cards.get(func.selector)
        actions = _actions_for_function(func, sim_result, block_map)
        state_effects_data = state_effects(actions, card)
        external_interactions_data = external_interactions(actions, card)
        dataflow_data = dataflow(actions)
        control_flow_data = control_flow(func, sim_result, block_map)
        tags = _behavior_tags(actions, state_effects_data, external_interactions_data, dataflow_data, card, block_map, func)
        summary = path_summary(control_flow_data, state_effects_data, external_interactions_data)

        for action in actions:
            for dep in action.evidence.get("depends_on", []):
                graph_edges.append({"from": dep, "to": action.id, "kind": "depends_on"})

        functions[func.selector] = {
            "actions": [_action_to_dict(a) for a in actions],
            "state_effects": state_effects_data,
            "external_interactions": external_interactions_data,
            "dataflow": dataflow_data,
            "control_flow": control_flow_data,
            "behavior_tags": tags,
            "path_summary": summary,
        }

    return {
        "functions": functions,
        "edges": graph_edges,
        "global_tags": sorted({tag for f in functions.values() for tag in f["behavior_tags"]}),
    }


def _actions_for_function(
    func: FunctionUnit,
    sim: SimulationResult,
    block_map: dict[int, Any],
) -> list[BehaviorAction]:
    actions: list[BehaviorAction] = []
    order = 0

    for bid in sorted(func.body_blocks):
        block = block_map.get(bid)
        trace = sim.traces.get(bid)
        if not block:
            continue

        if trace:
            for op in trace.storage_ops:
                action_type = "SLOAD" if op.op_type == "read" else "SSTORE"
                slot = repr(op.slot)
                value = repr(op.value) if op.value is not None else None
                action = BehaviorAction(
                    id=f"{func.selector}:{order}",
                    type=action_type,
                    block=bid,
                    offset=f"0x{op.offset_in_code:04x}",
                    order=order,
                    reads=[slot] if op.op_type == "read" else [],
                    writes=[slot] if op.op_type == "write" else [],
                    expression=f"storage[{slot}]" if op.op_type == "read" else f"storage[{slot}] = {value}",
                    value=value,
                    evidence={"slot": slot, "value": value, "trust_source": "bytecode_inferred"},
                )
                actions.append(action)
                order += 1

            for op in trace.operations:
                if op.category == "call":
                    desc = op.description.lower()
                    if "delegatecall" in desc:
                        call_type = "DELEGATECALL"
                    elif "staticcall" in desc:
                        call_type = "STATICCALL"
                    elif "callcode" in desc:
                        call_type = "CALLCODE"
                    else:
                        call_type = "CALL"
                    target, value = _parse_call_target_value(op.description)
                    rv_consumed = _return_value_checked_cross_block(block, op.offset, block_map, func.body_blocks)
                    action = BehaviorAction(
                        id=f"{func.selector}:{order}",
                        type=call_type,
                        block=bid,
                        offset=f"0x{op.offset:04x}",
                        order=order,
                        target=target,
                        value=value,
                        expression=op.description,
                        evidence={
                            "description": op.description,
                            "trust_source": "bytecode_inferred",
                            "return_value_consumed": rv_consumed,
                        },
                    )
                    actions.append(action)
                    order += 1

            for op in trace.memory_ops:
                action_type = "MLOAD" if op.op_type == "read" else "MSTORE"
                address = repr(op.address)
                value = repr(op.value) if op.value is not None else None
                actions.append(BehaviorAction(
                    id=f"{func.selector}:{order}",
                    type=action_type,
                    block=bid,
                    offset=f"0x{op.offset_in_code:04x}",
                    order=order,
                    reads=[f"memory[{address}]"] if op.op_type == "read" else [],
                    writes=[f"memory[{address}]"] if op.op_type == "write" else [],
                    expression=f"memory[{address}]" if op.op_type == "read" else f"memory[{address}] = {value}",
                    value=value,
                    evidence={"address": address, "value": value, "trust_source": "bytecode_inferred"},
                ))
                order += 1

        for inst in block.instructions:
            if inst.opcode.startswith("LOG"):
                actions.append(BehaviorAction(
                    id=f"{func.selector}:{order}",
                    type="LOG",
                    block=bid,
                    offset=f"0x{inst.offset:04x}",
                    order=order,
                    expression=inst.opcode,
                    evidence={"opcode": inst.opcode, "trust_source": "bytecode_inferred"},
                ))
                order += 1
            elif inst.opcode in ("RETURN", "REVERT", "CREATE", "CREATE2", "SELFDESTRUCT", "DELEGATECALL", "CALL"):
                # CALL/DELEGATECALL are usually already captured with args by
                # stack simulation. Add only missing system actions here.
                if inst.opcode in ("CALL", "DELEGATECALL") and any(a.offset == f"0x{inst.offset:04x}" for a in actions):
                    continue
                actions.append(BehaviorAction(
                    id=f"{func.selector}:{order}",
                    type=inst.opcode,
                    block=bid,
                    offset=f"0x{inst.offset:04x}",
                    order=order,
                    expression=inst.opcode,
                    evidence={"opcode": inst.opcode, "trust_source": "bytecode_inferred"},
                ))
                order += 1

    actions.sort(key=lambda a: (a.block, int(a.offset, 16), a.order))
    for idx, action in enumerate(actions):
        action.order = idx
        action.id = f"{func.selector}:{idx}"
    return actions


def _return_value_checked_cross_block(
    block: Any,
    call_offset: int,
    block_map: dict[int, Any],
    body_blocks: set[int],
) -> bool:
    """Check if instructions after a CALL check its return value.

    Extends the original single-block check to follow successor blocks,
    detecting patterns like:
    - Standard ISZERO check in the same block
    - Assembly switch(result) pattern: ISZERO in a successor block
    - RETURNDATASIZE + RETURNDATACOPY before revert/return (proxy pattern)
    - Any branch condition consuming the return value within 3 hops

    This is critical for proxy contracts where the assembly uses:
      switch result
      case 0 { revert(0, returndatasize()) }
      default { return(0, returndatasize()) }
    which compiles to ISZERO + JUMPI in a successor block.
    """
    # Phase 1: Check same block (fast path)
    found_call = False
    for inst in block.instructions:
        if inst.offset == call_offset:
            found_call = True
            continue
        if found_call:
            if inst.opcode in ("ISZERO", "RETURNDATASIZE", "RETURNDATACOPY"):
                return True
            if inst.opcode == "POP":
                return False
            # If the block branches (JUMPI), the return value may be consumed
            # as the branch condition itself — this IS a check
            if inst.opcode == "JUMPI":
                # The success bool is the branch condition → it IS checked
                return True
            if inst.opcode in ("JUMP", "REVERT", "RETURN", "STOP"):
                break

    # Phase 2: Check successor blocks (cross-block analysis)
    # Follow exits_to for up to 3 hops looking for return value consumption
    visited: set[int] = {block.id}
    frontier: list[int] = list(block.exits_to) if hasattr(block, 'exits_to') else []
    hops = 0
    max_hops = 3

    while frontier and hops < max_hops:
        next_frontier: list[int] = []
        for successor_id in frontier:
            if successor_id in visited:
                continue
            if successor_id not in body_blocks and successor_id not in block_map:
                continue
            visited.add(successor_id)
            successor = block_map.get(successor_id)
            if not successor:
                continue

            for inst in successor.instructions:
                if inst.opcode in ("ISZERO", "RETURNDATASIZE", "RETURNDATACOPY"):
                    return True
                if inst.opcode == "JUMPI":
                    # Branch condition consumes the top of stack — which could
                    # be the return value passed through from the call block
                    return True
                if inst.opcode == "POP":
                    return False
                if inst.opcode in ("REVERT", "RETURN", "STOP", "INVALID"):
                    # Terminal block with no check — but check other branches
                    break
                # Skip JUMPDESTs and other non-consuming opcodes
                if inst.opcode in ("JUMPDEST", "DUP1", "DUP2", "SWAP1", "SWAP2"):
                    continue
                # Any other opcode that consumes stack but isn't a check
                break

            if hasattr(successor, 'exits_to'):
                next_frontier.extend(successor.exits_to)

        frontier = next_frontier
        hops += 1

    return False


def _behavior_tags(actions, state_effects, external_interactions, dataflow, card, block_map=None, func=None) -> list[str]:
    tags = set()
    if state_effects["writes"]:
        tags.add("PUBLIC_STATE_WRITE")
    if state_effects["reads"]:
        tags.add("STATE_READ")
    if external_interactions:
        tags.add("EXTERNAL_INTERACTION")
    if any(i["kind"] == "DELEGATECALL" for i in external_interactions):
        tags.add("DELEGATECALL_PRESENT")
    if any(a.type == "SELFDESTRUCT" for a in actions):
        tags.add("SELFDESTRUCT_PRESENT")
    if any(t["kind"] == "tx.origin" for t in dataflow["sources"]):
        tags.add("TX_ORIGIN_OBSERVED")
    if any(t["kind"] == "calldata" for t in dataflow["sources"]):
        tags.add("USER_INPUT_DEPENDENT")
    if dataflow["traces"]:
        tags.add("SOURCE_TO_SINK_TRACE")

    # External call detected
    if external_interactions:
        tags.add("EXTERNAL_CALL_OBSERVED")

    # ── Path-aware reentrancy analysis ──────────────────────────────────
    # Instead of comparing flat action order numbers, verify that the SSTORE
    # and CALL/DELEGATECALL are on the same execution path using CFG edges.
    first_call = min((i["position"] for i in external_interactions if i["position"] is not None), default=None)
    if first_call is not None and state_effects["writes"]:
        call_actions = [
            a for a in actions
            if a.type in ("CALL", "DELEGATECALL", "CALLCODE")
        ]
        write_actions = [
            a for a in actions
            if a.type == "SSTORE"
        ]

        # Get blocks containing calls and writes
        call_blocks = {a.block for a in call_actions}
        write_blocks = {a.block for a in write_actions}

        # Check if any write block is reachable from a call block
        # (i.e., the SSTORE is on a path AFTER the CALL)
        has_path_verified_write_after_call = False
        has_coarse_write_after_call = False

        write_positions = [
            int(w["action_id"].split(":")[-1])
            for w in state_effects["writes"]
            if w.get("action_id")
        ]

        if any(pos > first_call for pos in write_positions):
            has_coarse_write_after_call = True

        # Path-verified check: is a write block reachable from a call block
        # via CFG edges? This catches the common proxy false positive where
        # SSTORE is in a predecessor block, not a successor.
        if block_map and has_coarse_write_after_call:
            for call_block_id in call_blocks:
                call_block = block_map.get(call_block_id)
                if not call_block or not hasattr(call_block, 'exits_to'):
                    continue
                # BFS from call block's successors
                reachable = reachable_blocks(call_block_id, block_map, max_depth=10)
                for wb_id in write_blocks:
                    if wb_id in reachable and wb_id != call_block_id:
                        has_path_verified_write_after_call = True
                        break
                    # Also check: write in the SAME block AFTER the call offset
                    if wb_id == call_block_id:
                        call_offsets = [
                            int(a.offset, 16) for a in call_actions
                            if a.block == call_block_id
                        ]
                        write_offsets = [
                            int(a.offset, 16) for a in write_actions
                            if a.block == wb_id
                        ]
                        if call_offsets and write_offsets:
                            max_call = max(call_offsets)
                            if any(wo > max_call for wo in write_offsets):
                                has_path_verified_write_after_call = True
                                break
                if has_path_verified_write_after_call:
                    break

        if has_path_verified_write_after_call:
            tags.add("EXTERNAL_CALL_BEFORE_STATE_UPDATE")
            tags.add("STATE_WRITE_AFTER_CALL")
            tags.add("VERIFIED_STATE_WRITE_AFTER_CALL")
        elif has_coarse_write_after_call:
            # Coarse match only — keep for backward compat but mark as unverified
            tags.add("EXTERNAL_CALL_BEFORE_STATE_UPDATE")
            tags.add("STATE_WRITE_AFTER_CALL")
            tags.add("UNVERIFIED_STATE_WRITE_AFTER_CALL")

    # ── Unchecked return values ─────────────────────────────────────────
    for action in actions:
        if action.type in ("CALL", "DELEGATECALL", "CALLCODE"):
            rv = action.evidence.get("return_value_consumed")
            if rv is False:
                tags.add("UNCHECKED_RETURN_VALUE")
                break

    # Unchecked arithmetic (pre-Solidity 0.8 without SafeMath)
    has_arithmetic = any(a.type in ("ADD", "SUB", "MUL", "DIV") for a in actions)
    has_overflow_check = any(
        a.type == "SLOAD" and "safemath" in str(a.expression or "").lower()
        for a in actions
    )
    if has_arithmetic and not has_overflow_check:
        # Only tag if no built-in overflow protection detected
        has_revert_on_overflow = any(
            a.type == "REVERT" and a.order > 0
            for a in actions
        )
        if not has_revert_on_overflow:
            tags.add("UNCHECKED_ARITHMETIC")

    # ── Bytecode-level guard detection ──────────────────────────────────
    # Detect admin/owner guards from bytecode: CALLER → SLOAD(slot) → EQ → JUMPI
    if block_map and func:
        guard_tags = detect_bytecode_guards(func, block_map)
        tags.update(guard_tags)

    if card:
        if card.guards:
            tags.add("GUARDED")
        if any(g in card.guards for g in ("onlyOwner", "factoryOnly", "tx_origin_whitelist", "msg_sender_guard")):
            tags.add("AUTH_GUARDED")
        if "tx_origin_whitelist" in card.guards:
            tags.add("TX_ORIGIN_WHITELIST")
        if "lock" in card.guards:
            tags.add("REENTRANCY_LOCK")
            tags.add("REENTRANCY_GUARD")
        if any(g in card.guards for g in ("nonReentrant", "reentrancyGuard")):
            tags.add("REENTRANCY_GUARD")
        if "constant_product_fee_adjusted_invariant" in card.guards:
            tags.add("INVARIANT_CHECK_AFTER_CALL")
        for event in card.events:
            tags.add(f"EVENT_{event.upper()}")

    return sorted(tags)


def _action_to_dict(action: BehaviorAction) -> dict[str, Any]:
    result = {
        "id": action.id,
        "type": action.type,
        "block": action.block,
        "offset": action.offset,
        "order": action.order,
        "evidence": action.evidence,
        "trust": trust("bytecode_inferred", 0.75, True),
    }
    for key in ("reads", "writes", "expression", "target", "value", "args"):
        value = getattr(action, key)
        if value:
            result[key] = value
    return result

def _parse_call_target_value(description: str) -> tuple[Optional[str], Optional[str]]:
    target = None
    value = None
    for part in description.replace(")", "").split(","):
        part = part.strip()
        if part.startswith("to="):
            target = part[3:]
        elif part.startswith("value="):
            value = part[6:]
    return target, value
