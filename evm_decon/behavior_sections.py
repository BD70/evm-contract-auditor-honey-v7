"""Composable behavior IR section builders."""

from __future__ import annotations

import re
from typing import Any, Optional

from .function_slicer import FunctionUnit
from .stack_sim import SimulationResult


def state_effects(actions: list[Any], card: Any) -> dict[str, Any]:
    reads = []
    writes = []

    for action in actions:
        if action.type == "SLOAD":
            reads.append({
                "action_id": action.id,
                "slot": action.evidence.get("slot"),
                "expression": action.expression,
                "offset": action.offset,
                "trust": trust("bytecode_inferred", 0.75, True),
            })
        elif action.type == "SSTORE":
            writes.append({
                "action_id": action.id,
                "slot": action.evidence.get("slot"),
                "new_value": action.value,
                "expression": action.expression,
                "offset": action.offset,
                "trust": trust("bytecode_inferred", 0.75, True),
            })

    semantic_summary = {}
    if card:
        semantic_summary = {
            "reads": list(card.state_reads),
            "writes": list(card.state_writes),
            "events": list(card.events),
            "guards": list(card.guards),
            "trust": trust(
                card.semantic_trust_source,
                card.semantic_trust_confidence,
                card.semantic_usable_as_detector_proof,
            ),
        }

    return {
        "reads": reads,
        "writes": writes,
        "semantic_summary": semantic_summary,
    }


def external_interactions(actions: list[Any], card: Any) -> list[dict[str, Any]]:
    interactions = []
    for action in actions:
        if action.type in ("CALL", "DELEGATECALL", "STATICCALL", "CALLCODE"):
            interactions.append({
                "action_id": action.id,
                "kind": action.type,
                "target": action.target,
                "value": action.value,
                "calldata_selector": extract_selector(action.expression or ""),
                "success_handling": "unknown",
                "position": action.order,
                "evidence": action.evidence,
                "trust": trust("bytecode_inferred", 0.75, True),
            })

    if card:
        semantic_call_trust = trust(
            card.semantic_trust_source,
            card.semantic_trust_confidence,
            card.semantic_usable_as_detector_proof,
        )
        for call in card.external_calls:
            if not semantic_call_trust["usable_as_detector_proof"]:
                continue
            interactions.append({
                "action_id": None,
                "kind": "SEMANTIC_CALL",
                "target": call,
                "value": None,
                "calldata_selector": extract_selector(call),
                "success_handling": "protocol_or_high_level_summary",
                "position": None,
                "evidence": {"semantic_call": call},
                "trust": semantic_call_trust,
            })
    return interactions


def dataflow(actions: list[Any]) -> dict[str, Any]:
    sources = []
    sinks = []
    propagations = []
    traces = []

    for action in actions:
        text = " ".join(filter(None, [action.expression, action.target, action.value]))
        action_sources = []
        for source_name in ("calldata", "msg.sender", "msg.value", "tx.origin"):
            if source_name in text:
                source = {
                    "id": f"src:{action.id}:{source_name}",
                    "kind": source_name,
                    "action_id": action.id,
                    "offset": action.offset,
                    "trust": trust("bytecode_inferred", 0.6, True),
                }
                sources.append(source)
                action_sources.append(source["id"])

        if action.type in ("SSTORE", "CALL", "DELEGATECALL", "SELFDESTRUCT", "CREATE", "CREATE2"):
            sink = {
                "id": f"sink:{action.id}",
                "kind": action.type,
                "action_id": action.id,
                "offset": action.offset,
                "trust": trust("bytecode_inferred", 0.65, True),
            }
            sinks.append(sink)
            for source in action_sources:
                traces.append({
                    "source": source,
                    "sink": sink["id"],
                    "path": [source, action.id, sink["id"]],
                    "confidence": 0.55,
                    "trust": trust("bytecode_inferred", 0.55, True),
                })

        if action_sources:
            propagations.append({
                "action_id": action.id,
                "from": action_sources,
                "to": [action.id],
                "kind": "expression_dependency",
            })

    return {
        "sources": sources,
        "propagations": propagations,
        "sanitizers": [],
        "sinks": sinks,
        "traces": traces,
    }


def control_flow(func: FunctionUnit, sim: SimulationResult, block_map: dict[int, Any]) -> dict[str, Any]:
    branches = []
    reverts = []
    returns = []
    paths = []

    for bid in sorted(func.body_blocks):
        trace = sim.traces.get(bid)
        block = block_map.get(bid)
        if trace and trace.branch_condition:
            branches.append({
                "block": bid,
                "condition": repr(trace.branch_condition),
                "true_target": trace.branch_true_target,
                "false_target": trace.branch_false_target,
            })
        if block:
            for inst in block.instructions:
                if inst.opcode == "REVERT":
                    reverts.append({"block": bid, "offset": f"0x{inst.offset:04x}"})
                elif inst.opcode == "RETURN":
                    returns.append({"block": bid, "offset": f"0x{inst.offset:04x}"})

    paths.append({
        "id": f"{func.selector}:path:summary",
        "entry_block": func.entry_block_id,
        "blocks": sorted(func.body_blocks),
        "branch_count": len(branches),
        "revert_count": len(reverts),
        "return_count": len(returns),
    })
    return {
        "entry_block": func.entry_block_id,
        "blocks": sorted(func.body_blocks),
        "branches": branches,
        "reverts": reverts,
        "returns": returns,
        "loops": [],
        "paths": paths,
    }


def path_summary(
    control_flow_data: dict[str, Any],
    state_effects_data: dict[str, Any],
    external_interactions_data: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "requires": [branch["condition"] for branch in control_flow_data["branches"]],
        "effects": {
            "state_reads": len(state_effects_data["reads"]),
            "state_writes": len(state_effects_data["writes"]),
        },
        "calls": len(external_interactions_data),
        "reverts": len(control_flow_data["reverts"]),
        "returns": len(control_flow_data["returns"]),
    }


def trust(source: str, confidence: float, usable_as_detector_proof: bool) -> dict[str, Any]:
    return {
        "trust_source": source,
        "confidence": confidence,
        "usable_as_detector_proof": usable_as_detector_proof,
    }


def reachable_blocks(start_block_id: int, block_map: dict[int, Any], max_depth: int = 10) -> set[int]:
    visited: set[int] = set()
    frontier = [start_block_id]
    depth = 0
    while frontier and depth < max_depth:
        next_frontier: list[int] = []
        for bid in frontier:
            if bid in visited:
                continue
            visited.add(bid)
            block = block_map.get(bid)
            if block and hasattr(block, "exits_to"):
                next_frontier.extend(block.exits_to)
        frontier = next_frontier
        depth += 1
    return visited


def detect_bytecode_guards(func: Any, block_map: dict[int, Any]) -> set[str]:
    tags: set[str] = set()

    for bid in func.body_blocks:
        block = block_map.get(bid)
        if not block:
            continue

        opcodes = [inst.opcode for inst in block.instructions]
        has_caller = "CALLER" in opcodes
        has_eq = "EQ" in opcodes
        has_jumpi = block.terminator == "JUMPI"
        has_sload = "SLOAD" in opcodes

        if has_caller and has_eq and has_jumpi and has_sload:
            tags.update({"GUARDED", "AUTH_GUARDED", "ADMIN_GUARD", "admin_guarded_function"})
            if hasattr(block, "exits_to"):
                for exit_id in block.exits_to:
                    exit_block = block_map.get(exit_id)
                    if exit_block and exit_block.terminator == "REVERT":
                        tags.add("STRONG_AUTH_GUARD")
                        break

        has_sub = "SUB" in opcodes
        if has_caller and has_sub and has_jumpi and has_sload:
            tags.update({"GUARDED", "AUTH_GUARDED"})

        sload_count = opcodes.count("SLOAD")
        sstore_count = opcodes.count("SSTORE")
        if sload_count >= 1 and sstore_count >= 1 and has_jumpi:
            for i, inst in enumerate(block.instructions):
                if inst.opcode != "SLOAD":
                    continue
                remaining = [block.instructions[j].opcode for j in range(i + 1, min(i + 6, len(block.instructions)))]
                if "EQ" in remaining and "JUMPI" in remaining:
                    for j in range(i + 1, min(i + 4, len(block.instructions))):
                        inst_j = block.instructions[j]
                        if inst_j.opcode.startswith("PUSH") and inst_j.operand_value in (1, 2):
                            tags.update({"REENTRANCY_GUARD", "reentrancy_guard", "mutex_lock"})
                            break
                break

    return tags


def extract_selector(text: str) -> Optional[str]:
    match = re.search(r"0x[0-9a-fA-F]{8}", text)
    return match.group(0) if match else None
