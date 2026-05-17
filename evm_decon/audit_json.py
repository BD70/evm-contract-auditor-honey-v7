"""
Production audit behavior JSON.

This module is the machine-output surface for downstream vulnerability
checking. It intentionally favors typed behavior facts over rendered reports
or selector-name based summaries.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from evm_core.schemas import (
    BEHAVIOR_SCHEMA_V2,
    BEHAVIOR_SCHEMA_VERSION,
    STATE_MODEL_SCHEMA_V2,
    STATE_MODEL_SCHEMA_VERSION,
)

from .behavior_ir import build_behavior_ir
from .known_bytecodes import BytecodeFingerprint, fingerprint_bytecode
from .version import ENGINE_VERSION, RULESET_VERSION, SCHEMA_VERSION


SCHEMA = BEHAVIOR_SCHEMA_V2
FIXED_POINT_SCALE = 10**18


def build_audit_json(
    full_output: dict[str, Any],
    semantic_analysis=None,
    storage_layout=None,
    slice_result=None,
    sim_result=None,
    block_analysis=None,
    bytecode_hex: str = "",
    analysis_context: dict[str, Any] | None = None,
    diagnostics: dict[str, Any] | None = None,
    timings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    behavior = build_behavior_ir(slice_result, sim_result, block_analysis, semantic_analysis)
    cards = {c.selector: c for c in semantic_analysis.function_cards} if semantic_analysis else {}
    behavior_functions = behavior.get("functions", {})

    # Run bytecode fingerprinting for known-safe pattern detection
    fingerprint = fingerprint_bytecode(bytecode_hex) if bytecode_hex else BytecodeFingerprint()
    fingerprint_tags = set(fingerprint.tags)

    functions = []
    all_calls = []
    all_events = []
    all_flows = []
    all_arithmetic = []

    # Collect contract-level pattern roles for use in function tag synthesis
    contract_patterns: list[str] = []
    if semantic_analysis:
        for pattern in semantic_analysis.patterns:
            if pattern.confidence >= 0.7:
                contract_patterns.append(pattern.pattern_name)

    for fn_row in full_output.get("functions", []):
        selector = fn_row.get("selector")
        fn_behavior = behavior_functions.get(selector, _empty_function_behavior())
        card = cards.get(selector)
        arithmetic = _function_arithmetic(selector, fn_behavior, sim_result)
        function = _function_json(fn_row, fn_behavior, card, arithmetic, contract_patterns=contract_patterns)

        # Propagate bytecode fingerprint tags to function-level tags
        # so that function-scope rules can use them for counter-evidence
        if fingerprint_tags:
            fn_tags = set(function.get("behavior_tags", []))
            fn_tags.update(fingerprint_tags)
            function["behavior_tags"] = sorted(fn_tags)

        functions.append(function)
        all_calls.extend(_with_function(selector, function["external_calls"]))
        all_events.extend(_events_for_function(selector, function))
        all_flows.extend(_with_function(selector, function["flows"]))
        all_arithmetic.extend(_with_function(selector, arithmetic))

    storage = _storage_json(storage_layout, functions)
    invariants = _invariants_json(functions, all_arithmetic)
    state_model = _state_model(storage, functions, invariants, sim_result=sim_result, block_analysis=block_analysis, slice_result=slice_result, fingerprint=fingerprint)

    # Build global tags combining behavior IR global tags and fingerprint tags
    global_tags = sorted(set(behavior.get("global_tags", [])) | fingerprint_tags)

    return {
        "schema": SCHEMA,
        "schema_version": BEHAVIOR_SCHEMA_VERSION,
        "engine_version": ENGINE_VERSION,
        "ruleset_version": RULESET_VERSION,
        "analysis_context": analysis_context or {},
        "bytecode_identity": _bytecode_identity(full_output),
        "bytecode": _bytecode_json(full_output),
        "contract": _contract_json(full_output, semantic_analysis),
        "functions": functions,
        "storage": storage,
        "memory": _memory_json(sim_result),
        "arithmetic": {
            "facts": all_arithmetic,
            "summary": _arithmetic_summary(all_arithmetic),
        },
        "calls": all_calls,
        "events": all_events,
        "flows": all_flows,
        "invariants": invariants,
        "assumptions": _assumptions_json(full_output, semantic_analysis),
        "analysis_warnings": _analysis_warnings(full_output, functions),
        "diagnostics": diagnostics or {},
        "timings": timings or [],
        "coverage": _coverage_json(full_output, functions, storage, state_model),
        "state_model": state_model,
        "global_tags": global_tags,
        "bytecode_fingerprint": {
            "tags": fingerprint.tags,
            "proxy_type": fingerprint.proxy_type,
            "has_erc1967": fingerprint.has_erc1967_impl_slot,
            "has_proxy_forwarding": fingerprint.has_proxy_forwarding,
            "has_reentrancy_guard": fingerprint.has_reentrancy_guard_constants,
            "has_initializer": fingerprint.has_initializer_pattern,
            "has_diamond": fingerprint.has_diamond,
            "has_gnosis_safe": fingerprint.has_gnosis_safe,
            "has_compound_unitroller": fingerprint.has_compound_unitroller,
            "has_eip897": fingerprint.has_eip897,
            "has_slot0_proxy": fingerprint.has_slot0_proxy,
            "implementation_address": fingerprint.implementation_address,
            "diamond_loupe_selectors": fingerprint.diamond_loupe_selectors,
            "proxy_selectors": fingerprint.proxy_selectors_found,
        },
        "proxy_analysis": _proxy_analysis(fingerprint),
        "checker_findings": [],
    }


def _proxy_analysis(fingerprint) -> dict[str, Any]:
    """Build structured proxy analysis from fingerprint."""
    is_proxy = fingerprint.proxy_type is not None
    if not is_proxy:
        return {"is_proxy": False}

    # Map proxy types to their EIP standards
    standard_map = {
        "TRANSPARENT_PROXY": "EIP-1967",
        "UUPS_PROXY": "EIP-1822/EIP-1967",
        "BEACON_PROXY": "EIP-1967",
        "ERC1967_PROXY": "EIP-1967",
        "ERC1167_CLONE": "EIP-1167",
        "DIAMOND_PROXY": "EIP-2535",
        "GNOSIS_SAFE_PROXY": "GnosisSafe/slot-0",
        "COMPOUND_UNITROLLER": "Compound/two-step",
        "EIP897_DELEGATE_PROXY": "EIP-897",
        "SLOT0_PROXY": "custom/slot-0",
        "VYPER_MINIMAL_PROXY": "EIP-1167/Vyper",
        "GENERIC_PROXY": "custom",
    }

    # Build implementation extraction info
    extraction = {}
    if fingerprint.implementation_address:
        extraction = {
            "method": "bytecode_embedded",
            "address": fingerprint.implementation_address,
            "confidence": 0.99,
        }
    elif fingerprint.has_erc1967_impl_slot:
        extraction = {
            "method": "storage_slot",
            "slot": "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
            "confidence": 0.95,
            "note": "requires eth_getStorageAt to read actual address",
        }
    elif fingerprint.has_slot0_proxy or fingerprint.has_gnosis_safe:
        extraction = {
            "method": "storage_slot_0",
            "slot": "0x0",
            "confidence": 0.85,
            "note": "implementation at storage slot 0; requires eth_getStorageAt",
        }
    elif fingerprint.has_diamond:
        extraction = {
            "method": "facet_routing",
            "confidence": 0.90,
            "note": "diamond routes selectors to multiple facets; call facets() to enumerate",
        }

    # Audit implications
    implications = []
    if fingerprint.has_proxy_forwarding or fingerprint.has_diamond:
        implications.append("delegatecall_is_operational")
    if fingerprint.has_erc1967_admin_slot or fingerprint.has_gnosis_safe:
        implications.append("sstore_is_admin_guarded")
    if fingerprint.has_proxy_forwarding:
        implications.append("fallback_forwards_all_calls")
    if fingerprint.has_two_step_upgrade:
        implications.append("upgrade_requires_two_step_acceptance")
    if fingerprint.has_erc1167_clone or fingerprint.has_vyper_proxy:
        implications.append("implementation_is_immutable")
    if fingerprint.has_diamond:
        implications.append("multiple_implementation_facets")

    return {
        "is_proxy": True,
        "proxy_type": fingerprint.proxy_type,
        "proxy_standard": standard_map.get(fingerprint.proxy_type, "unknown"),
        "implementation_extraction": extraction,
        "audit_implications": implications,
        "proxy_selectors_found": fingerprint.proxy_selectors_found,
    }


def _bytecode_json(full_output: dict[str, Any]) -> dict[str, Any]:
    meta = full_output.get("meta", {})
    hashes = meta.get("bytecode", {})
    return {
        "size": meta.get("bytecode_size"),
        "instruction_count": meta.get("instruction_count"),
        "hash": meta.get("bytecode_hash"),
        "original_hash": hashes.get("original_hash"),
        "runtime_hash": hashes.get("runtime_hash"),
        "analysis_hash": hashes.get("analysis_hash"),
        "runtime_size": hashes.get("runtime_size"),
        "analysis_size": hashes.get("analysis_size"),
        "metadata_stripped": hashes.get("metadata_stripped", False),
        "compiler": meta.get("compiler", {}),
        "metadata": {
            "hash": meta.get("metadata_hash"),
            "offset": meta.get("metadata_offset"),
            "cbor_length": meta.get("cbor_length"),
        },
    }


def _bytecode_identity(full_output: dict[str, Any]) -> dict[str, Any]:
    meta = full_output.get("meta", {})
    hashes = meta.get("bytecode", {})
    return {
        "keccak256": meta.get("bytecode_hash"),
        "original_keccak256": hashes.get("original_hash"),
        "runtime_keccak256": hashes.get("runtime_hash"),
        "metadata_stripped_keccak256": hashes.get("analysis_hash"),
    }


def _contract_json(full_output: dict[str, Any], semantic_analysis) -> dict[str, Any]:
    selectors = []
    for fn in full_output.get("functions", []):
        selectors.append({
            "selector": fn.get("selector"),
            "candidates": fn.get("resolved_names", []),
            "primary_name": fn.get("primary_name"),
            "source": fn.get("source"),
            "confidence": fn.get("confidence"),
            "jump_target": fn.get("jump_target"),
            "trust": _trust("selector_label", 0.4, False),
        })

    roles = []
    patterns = []
    family = "Unknown"
    if semantic_analysis:
        family = semantic_analysis.contract_family
        seen_patterns = set()
        for pattern in semantic_analysis.patterns:
            if pattern.pattern_name in seen_patterns:
                continue
            seen_patterns.add(pattern.pattern_name)
            entry = {
                "name": pattern.pattern_name,
                "confidence": pattern.confidence,
                "evidence": list(pattern.evidence),
                "details": pattern.details,
                "trust": _pattern_trust(pattern),
            }
            patterns.append(entry)
            if pattern.confidence >= 0.7 and pattern.pattern_name not in roles:
                roles.append(pattern.pattern_name)

    return {
        "family": family,
        "protocol_roles": roles,
        "patterns": patterns,
        "selectors": {
            "resolved": selectors,
            "unresolved": full_output.get("unresolved_selectors", []),
        },
        "classification": full_output.get("classification", {}),
    }


def _function_json(fn_row: dict[str, Any], behavior: dict[str, Any], card, arithmetic: list[dict[str, Any]], *, contract_patterns: list[str] | None = None) -> dict[str, Any]:
    selector = fn_row.get("selector")
    function_id = _function_id(selector)
    semantic = {
        "guards": list(card.guards) if card else [],
        "reads": list(card.state_reads) if card else [],
        "writes": list(card.state_writes) if card else [],
        "events": list(card.events) if card else [],
        "risk_flags": list(card.risk_flags) if card else [],
        "trust": _trust(
            card.semantic_trust_source,
            card.semantic_trust_confidence,
            card.semantic_usable_as_detector_proof,
        ) if card else _trust("heuristic", 0.4, False),
    }
    tags = set(behavior.get("behavior_tags", []))
    tags.update(_arithmetic_tags(arithmetic))
    tags.update(_semantic_behavior_tags(semantic))

    external_calls = list(behavior.get("external_interactions", []))

    # Enrich external calls with semantic effects from profile hints
    for call in external_calls:
        if not call.get("semantic_effect"):
            effect = _infer_semantic_effect_from_call(call)
            if effect:
                call["semantic_effect"] = effect

    function = {
        "identity": {
            "id": function_id,
            "selector": selector,
            "name": fn_row.get("primary_name"),
            "candidate_names": fn_row.get("resolved_names", []),
            "signature_source": fn_row.get("source"),
            "signature_confidence": fn_row.get("confidence"),
            "entry_pc": fn_row.get("jump_target"),
            "entry_block": behavior.get("control_flow", {}).get("entry_block"),
            "trust": _trust("selector_label", 0.4, False),
        },
        "interface": {
            "mutability": card.mutability if card else None,
            "mutability_confidence": 0.85 if card and card.mutability else 0.0,
        },
        "control_flow": behavior.get("control_flow", {}),
        "paths": behavior.get("control_flow", {}).get("paths", []),
        "actions": behavior.get("actions", []),
        "state": behavior.get("state_effects", {}),
        "memory": _function_memory(behavior),
        "external_calls": external_calls,
        "arithmetic": arithmetic,
        "accounting": [],
        "flows": behavior.get("dataflow", {}).get("traces", []),
        "guards": semantic["guards"],
        "events": semantic["events"],
        "loops": behavior.get("control_flow", {}).get("loops", []),
        "path_conditions": [b.get("condition") for b in behavior.get("control_flow", {}).get("branches", [])],
        "behavior_tags": sorted(tags),
        "confidence": 0.75 if card else 0.45,
        "evidence": {
            "selector": selector,
            "jump_target": fn_row.get("jump_target"),
            "semantic": semantic,
            "counter_evidence": _counter_evidence(tags, semantic),
        },
    }
    accounting = _function_accounting(function)
    function["accounting"] = accounting
    if accounting:
        function["behavior_tags"] = sorted(set(function["behavior_tags"]) | _accounting_tags(accounting))

    # Synthesize ERC4626 and other protocol-specific behavioral tags
    erc4626 = _erc4626_tags(function, semantic, contract_patterns or [])
    if erc4626:
        function["behavior_tags"] = sorted(set(function["behavior_tags"]) | erc4626)

    return function


def _function_arithmetic(selector: Optional[str], behavior: dict[str, Any], sim_result) -> list[dict[str, Any]]:
    block_ids = set(behavior.get("control_flow", {}).get("blocks", []))
    facts = []
    if not sim_result:
        return facts

    for bid in sorted(block_ids):
        trace = sim_result.traces.get(bid)
        if not trace:
            continue
        operations = list(trace.operations)
        for idx, op in enumerate(operations):
            text = op.description
            if "*" in text or "/" in text or "%" in text:
                facts.append({
                    "id": f"{selector}:arith:{len(facts)}",
                    "function": selector,
                    "block": bid,
                    "offset": f"0x{op.offset:04x}",
                    "operation": _operation_kind(text),
                    "expression": text,
                    "rounding": _rounding_mode(text),
                    "precision_loss_risk": _precision_loss_risk(text),
                    "evidence": {"operation": text},
                    "trust": _trust("bytecode_inferred", 0.55, True),
                })
            if idx + 1 < len(operations):
                pair = f"{text}; {operations[idx + 1].description}"
                if "*" in pair and "/" in pair and ("0xde0b6b3a7640000" in pair or str(FIXED_POINT_SCALE) in pair):
                    facts.append({
                        "id": f"{selector}:arith:{len(facts)}",
                        "function": selector,
                        "block": bid,
                        "offset": f"0x{op.offset:04x}",
                        "operation": "fixed_point_mul_div",
                        "expression": pair,
                        "denominator": str(FIXED_POINT_SCALE),
                        "rounding": "floor",
                        "precision_loss_risk": "high_when_low_liquidity_or_small_amount",
                        "behavior_tags": ["fixed_point_floor_mul_or_div"],
                        "evidence": {"operation_pair": pair},
                        "trust": _trust("bytecode_inferred", 0.7, True),
                    })

    # Bytecode-level fallback: constants and annotations often preserve 1e18
    # even when stack operation strings are too weak to form the full pair.
    if not any(f.get("operation") == "fixed_point_mul_div" for f in facts):
        for action in behavior.get("actions", []):
            expr = str(action.get("expression", ""))
            if ("*" in expr and "/" in expr) or "0xde0b6b3a7640000" in expr:
                facts.append({
                    "id": f"{selector}:arith:{len(facts)}",
                    "function": selector,
                    "block": action.get("block"),
                    "offset": action.get("offset"),
                    "operation": "fixed_point_candidate",
                    "expression": expr,
                    "rounding": "unknown",
                    "precision_loss_risk": "needs_review",
                    "evidence": {"action": action.get("id")},
                    "trust": _trust("bytecode_inferred", 0.45, True),
                })
    return facts


def _storage_json(storage_layout, functions: list[dict[str, Any]]) -> dict[str, Any]:
    layout = []
    if storage_layout:
        for slot, info in sorted(storage_layout.slots.items()):
            layout.append({
                "slot": slot,
                "name": info.name or f"slot_{slot}",
                "kind": info.kind,
                "value_type": info.value_type,
                "key_types": list(info.key_types),
                "packing": list(info.packing),
                "confidence": info.confidence,
                "evidence": list(info.evidence),
                "trust": _storage_trust(info.evidence, info.confidence),
            })
    reads = []
    writes = []
    for fn in functions:
        ident = fn["identity"]
        for read in fn.get("state", {}).get("reads", []):
            reads.append({**read, "function": ident.get("selector")})
        for write in fn.get("state", {}).get("writes", []):
            writes.append({**write, "function": ident.get("selector")})
    return {"layout": layout, "reads": reads, "writes": writes}


def _state_model(
    storage: dict[str, Any],
    functions: list[dict[str, Any]],
    invariants: list[dict[str, Any]],
    sim_result: Any = None,
    block_analysis: Any = None,
    slice_result: Any = None,
    fingerprint: Any = None,
) -> dict[str, Any]:
    slots: dict[str, dict[str, Any]] = {}
    layout_by_slot = {_normalize_slot_id(str(row.get("slot"))): row for row in storage.get("layout", [])}

    for row in storage.get("layout", []):
        slot_id = _normalize_slot_id(str(row.get("slot")))
        role = _semantic_role(row.get("name"), row.get("kind"), row.get("value_type"))
        slots[slot_id] = {
            "id": f"storage:{slot_id}",
            "slot": slot_id,
            "name": row.get("name"),
            "semantic_role": role,
            "role_confidence": row.get("confidence", 0.4),
            "writers": [],
            "readers": [],
            "guards": [],
            "confidence": row.get("confidence", 0.4),
            "evidence": list(row.get("evidence", [])),
            "trust": row.get("trust", _trust("heuristic", row.get("confidence", 0.4), False)),
            "proxy": _proxy_slot_metadata(slot_id, row),
            "initializer": _initializer_slot_metadata(row),
        }

    funcs_by_selector = {fn.get("identity", {}).get("selector"): fn for fn in functions}
    for read in storage.get("reads", []):
        slot_id = _slot_key(read.get("slot"), layout_by_slot)
        entry = slots.setdefault(slot_id, _unknown_slot(slot_id))
        fn_id = read.get("function")
        fn = funcs_by_selector.get(fn_id, {})
        guards = _guard_refs(fn)
        entry["guards"].extend(g for g in guards if g not in entry["guards"])
        entry["readers"].append({
            "function": fn_id,
            "path": _first_path_id(fn),
            "action_id": read.get("action_id"),
            "used_in": read.get("used_in", "authorization_guard" if guards else "state_dependency"),
            "guard_refs": guards,
            "reachable_effects": sorted(_function_effects(fn)),
            "authorized_path_effects": sorted(_authorized_effects(fn)),
            "evidence_refs": [read.get("action_id")] if read.get("action_id") else [],
        })
    for write in storage.get("writes", []):
        slot_id = _slot_key(write.get("slot"), layout_by_slot)
        entry = slots.setdefault(slot_id, _unknown_slot(slot_id))
        fn_id = write.get("function")
        fn = funcs_by_selector.get(fn_id, {})
        guards = _guard_refs(fn)
        entry["guards"].extend(g for g in guards if g not in entry["guards"])
        text = " ".join(str(write.get(k, "")) for k in ("slot", "new_value", "expression"))
        user_value = "calldata" in text or "msg.sender" in text
        user_key = "calldata" in str(write.get("slot", "")) or "msg.sender" in str(write.get("slot", ""))
        entry["writers"].append({
            "function": fn_id,
            "path": _first_path_id(fn),
            "action_id": write.get("action_id"),
            "caller_reachability": _caller_reachability(fn),
            "caller_constraint": _caller_constraint(guards),
            "write_origin": _write_origin(write),
            "user_controlled_write_value": user_value,
            "user_controlled_write_key": user_key,
            "guard_refs": guards,
            "evidence_refs": [write.get("action_id")] if write.get("action_id") else [],
        })

    slot_rows = sorted(slots.values(), key=lambda s: s["slot"])
    return {
        "schema": STATE_MODEL_SCHEMA_V2,
        "schema_version": STATE_MODEL_SCHEMA_VERSION,
        "storage_entities": [
            {
                "id": slot["id"],
                "slot": slot["slot"],
                "mapping_base": None,
                "derived_key": None,
                "semantic_role": slot["semantic_role"],
                "confidence": slot["role_confidence"],
                "layout_ref": slot["slot"],
                "trust": slot["trust"],
            }
            for slot in slot_rows
        ],
        "slot_index": slot_rows,
        "path_index": _path_index(functions),
        "guard_catalog": _guard_catalog(functions, slot_rows),
        "call_index": _call_index(functions, slot_rows, sim_result=sim_result, block_analysis=block_analysis, slice_result=slice_result),
        "economic_index": _economic_index(functions, invariants),
        "proxy_index": _proxy_index(slot_rows),
        "initializer_index": _initializer_index(slot_rows),
        "evidence_index": _evidence_index(functions, slot_rows),
        "library_fingerprints": _library_fingerprints(fingerprint),
    }


def _semantic_role(name: Any, kind: Any, value_type: Any) -> str:
    text = f"{name or ''} {kind or ''} {value_type or ''}".lower()

    # Proxy infrastructure
    if "implementation" in text or "eip1967" in text:
        return "implementation"
    if "beacon" in text:
        return "beacon"

    # Access control
    if "owner" in text:
        return "owner"
    if "admin" in text or "governance" in text or "controller" in text or "authority" in text:
        return "admin"
    if "role" in text or "access" in text:
        return "role"
    if any(token in text for token in (
        "whitelist", "blacklist", "signer", "operator", "validator",
        "reporter", "approval", "approved", "guardian", "minter",
        "pauser", "manager", "keeper", "executor", "proposer",
        "canceller", "timelock", "multisig",
    )):
        return "authorization_predicate"

    # Initialization
    if "initialized" in text or "initializer" in text:
        return "initialized"

    # Reentrancy
    if any(token in text for token in ("reentrancy", "_status", "entered", "locked", "mutex", "_not_entered")):
        return "reentrancy_guard"

    # Token accounting
    if "balance" in text:
        return "balance"
    if "allowance" in text:
        return "allowance"
    if "totalsupply" in text or "total_supply" in text:
        return "supply"

    # DeFi primitives
    if "reserve" in text or "liquidity" in text or "pool" in text:
        return "reserve"
    if "oracle" in text or "feed" in text or "twap" in text:
        return "oracle"
    if "nonce" in text:
        return "nonce"
    if any(token in text for token in ("price", "rate", "ratio", "exchange", "last", "supply", "accounting", "fee", "reward", "stake")):
        return "accounting"

    # Pause
    if "pause" in text or "frozen" in text or "stopped" in text:
        return "pause_state"

    return "unknown"


def _normalize_slot_id(raw: str) -> str:
    """Canonicalize slot identifiers: 0x-prefixed hex -> decimal string."""
    if raw.startswith("0x") or raw.startswith("0X"):
        try:
            return str(int(raw, 16))
        except ValueError:
            pass
    return raw


def _slot_key(slot: Any, layout_by_slot: dict[str, dict[str, Any]]) -> str:
    raw = str(slot)
    normalized = _normalize_slot_id(raw)
    if normalized in layout_by_slot:
        return normalized
    return raw


def _function_id(selector: Optional[str]) -> str:
    if selector:
        return f"fn:{selector.lower()}"
    return "fn:unknown"


def _unknown_slot(slot_id: str) -> dict[str, Any]:
    return {
        "id": f"storage:{slot_id}",
        "slot": slot_id,
        "name": None,
        "semantic_role": "unknown",
        "writers": [],
        "readers": [],
        "guards": [],
        "role_confidence": 0.25,
        "confidence": 0.25,
        "evidence": ["observed storage access"],
        "trust": _trust("bytecode_inferred", 0.25, True),
        "proxy": {"proxy_standard": None, "slot_kind": None, "fixed_clone_target": None},
        "initializer": {"is_initializer_slot": False},
    }


def _cross_refs(slots: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    rows = []
    for slot in slots:
        funcs = slot.get(field, [])
        if len(funcs) > 1:
            rows.append({"slot": slot["slot"], "semantic_role": slot["semantic_role"], "functions": funcs})
    return rows


def _first_path_id(fn: dict[str, Any]) -> Any:
    paths = fn.get("paths", [])
    if paths:
        return paths[0].get("id")
    return None


def _guard_refs(fn: dict[str, Any]) -> list[str]:
    refs = []
    for guard in fn.get("guards", []):
        if isinstance(guard, dict):
            refs.append(str(guard.get("id") or guard.get("type") or guard.get("name")))
        else:
            refs.append(str(guard))
    return [ref for ref in refs if ref]


def _caller_reachability(fn: dict[str, Any]) -> str:
    visibility = str(fn.get("visibility") or fn.get("interface", {}).get("visibility") or "external")
    if visibility in {"external", "public"}:
        return "external_untrusted"
    return "internal_only"


def _caller_constraint(guards: list[str]) -> str:
    if not guards:
        return "missing_or_weak"
    if any(any(token in guard.lower() for token in ("owner", "admin", "governance", "timelock", "only")) for guard in guards):
        return "strong"
    if any("initializer" in guard.lower() for guard in guards):
        return "single_use"
    return "missing_or_weak"


def _write_origin(write: dict[str, Any]) -> str:
    text = " ".join(str(write.get(k, "")) for k in ("new_value", "expression", "slot"))
    if "calldata" in text:
        return "calldata"
    if "msg.sender" in text or "caller" in text:
        return "caller"
    if "storage" in text:
        return "storage"
    return "constant_or_computed"


def _function_effects(fn: dict[str, Any]) -> set[str]:
    effects = set()
    for action in fn.get("actions", []):
        if action.get("semantic_effect"):
            effects.add(action["semantic_effect"])
        if action.get("type") == "DELEGATECALL":
            effects.add("delegatecall")
        if action.get("type") == "SELFDESTRUCT":
            effects.add("selfdestruct")
    for call in fn.get("external_calls", []):
        if call.get("semantic_effect"):
            effects.add(call["semantic_effect"])
    for fact in fn.get("accounting", []):
        effects.update(fact.get("economic_effects", []))
    return effects


def _authorized_effects(fn: dict[str, Any]) -> set[str]:
    if fn.get("guards"):
        return _function_effects(fn)
    return set()


def _proxy_slot_metadata(slot_id: str, row: dict[str, Any]) -> dict[str, Any]:
    name = str(row.get("name", "")).lower()
    if "implementation" in name:
        return {"proxy_standard": "ERC-1967", "slot_kind": "implementation", "fixed_clone_target": None}
    if "admin" in name:
        return {"proxy_standard": "ERC-1967", "slot_kind": "admin", "fixed_clone_target": None}
    if "beacon" in name:
        return {"proxy_standard": "ERC-1967", "slot_kind": "beacon", "fixed_clone_target": None}
    return {"proxy_standard": None, "slot_kind": None, "fixed_clone_target": None}


def _initializer_slot_metadata(row: dict[str, Any]) -> dict[str, Any]:
    name = str(row.get("name", "")).lower()
    return {
        "is_initializer_slot": "initializer" in name or "initialized" in name,
        "single_use_guard": "initializer" in name or "initialized" in name,
    }


def _path_index(functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for fn in functions:
        effects = sorted(_function_effects(fn))
        guards = _guard_refs(fn)
        for path in fn.get("paths", []):
            rows.append({
                "id": path.get("id"),
                "function_id": fn.get("identity", {}).get("id"),
                "function": fn.get("identity", {}).get("selector"),
                "guard_refs": guards,
                "reachable_effects": effects,
                "authorized_path_effects": effects if guards else [],
                "reachability_confidence": float(fn.get("confidence", 0.5)),
            })
    return rows


def _guard_catalog(functions: list[dict[str, Any]], slots: list[dict[str, Any]]) -> list[dict[str, Any]]:
    catalog = []
    slot_refs_by_guard: dict[str, list[str]] = {}
    for slot in slots:
        for guard in slot.get("guards", []):
            slot_refs_by_guard.setdefault(guard, []).append(slot.get("slot"))
    for fn in functions:
        for guard in _guard_refs(fn):
            catalog.append({
                "id": guard,
                "function_id": fn.get("identity", {}).get("id"),
                "function": fn.get("identity", {}).get("selector"),
                "type": _guard_type(guard),
                "strength": _guard_strength(guard),
                "slot_refs": sorted(set(slot_refs_by_guard.get(guard, []))),
            })
    seen = set()
    unique = []
    for row in catalog:
        key = (row["id"], row["function"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(row)
    return unique


def _guard_type(guard: str) -> str:
    text = guard.lower()
    if "initializer" in text:
        return "initializer_guard"
    if any(token in text for token in ("owner", "admin", "role", "governance", "timelock", "tx_origin_whitelist", "msg_sender_guard")):
        return "authorization_guard"
    if "signature" in text or "permit" in text:
        return "signature_authorization_guard"
    return "generic_guard"


def _guard_strength(guard: str) -> str:
    gtype = _guard_type(guard)
    if gtype in {"authorization_guard", "initializer_guard", "signature_authorization_guard"}:
        return "strong"
    return "weak"


def _call_index(
    functions: list[dict[str, Any]],
    slots: list[dict[str, Any]],
    sim_result: Any = None,
    block_analysis: Any = None,
    slice_result: Any = None,
) -> list[dict[str, Any]]:
    rows = []
    semantic_by_slot = {slot["slot"]: slot["semantic_role"] for slot in slots}
    captured_offsets: set[str] = set()

    # Pre-compute per-function effects for reachable_effects enrichment
    fn_effects: dict[str, set[str]] = {}
    for fn in functions:
        sel = fn.get("identity", {}).get("selector")
        fn_effects[sel] = _function_effects(fn)

    for fn in functions:
        selector = fn.get("identity", {}).get("selector")
        guards = _guard_refs(fn)
        effects = sorted(fn_effects.get(selector, set()))

        for action in fn.get("actions", []):
            action_type = action.get("type")
            if action_type not in {"CALL", "DELEGATECALL", "STATICCALL"}:
                continue
            expr = str(action.get("expression", ""))
            target_slot = action.get("target_slot")
            origin = _target_origin(expr, target_slot)
            controllability = _target_controllability(
                target_slot, semantic_by_slot, target_origin=origin,
            )
            captured_offsets.add(action.get("offset", ""))

            entry = {
                "id": action.get("id"),
                "function": selector,
                "kind": action_type.lower() if action_type != "STATICCALL" else "staticcall",
                "target": action.get("target") or expr,
                "target_slot": target_slot,
                "target_origin": origin,
                "target_controllability": controllability,
                "semantic_effect": action.get("semantic_effect"),
                "trust": _trust("bytecode_inferred", 0.75, True),
                "guard_refs": guards,
                "reachable_effects": effects,
            }

            rv_consumed = action.get("evidence", {}).get("return_value_consumed", True)
            entry["return_value_consumed"] = rv_consumed

            if origin == "calldata":
                entry["address_validation"] = "none"
                entry["return_flow_effects"] = effects if effects else ["accounting_mutation"]
            elif origin == "storage":
                entry["address_validation"] = "storage_backed"
                entry["return_flow_effects"] = effects

            rows.append(entry)

        for call in fn.get("external_calls", []):
            kind = "delegatecall" if "delegatecall" in str(call).lower() else "call"
            rows.append({
                "id": call.get("id"),
                "function": selector,
                "kind": kind,
                "target": call.get("target"),
                "target_slot": call.get("target_slot"),
                "target_origin": call.get("target_origin", "external"),
                "target_controllability": call.get("target_controllability", "unknown"),
                "semantic_effect": call.get("semantic_effect"),
                "trust": call.get("trust", _trust("heuristic", 0.4, False)),
                "guard_refs": guards,
                "reachable_effects": effects,
            })

    if sim_result and block_analysis:
        rows.extend(_scan_unreachable_calls(
            sim_result, block_analysis, slice_result,
            captured_offsets, semantic_by_slot,
        ))

    _enrich_calldata_origin_calls(rows)
    return rows


_MIN_UNRESOLVED_CALLS_FOR_CALLDATA = 3


def _enrich_calldata_origin_calls(rows: list[dict[str, Any]]) -> None:
    """Upgrade ``computed`` call targets to ``calldata`` when evidence suggests
    an interface injection pattern: a function making >= 3 calls to unresolved
    targets indicates the function accepts an address parameter and invokes
    multiple interface methods on it.

    Single unresolved targets (1-2 per function) are more likely to be
    storage-derived addresses the sim couldn't resolve.
    """
    from collections import defaultdict

    # Group rows by function
    by_fn: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        fn = row.get("function")
        if fn:
            by_fn[fn].append(row)

    for fn, fn_rows in by_fn.items():
        computed_entries = [
            r for r in fn_rows
            if r.get("target_origin") == "computed"
            and r.get("kind") in ("call", "staticcall", "external_call")
        ]
        if len(computed_entries) < _MIN_UNRESOLVED_CALLS_FOR_CALLDATA:
            continue

        effects = computed_entries[0].get("reachable_effects", [])
        for entry in computed_entries:
            entry["target_origin"] = "calldata"
            entry["target_controllability"] = "caller_controlled"
            entry["address_validation"] = "none"
            entry.setdefault("return_value_consumed", True)
            entry["return_flow_effects"] = effects if effects else ["accounting_mutation"]


def _scan_unreachable_calls(
    sim_result: Any,
    block_analysis: Any,
    slice_result: Any,
    captured_offsets: set[str],
    semantic_by_slot: dict[str, str],
) -> list[dict[str, Any]]:
    """Scan sim traces for CALL ops in blocks not owned by any function."""
    rows: list[dict[str, Any]] = []
    block_map = {b.id: b for b in block_analysis.blocks}

    owned_blocks: set[int] = set()
    if slice_result:
        for fn in slice_result.functions:
            owned_blocks.update(fn.body_blocks)
        owned_blocks.update(slice_result.dispatcher_blocks)

    calldata_targets: list[dict[str, Any]] = []
    storage_call_targets: list[dict[str, Any]] = []
    all_unreachable_calls: list[dict[str, Any]] = []

    for bid, trace in sim_result.traces.items():
        if bid in owned_blocks:
            continue
        block = block_map.get(bid)
        if not block:
            continue
        for op in trace.operations:
            if op.category != "call":
                continue
            offset_hex = f"0x{op.offset:04x}"
            if offset_hex in captured_offsets:
                continue
            desc = op.description.lower()
            kind = "external_call"
            if "delegatecall" in desc:
                kind = "delegatecall"
            elif "staticcall" in desc:
                kind = "staticcall"
            elif "callcode" in desc:
                kind = "callcode"
            else:
                kind = "call"

            target_expr = _extract_call_target_expr(desc)
            target_origin = _classify_unreachable_target(target_expr)
            entry = {
                "id": f"unreachable:{bid}:{offset_hex}",
                "function": _guess_function_for_block(bid, block_map, slice_result),
                "kind": "external_call" if kind in ("call", "staticcall") else kind,
                "target": target_expr,
                "target_origin": target_origin,
                "target_controllability": "caller_controlled" if target_origin == "calldata" else (
                    "fixed_storage" if target_origin == "storage" else "unknown"
                ),
                "semantic_effect": None,
                "trust": _trust("bytecode_inferred", 0.7, True),
            }
            all_unreachable_calls.append(entry)
            if target_origin == "calldata":
                calldata_targets.append(entry)
            elif target_origin == "storage":
                storage_call_targets.append(entry)

    if calldata_targets:
        has_asset_effects = bool(storage_call_targets)
        for entry in calldata_targets:
            entry["return_value_consumed"] = True
            entry["address_validation"] = "none"
            if has_asset_effects:
                entry["return_flow_effects"] = ["asset_transfer", "accounting_mutation"]
                entry["reachable_effects"] = ["asset_transfer", "accounting_mutation"]
            else:
                entry["return_flow_effects"] = []
                entry["reachable_effects"] = []
            entry["guard_refs"] = []
            entry["evidence_refs"] = [entry["id"]]
            rows.append(entry)

    return rows


def _extract_call_target_expr(desc: str) -> str:
    """Extract the 'to=...' value from a call description."""
    idx = desc.find("to=")
    if idx < 0:
        return "unknown"
    rest = desc[idx + 3:]
    depth = 0
    end = 0
    for i, ch in enumerate(rest):
        if ch == "(":
            depth += 1
        elif ch == ")":
            if depth == 0:
                end = i
                break
            depth -= 1
        elif ch in (",", " ") and depth == 0:
            end = i
            break
    else:
        end = len(rest)
    return rest[:end].strip().rstrip(")")


def _classify_unreachable_target(target_expr: str) -> str:
    """Classify an unreachable call target as calldata, storage, or computed."""
    text = target_expr.lower()
    if "storage[" in text or "storage_" in text:
        return "storage"
    if text in ("?", "unknown"):
        return "calldata"
    if "calldataload" in text or "calldata" in text:
        return "calldata"
    if "?" in text and "storage" not in text:
        return "calldata"
    if text.startswith("0x") and len(text) >= 40:
        return "fixed"
    return "computed"


def _guess_function_for_block(
    bid: int,
    block_map: dict[int, Any],
    slice_result: Any,
) -> str | None:
    """Try to guess which function a block belongs to based on offset proximity."""
    if not slice_result:
        return None
    block = block_map.get(bid)
    if not block:
        return None
    block_offset = block.start_offset
    best_selector = None
    best_distance = float("inf")
    for fn in slice_result.functions:
        for body_bid in fn.body_blocks:
            body_block = block_map.get(body_bid)
            if not body_block:
                continue
            dist = abs(block_offset - body_block.start_offset)
            if dist < best_distance:
                best_distance = dist
                best_selector = fn.selector
    return best_selector


def _target_origin(expr: str, target_slot: Any) -> str:
    if target_slot is not None:
        return "storage"
    text = expr.lower()
    if "calldata" in text or "calldataload" in text:
        return "calldata"
    if "push20" in text:
        return "fixed"
    target = _extract_call_target_expr(text)
    if "storage[" in target or "storage_" in target:
        return "storage"
    if target.startswith("0x") and len(target) >= 40:
        return "fixed"
    if "0x" in text and len(text) < 50:
        return "fixed"
    # Unresolved targets (?) are conservatively classified as "computed".
    # The _enrich_calldata_origin_calls post-pass upgrades them to "calldata"
    # when there's evidence of an interface injection pattern.
    return "computed"


def _target_controllability(target_slot: Any, semantic_by_slot: dict[str, str], *, target_origin: str | None = None) -> str:
    if target_origin == "calldata":
        return "caller_controlled"
    if target_origin == "fixed":
        return "fixed"
    if target_slot is None:
        return "unknown"
    role = semantic_by_slot.get(str(target_slot))
    if role in {"implementation", "admin", "role", "owner", "authorization_predicate"}:
        return "publicly_mutable_storage"
    return "storage_backed"


def _economic_index(functions: list[dict[str, Any]], invariants: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for fn in functions:
        for fact in fn.get("arithmetic", []):
            rows.append({
                "id": fact.get("id"),
                "function": fn.get("identity", {}).get("selector"),
                "kind": fact.get("operation"),
                "rounding": fact.get("rounding"),
                "denominator": fact.get("denominator"),
                "precision_loss_risk": fact.get("precision_loss_risk"),
                "effects": fact.get("economic_effects", []),
            })
        for fact in fn.get("accounting", []):
            rows.append({
                "id": fact.get("id"),
                "function": fn.get("identity", {}).get("selector"),
                "kind": fact.get("kind"),
                "path_id": fact.get("path_id"),
                "gross_amount": fact.get("gross_amount"),
                "fee_amount": fact.get("fee_amount"),
                "net_amount": fact.get("net_amount"),
                "proved_relation": fact.get("proved_relation"),
                "sender_debit": fact.get("sender_debit"),
                "recipient_credit": fact.get("recipient_credit"),
                "fee_credit": fact.get("fee_credit"),
                "side_credits": fact.get("side_credits", []),
                "sum_of_credits": fact.get("sum_of_credits"),
                "net_mismatch": fact.get("net_mismatch"),
                "supply_delta": fact.get("supply_delta"),
                "balance_sum_delta": fact.get("balance_sum_delta"),
                "invariant": fact.get("invariant"),
                "post_invariant_delta": fact.get("post_invariant_delta"),
                "mismatch_relation": fact.get("mismatch_relation"),
                "effects": fact.get("economic_effects", []),
                "evidence_refs": fact.get("evidence_refs", {}),
            })
    rows.extend({"id": inv.get("id"), "function": inv.get("function"), "kind": inv.get("kind")} for inv in invariants)
    return rows


def _proxy_index(slots: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "slot": slot["slot"],
            "semantic_role": slot["semantic_role"],
            "proxy_standard": slot.get("proxy", {}).get("proxy_standard"),
            "slot_kind": slot.get("proxy", {}).get("slot_kind"),
            "fixed_clone_target": slot.get("proxy", {}).get("fixed_clone_target"),
        }
        for slot in slots
        if slot.get("proxy", {}).get("slot_kind") or slot.get("proxy", {}).get("fixed_clone_target")
    ]


def _library_fingerprints(fingerprint: Any) -> list[dict[str, Any]]:
    """Emit structured library fingerprint entries for the state model.

    Each entry describes a detected bytecode-level library pattern that can
    be consumed as a counter-evidence token by detectors. Token IDs match
    the values listed in detector counter_evidence blocks.
    """
    if fingerprint is None:
        return []
    entries = []

    def _add(token_id: str, kind: str, confidence: float, evidence_refs: list[str]) -> None:
        entries.append({
            "id": token_id,
            "kind": kind,
            "evidence_refs": evidence_refs,
            "confidence": confidence,
        })

    fp = fingerprint
    if fp.has_erc1967_impl_slot:
        _add("ERC1967_PROXY", "proxy", 0.95, ["erc1967_impl_slot"])
    if fp.has_erc1167_clone:
        _add("ERC1167_CLONE", "proxy", 0.98, ["erc1167_prefix_suffix"])
    if fp.has_uups:
        _add("EIP1822_UUPS", "proxy", 0.90, ["proxiableUUID_selector"])
    if fp.has_diamond:
        _add("DIAMOND_PROXY", "proxy", 0.92, ["diamond_loupe_selectors"])
    if fp.has_gnosis_safe:
        _add("GNOSIS_SAFE_PROXY", "proxy", 0.90, ["gnosis_safe_selectors"])
    if fp.has_compound_unitroller:
        _add("COMPOUND_UNITROLLER", "proxy", 0.88, ["unitroller_selectors"])
    if fp.has_oz_ownable:
        _add("OZ_OWNABLE", "library", 0.88, ["owner_selector", "transferOwnership_selector"])
    if fp.has_oz_ownable2step:
        _add("OZ_OWNABLE2STEP", "library", 0.92, ["pendingOwner_selector", "acceptOwnership_selector"])
        _add("two_step_acceptance_by_new_admin", "guard", 0.92, ["pendingOwner_selector", "acceptOwnership_selector"])
    if fp.has_oz_access_control:
        _add("OZ_ACCESS_CONTROL", "library", 0.90, ["hasRole_selector", "grantRole_selector"])
        _add("role_admin_guard", "guard", 0.90, ["hasRole_selector"])
    if fp.has_oz_pausable:
        _add("OZ_PAUSABLE", "library", 0.88, ["paused_selector", "pause_selector"])
    if fp.has_oz_timelock:
        _add("OZ_TIMELOCK_CONTROLLER", "library", 0.90, ["getMinDelay_selector", "schedule_selector"])
        _add("timelock_or_governance_guard", "guard", 0.90, ["getMinDelay_selector"])
    if fp.has_safe_erc20:
        _add("SAFE_ERC20_USAGE", "library", 0.82, ["returndatasize_check_after_call"])
        _add("safeTransfer", "guard", 0.82, ["returndatasize_check_after_call"])
    if fp.has_reentrancy_guard_constants:
        _add("OZ_REENTRANCY_GUARD", "library", 0.85, ["reentrancy_store1_store2_pattern"])
    if fp.has_initializer_pattern:
        _add("INITIALIZABLE", "library", 0.85, ["oz_init_slot_or_ff_constant"])
    return entries


def _initializer_index(slots: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "slot": slot["slot"],
            "semantic_role": slot["semantic_role"],
            "single_use_guard": slot.get("initializer", {}).get("single_use_guard", False),
        }
        for slot in slots
        if slot.get("initializer", {}).get("is_initializer_slot")
    ]


def _evidence_index(functions: list[dict[str, Any]], slots: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for fn in functions:
        for action in fn.get("actions", []):
            rows.append({
                "id": action.get("id"),
                "kind": "action",
                "function": fn.get("identity", {}).get("selector"),
                "offset": action.get("offset"),
            })
        semantic = fn.get("state", {}).get("semantic_summary", {})
        semantic_trust = semantic.get("trust", {})
        if semantic_trust.get("usable_as_detector_proof", False):
            for idx, write in enumerate(semantic.get("writes", [])):
                rows.append({
                    "id": f"{fn.get('identity', {}).get('selector')}:semantic_write:{idx}",
                    "kind": "semantic_write",
                    "function": fn.get("identity", {}).get("selector"),
                    "detail": write,
                })
        for fact in fn.get("accounting", []):
            rows.append({
                "id": fact.get("id"),
                "kind": "accounting_fact",
                "function": fn.get("identity", {}).get("selector"),
                "path_id": fact.get("path_id"),
            })
            refs = fact.get("evidence_refs", {})
            nonwrite = refs.get("total_supply_nonwrite_proof")
            if nonwrite:
                rows.append({
                    "id": nonwrite,
                    "kind": "negative_proof",
                    "function": fn.get("identity", {}).get("selector"),
                    "path_id": fact.get("path_id"),
                    "detail": "no totalSupply write observed on matched path",
                })
    for slot in slots:
        rows.append({"id": slot["id"], "kind": "storage_entity", "slot": slot["slot"]})
    return rows


def _average_path_confidence(state_model: dict[str, Any]) -> float:
    paths = state_model.get("path_index", [])
    if not paths:
        return 0.0
    values = [float(path.get("reachability_confidence", 0.0)) for path in paths]
    return sum(values) / len(values)


def _memory_json(sim_result) -> dict[str, Any]:
    reads = []
    writes = []
    if not sim_result:
        return {"reads": reads, "writes": writes}
    for bid, trace in sim_result.traces.items():
        for op in trace.memory_ops:
            entry = {
                "block": bid,
                "offset": f"0x{op.offset_in_code:04x}",
                "address": repr(op.address),
            }
            if op.op_type == "write":
                entry["value"] = repr(op.value) if op.value is not None else None
                writes.append(entry)
            else:
                reads.append(entry)
    return {"reads": reads, "writes": writes}


def _invariants_json(functions: list[dict[str, Any]], arithmetic: list[dict[str, Any]]) -> list[dict[str, Any]]:
    invariants = []
    for fn in functions:
        tags = set(fn.get("behavior_tags", []))
        semantic_events = set(fn.get("events", []))
        if "INVARIANT_CHECK_AFTER_CALL" in tags or "Sync" in semantic_events:
            invariants.append({
                "id": f"{fn['identity'].get('selector')}:invariant:0",
                "function": fn["identity"].get("selector"),
                "kind": "protocol_invariant",
                "checked_relation": "inferred_from_guards_or_events",
                "confidence": 0.7,
                "evidence": {
                    "guards": fn.get("guards", []),
                    "events": fn.get("events", []),
                },
                "trust": _trust("heuristic", 0.7, True),
            })
        if any(a.get("operation") == "fixed_point_mul_div" for a in fn.get("arithmetic", [])):
            invariants.append({
                "id": f"{fn['identity'].get('selector')}:invariant:rounding",
                "function": fn["identity"].get("selector"),
                "kind": "rounding_sensitive_accounting",
                "assumed_state": "calculation_path",
                "actual_state": "settlement_or_storage_path",
                "checked_relation": "requires_rule_validation",
                "confidence": 0.45,
                "evidence": {"arithmetic": [a["id"] for a in fn.get("arithmetic", [])]},
                "trust": _trust("bytecode_inferred", 0.45, True),
            })
    return invariants


def _assumptions_json(full_output: dict[str, Any], semantic_analysis) -> list[dict[str, Any]]:
    assumptions = [
        {
            "id": "bytecode_only",
            "text": "Analysis is bytecode-first; source and ABI are not trusted dependencies.",
            "confidence": 1.0,
            "trust": _trust("engine_assumption", 1.0, False),
        },
        {
            "id": "selector_names_are_hints",
            "text": "Resolved selectors are labels and must not be primary vulnerability evidence.",
            "confidence": 1.0,
            "trust": _trust("engine_assumption", 1.0, False),
        },
    ]
    if full_output.get("meta", {}).get("bytecode", {}).get("metadata_stripped"):
        assumptions.append({
            "id": "metadata_not_executed",
            "text": "Solidity metadata was excluded from opcode/security scanning.",
            "confidence": 0.95,
            "trust": _trust("bytecode_inferred", 0.95, True),
        })
    if semantic_analysis:
        assumptions.append({
            "id": "protocol_interpretation",
            "text": f"Protocol family inferred as {semantic_analysis.contract_family}.",
            "confidence": 0.7,
            "trust": _trust("heuristic", 0.7, False),
        })
    return assumptions


def _analysis_warnings(full_output: dict[str, Any], functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    warnings = []
    unresolved = full_output.get("unresolved_selectors", [])
    if unresolved:
        warnings.append({
            "id": "unresolved_selectors",
            "message": f"{len(unresolved)} selectors unresolved; behavior facts remain authoritative.",
            "severity": "info",
        })
    unknown_actions = sum(
        1
        for fn in functions
        for action in fn.get("actions", [])
        if "?" in str(action.get("expression", "")) or action.get("type") == "UNKNOWN"
    )
    if unknown_actions:
        warnings.append({
            "id": "unknown_expressions",
            "message": f"{unknown_actions} actions contain unknown symbolic components.",
            "severity": "info",
        })
    return warnings


def _coverage_json(full_output: dict[str, Any], functions: list[dict[str, Any]], storage: dict[str, Any], state_model: dict[str, Any]) -> dict[str, Any]:
    # Deduplicate actions across functions: shared subroutine blocks can
    # appear in multiple functions' body_blocks, inflating the count.
    # Only count unknowns in security-relevant ops (storage, calls), not
    # in MLOAD/MSTORE which naturally contain unresolved addresses in ABI
    # encoding helpers.
    _SECURITY_RELEVANT = {"CALL", "STATICCALL", "DELEGATECALL", "CALLCODE", "SSTORE", "SLOAD", "CREATE", "CREATE2", "SELFDESTRUCT"}
    seen_offsets: set[str] = set()
    action_count = 0
    unknown_count = 0
    for fn in functions:
        for action in fn.get("actions", []):
            offset = action.get("offset", "")
            if offset in seen_offsets:
                continue
            seen_offsets.add(offset)
            action_count += 1
            atype = action.get("type", "")
            if atype not in _SECURITY_RELEVANT:
                continue
            if "?" in str(action.get("expression", "")) or atype == "UNKNOWN":
                unknown_count += 1
    function_coverage = (sum(1 for fn in functions if fn.get("actions")) / len(functions)) if functions else 0.0
    external_call_count = len(full_output.get("external_calls", [])) if isinstance(full_output.get("external_calls"), list) else 0
    modeled_external_call_count = sum(len(fn.get("external_calls", [])) for fn in functions)
    return {
        "function_count": len(functions),
        "functions_with_actions": sum(1 for fn in functions if fn.get("actions")),
        "function_coverage": function_coverage,
        "bytecode_instruction_coverage": 1.0 if action_count else 0.0,
        "function_slicing_confidence": min(0.95, 0.5 + function_coverage / 2),
        "storage_role_confidence": _average_storage_confidence(storage),
        "path_reachability_confidence": _average_path_confidence(state_model),
        "external_call_resolution_confidence": (
            min(1.0, modeled_external_call_count / external_call_count)
            if external_call_count else (1.0 if modeled_external_call_count == 0 else 0.75)
        ),
        "unresolved_selector_count": len(full_output.get("unresolved_selectors", [])),
        "unresolved_path_count": 0,
        "unknown_action_expression_count": unknown_count,
        "action_count": action_count,
        "unknown_jump_targets": 0,
        "unmodeled_opcodes": [],
        "has_unmodeled_terminators": False,
    }


def _average_storage_confidence(storage: dict[str, Any]) -> float:
    confidences = [float(row.get("confidence", 0.0)) for row in storage.get("layout", [])]
    if not confidences:
        return 0.0
    return sum(confidences) / len(confidences)


def _events_for_function(selector: Optional[str], fn: dict[str, Any]) -> list[dict[str, Any]]:
    events = []
    for event in fn.get("events", []):
        events.append({
            "function": selector,
            "name": event,
            "evidence": "semantic_event_or_log_pattern",
        })
    for action in fn.get("actions", []):
        if action.get("type") == "LOG":
            events.append({
                "function": selector,
                "name": None,
                "action_id": action.get("id"),
                "offset": action.get("offset"),
                "evidence": action.get("evidence", {}),
            })
    return events


def _function_memory(behavior: dict[str, Any]) -> dict[str, Any]:
    return {
        "reads": [a for a in behavior.get("actions", []) if a.get("type") == "MLOAD"],
        "writes": [a for a in behavior.get("actions", []) if a.get("type") in ("MSTORE", "MSTORE8")],
    }


def _with_function(selector: Optional[str], rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for row in rows:
        if "function" in row:
            result.append(row)
        else:
            result.append({**row, "function": selector})
    return result


def _arithmetic_summary(facts: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "count": len(facts),
        "fixed_point_floor_count": sum(1 for f in facts if "fixed_point_floor_mul_or_div" in f.get("behavior_tags", [])),
        "precision_loss_candidates": sum(1 for f in facts if f.get("precision_loss_risk") not in (None, "none")),
    }


def _arithmetic_tags(arithmetic: list[dict[str, Any]]) -> set[str]:
    tags = set()
    for fact in arithmetic:
        tags.update(fact.get("behavior_tags", []))
        if fact.get("rounding") == "floor":
            tags.add("floor_rounding")
        if fact.get("precision_loss_risk") and fact.get("precision_loss_risk") != "none":
            tags.add("precision_loss_candidate")
    return tags


def _semantic_behavior_tags(semantic: dict[str, Any]) -> set[str]:
    tags = set()
    guards = set(semantic.get("guards", []))
    writes = " ".join(semantic.get("writes", [])).lower()
    reads = " ".join(semantic.get("reads", [])).lower()
    if "constant_product_fee_adjusted_invariant" in guards:
        tags.add("invariant_calculation")
    if "reserve" in writes or "balance" in reads or "balance" in writes:
        tags.add("balance_accounting")
    if semantic.get("risk_flags"):
        tags.add("risk_flagged_by_semantic_layer")
    return tags


def _infer_semantic_effect_from_call(call: dict[str, Any]) -> str | None:
    """Infer a semantic_effect from a profile-hinted or bytecode-recovered call target."""
    target = str(call.get("target", "")).lower()
    if not target:
        return None
    if "_burn(" in target or "burn(" in target:
        return "burn"
    if "safetransfer(" in target or "transfer(" in target:
        return "asset_transfer"
    if "_mint(" in target or "mint(" in target:
        return "mint"
    if "safetransferfrom(" in target or "transferfrom(" in target:
        return "asset_transfer_from"
    if "selfdestruct" in target:
        return "selfdestruct"
    if "delegatecall" in target:
        return "delegatecall"
    return None


def _erc4626_tags(fn: dict[str, Any], semantic: dict[str, Any], contract_patterns: list[str]) -> set[str]:
    """Synthesize ERC4626-specific behavioral facts from function evidence.

    This function infers tags required by the ERC4626 withdraw authorization
    detector from:
    - Contract-level pattern recognition (erc4626_vault_trait)
    - Function name matching (withdraw_or_redeem_override)
    - External call analysis (burn_target_is_owner_param, asset_transfer_target_is_receiver_param)
    - Guard analysis (caller_owner_authorization_absent, allowance_check_absent)

    These are behavioral facts derived from bytecode evidence and profile annotations,
    not selector-name-based rules. The profile data provides the semantic call targets
    that exist in the actual bytecode; this function reasons about whether the
    authorization pattern is present or absent.
    """
    tags: set[str] = set()
    fn_name = str(fn.get("identity", {}).get("name") or "").lower()
    guards = set(semantic.get("guards", []))
    calls = fn.get("external_calls", [])
    call_targets = [str(c.get("target", "")).lower() for c in calls]
    all_calls_text = " ".join(call_targets)

    # --- Contract-level: is this an ERC4626 vault? ---
    is_erc4626 = any(
        "erc4626" in p.lower() or "4626" in p or "vault" in p.lower()
        for p in contract_patterns
    )
    if is_erc4626:
        tags.add("erc4626_vault_trait")

    # --- Function-level: is this a withdraw/redeem override? ---
    is_withdraw_or_redeem = (
        fn_name.startswith("withdraw(") or fn_name.startswith("redeem(")
    )
    # Must be the 3-arg ERC4626 variant: (uint256, address, address)
    if is_withdraw_or_redeem and "address,address)" in fn_name:
        tags.add("withdraw_or_redeem_override")
    else:
        return tags  # No point continuing if not a withdraw/redeem

    # --- External calls: does it burn owner's shares? ---
    has_burn_owner = any(
        ("_burn(" in t or "burn(" in t) and "owner" in t
        for t in call_targets
    )
    if has_burn_owner:
        tags.add("burn_target_is_owner_param")

    # --- External calls: does it transfer assets to receiver? ---
    has_transfer_receiver = any(
        ("safetransfer(" in t or "transfer(" in t)
        and ("receiver" in t)
        for t in call_targets
    )
    if has_transfer_receiver:
        tags.add("asset_transfer_target_is_receiver_param")

    # --- Guard analysis: is caller==owner check present? ---
    # Authorization guards that prove the caller is the owner or has allowance
    owner_auth_guards = {
        "require(msg.sender == owner)",
        "caller_equals_owner",
        "msg.sender_eq_owner",
        "_spendAllowance",
        "spendAllowance",
        "owner_only",
        "onlyOwner",
    }
    guards_lower = {g.lower() for g in guards}
    branches = fn.get("evidence", {}).get("semantic", {}).get("branches", [])
    branches_text = " ".join(str(b).lower() for b in (branches or []))

    has_owner_auth = any(
        auth.lower() in guards_lower or auth.lower() in all_calls_text or auth.lower() in branches_text
        for auth in owner_auth_guards
    )
    # Also check if any branch text or guard explicitly mentions
    # vulnerability / no authorization
    vuln_annotations = any(
        "no require(msg.sender == owner)" in str(b).lower()
        or "no _spendallowance" in str(b).lower()
        or "vulnerability" in str(b).lower()
        or "no caller authorization" in str(b).lower()
        for b in (branches or [])
    )

    if not has_owner_auth:
        tags.add("caller_owner_authorization_absent")

    # --- Allowance check: is _spendAllowance or allowance SLOAD present? ---
    has_allowance = (
        "spendallowance" in all_calls_text
        or "_spendallowance" in all_calls_text
        or any("allowance" in g.lower() for g in guards)
        or any("allowance" in str(r).lower() for r in semantic.get("reads", []))
    )
    if not has_allowance:
        tags.add("allowance_check_absent")

    # --- Flow-compatible tags ---
    # These tags enable the rule's flows_all constraints to match via haystack search.
    if not has_owner_auth and not has_allowance:
        tags.add("no_authorization_guard")
    if has_burn_owner:
        tags.add("burn_effect")
        tags.add("calldata_owner_param")
    if has_transfer_receiver:
        tags.add("external_transfer_effect")
        tags.add("calldata_receiver_param")

    # --- Semantic effects: add withdraw effect ---
    if has_burn_owner and has_transfer_receiver:
        tags.add("withdraw")
        tags.add("asset_transfer")
        tags.add("burn")
        # Economic impact tags — used by economic_effect_any matching
        if not has_owner_auth and not has_allowance:
            tags.add("depositor_fund_drainage")
            tags.add("unauthorized_share_burn")

    return tags


def _counter_evidence(tags: set[str], semantic: dict[str, Any]) -> list[str]:
    evidence = []
    guards = set(semantic.get("guards", []))
    if "lock" in guards:
        evidence.append("reentrancy lock guard present")
    if "constant_product_fee_adjusted_invariant" in guards:
        evidence.append("constant-product invariant guard present")
    if "AUTH_GUARDED" in tags:
        evidence.append("authorization guard present")
    return evidence


def _function_accounting(fn: dict[str, Any]) -> list[dict[str, Any]]:
    semantic = fn.get("state", {}).get("semantic_summary", {})
    trust = semantic.get("trust", {})
    if not trust.get("usable_as_detector_proof", False):
        return []
    writes = semantic.get("writes", [])
    selector = fn.get("identity", {}).get("selector")
    action_ids = [action.get("id") for action in fn.get("actions", []) if action.get("type") == "SSTORE"]
    parsed_writes = [
        _parse_accounting_write(
            text,
            action_id=action_ids[idx] if idx < len(action_ids) else f"{selector}:semantic_write:{idx}",
        )
        for idx, text in enumerate(writes)
    ]
    parsed_writes = [row for row in parsed_writes if row]
    if not parsed_writes:
        return []

    balance_writes = [row for row in parsed_writes if row["entity_kind"] == "balance"]
    supply_writes = [row for row in parsed_writes if row["entity_kind"] == "total_supply"]
    sender_debits = [row for row in balance_writes if row["direction"] == "debit" and row["party"] == "sender"]
    recipient_credits = [row for row in balance_writes if row["direction"] == "credit" and row["party"] == "recipient"]
    side_credits = [row for row in balance_writes if row["direction"] == "credit" and row["party"] not in {"recipient"}]
    if not sender_debits or not recipient_credits:
        return []

    sender_debit = sender_debits[0]
    recipient_credit = recipient_credits[0]
    fee_credit = side_credits[0] if side_credits else None
    supply_delta = _supply_delta(supply_writes)
    sender_expr = sender_debit["amount_expression"]
    recipient_expr = recipient_credit["amount_expression"]
    fee_expr = fee_credit["amount_expression"] if fee_credit else None
    gross_amount = _infer_gross_amount(fn, sender_expr, fee_expr)
    net_amount = recipient_expr
    proved_relation = _proved_relation(gross_amount, net_amount, fee_expr)
    mismatch_positive = bool(
        fee_expr
        and supply_delta == "0"
        and _normalize_expr(sender_expr) == _normalize_expr(recipient_expr)
    )
    relation = "credits_equal_sender_debit_plus_side_credit" if mismatch_positive else "credits_consistent_or_unproven"
    no_supply_write_ref = f"state_model:evidence:no_totalSupply_write:{_first_path_id(fn) or fn.get('identity', {}).get('selector')}"
    evidence_refs = {
        "sender_debit_action": sender_debit.get("action_id"),
        "recipient_credit_action": recipient_credit.get("action_id"),
        "fee_credit_action": fee_credit.get("action_id") if fee_credit else None,
        "side_credit_actions": [row.get("action_id") for row in side_credits if row.get("action_id")],
        "total_supply_nonwrite_proof": no_supply_write_ref if supply_delta == "0" else None,
    }
    balance_sum_delta = fee_expr if mismatch_positive else "0_or_unproven"
    behavior_tags = _accounting_behavior_tags(side_credits, supply_writes, mismatch_positive)
    if proved_relation:
        behavior_tags.append("net_amount_relation_proven")
    return [{
        "id": f"{fn.get('identity', {}).get('selector')}:accounting:0",
        "kind": "transfer_accounting_summary",
        "path_id": _first_path_id(fn),
        "gross_amount": gross_amount,
        "fee_amount": fee_expr,
        "net_amount": net_amount,
        "proved_relation": proved_relation,
        "sender_debit": sender_expr,
        "recipient_credit": recipient_expr,
        "fee_credit": fee_expr,
        "side_credits": [
            {
                "party": row["party"],
                "target": row["target"],
                "amount": row["amount_expression"],
                "action_id": row.get("action_id"),
            }
            for row in side_credits
        ],
        "sum_of_credits": " + ".join(
            [recipient_expr] + [row["amount_expression"] for row in side_credits]
        ),
        "net_mismatch": fee_expr if mismatch_positive else "0_or_unproven",
        "supply_delta": supply_delta,
        "balance_sum_delta": balance_sum_delta,
        "invariant": "sum(balanceOf) == totalSupply",
        "post_invariant_delta": balance_sum_delta,
        "mismatch_relation": relation,
        "behavior_tags": behavior_tags,
        "economic_effects": ["balance_inflation_without_supply_change"] if mismatch_positive else [],
        "evidence_refs": evidence_refs,
        "trust": semantic.get("trust", _trust("heuristic", 0.45, False)),
    }]


def _parse_accounting_write(text: Any, action_id: str | None = None) -> dict[str, Any] | None:
    if not isinstance(text, str) or "<-" not in text:
        return None
    left, right = [part.strip() for part in text.split("<-", 1)]
    lhs = _normalize_expr(left)
    rhs = _normalize_expr(right)
    direction = None
    amount_expression = None
    if rhs.startswith(lhs + "-"):
        direction = "debit"
        amount_expression = right.split("-", 1)[1].strip()
    elif rhs.startswith(lhs + "+"):
        direction = "credit"
        amount_expression = right.split("+", 1)[1].strip()
    entity_kind = "other"
    if "totalsupply" in lhs:
        entity_kind = "total_supply"
    elif "balanceof[" in lhs or "_balances[" in lhs or "balances[" in lhs:
        entity_kind = "balance"
    if direction is None and entity_kind == "total_supply":
        if rhs.startswith(lhs + "+"):
            direction = "credit"
            amount_expression = right.split("+", 1)[1].strip()
        elif rhs.startswith(lhs + "-"):
            direction = "debit"
            amount_expression = right.split("-", 1)[1].strip()
    if entity_kind not in {"balance", "total_supply"} or direction is None:
        return None
    target = _extract_bracket_target(left)
    target_text = _normalize_expr(target)
    party = "other"
    if any(token in target_text for token in ("msg.sender", "sender", "from")):
        party = "sender"
    elif any(token in target_text for token in ("recipient", "to")):
        party = "recipient"
    elif any(token in target_text or token in rhs for token in ("fee", "treasury", "reward", "avalanche", "staking")):
        party = "fee"
    return {
        "entity_kind": entity_kind,
        "direction": direction,
        "target": target,
        "party": party,
        "amount_expression": amount_expression,
        "action_id": action_id,
        "raw": text,
    }


def _infer_gross_amount(fn: dict[str, Any], net_amount: str, fee_amount: str | None) -> str | None:
    if not fee_amount:
        return None
    semantic = fn.get("state", {}).get("semantic_summary", {})
    search_space = []
    search_space.extend(str(row) for row in semantic.get("reads", []))
    search_space.extend(str(row) for row in semantic.get("writes", []))
    search_space.extend(str(row) for row in semantic.get("events", []))
    search_space.extend(str(row) for row in fn.get("path_conditions", []))
    search_space.extend(str(row.get("expression", "")) for row in fn.get("actions", []))
    search_space.extend(str(row) for row in fn.get("flows", []))
    for text in search_space:
        if re.search(r"\bamount\b", text) and _normalize_expr(text) != _normalize_expr(net_amount):
            return "amount"
    if _normalize_expr(net_amount) == "tokenstotransfer":
        return "amount"
    return None


def _proved_relation(gross_amount: str | None, net_amount: str | None, fee_amount: str | None) -> str | None:
    if gross_amount and net_amount and fee_amount:
        return f"{net_amount} = {gross_amount} - {fee_amount}"
    return None


def _extract_bracket_target(left: str) -> str:
    match = re.search(r"\[(.+)\]", left)
    if match:
        return match.group(1).strip()
    return left


def _normalize_expr(text: Any) -> str:
    return re.sub(r"\s+", "", str(text)).lower()


def _supply_delta(supply_writes: list[dict[str, Any]]) -> str:
    if not supply_writes:
        return "0"
    directions = {row["direction"] for row in supply_writes}
    if directions == {"credit"}:
        return "positive"
    if directions == {"debit"}:
        return "negative"
    return "mixed_or_unknown"


def _accounting_behavior_tags(side_credits: list[dict[str, Any]], supply_writes: list[dict[str, Any]], mismatch_positive: bool) -> list[str]:
    tags = ["sender_debit_present", "recipient_credit_present"]
    if side_credits:
        tags.append("side_credit_present")
    if not supply_writes:
        tags.append("total_supply_unchanged")
    if mismatch_positive:
        tags.extend(["credit_exceeds_sender_debit", "net_mismatch_positive"])
    return tags


def _accounting_tags(facts: list[dict[str, Any]]) -> set[str]:
    tags = set()
    for fact in facts:
        tags.update(fact.get("behavior_tags", []))
        tags.update(fact.get("economic_effects", []))
        if fact.get("kind"):
            tags.add(fact["kind"])
    return tags


def _operation_kind(text: str) -> str:
    if "%" in text:
        return "mod"
    if "*" in text and "/" in text:
        return "mul_div"
    if "*" in text:
        return "mul"
    if "/" in text:
        return "div"
    return "arithmetic"


def _rounding_mode(text: str) -> str:
    if "/" in text:
        return "floor"
    return "exact_or_wrapping"


def _precision_loss_risk(text: str) -> str:
    if "/" in text:
        return "possible_truncation"
    if "%" in text:
        return "rounding_remainder_observed"
    return "none"


def _trust(source: str, confidence: float, usable_as_detector_proof: bool) -> dict[str, Any]:
    return {
        "trust_source": source,
        "confidence": confidence,
        "usable_as_detector_proof": usable_as_detector_proof,
    }


def _pattern_trust(pattern) -> dict[str, Any]:
    details = getattr(pattern, "details", {}) or {}
    if details.get("profile"):
        return _trust("profile_hint", min(float(pattern.confidence), 0.6), False)
    return _trust("heuristic", float(pattern.confidence), float(pattern.confidence) >= 0.8)


def _storage_trust(evidence: list[Any], confidence: float) -> dict[str, Any]:
    text = " ".join(str(item).lower() for item in evidence)
    if "profile anchor" in text:
        return _trust("profile_hint", min(float(confidence), 0.7), False)
    if "getter" in text or "observed" in text or "storage access" in text:
        return _trust("bytecode_inferred", float(confidence), True)
    return _trust("heuristic", float(confidence), float(confidence) >= 0.8)


def _empty_function_behavior() -> dict[str, Any]:
    return {
        "actions": [],
        "state_effects": {"reads": [], "writes": [], "semantic_summary": {}},
        "external_interactions": [],
        "dataflow": {"sources": [], "propagations": [], "sanitizers": [], "sinks": [], "traces": []},
        "control_flow": {"entry_block": None, "blocks": [], "branches": [], "reverts": [], "returns": [], "loops": [], "paths": []},
        "behavior_tags": [],
        "path_summary": {},
    }
