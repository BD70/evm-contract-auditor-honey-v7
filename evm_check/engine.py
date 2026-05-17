"""Detector engine for evm-audit behavior JSON."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .corpus_loader import load_corpus_manifest
from .findings import (
    build_function_finding,
    build_stateful_finding,
    evaluate_sequence_counter_evidence,
)
from .policy import (
    STATUS_PROBABLE,
    coverage_checks,
)
from .rule_loader import load_rules
from .schema import (
    CHECKER_SCHEMA,
    PROOF_ORDER,
    validate_audit,
    validate_rule,
)
from .witness import collect_witness


def check_audit(audit: dict[str, Any], rules: list[dict[str, Any]]) -> dict[str, Any]:
    audit_errors = validate_audit(audit)
    if audit_errors:
        raise ValueError("; ".join(audit_errors))

    findings = []
    trace = []
    for rule in rules:
        validation = validate_rule(rule)
        if not validation["ok"]:
            rid = rule.get("rule", {}).get("id", "<unknown>")
            raise ValueError(f"detector {rid} validation failed: " + "; ".join(validation["errors"]))
        rule_findings, rule_trace = _evaluate_rule(audit, rule)
        findings.extend(rule_findings)
        trace.extend(rule_trace)

    return {
        "schema": CHECKER_SCHEMA,
        "schema_version": "1.0.0",
        "audit_schema": audit.get("schema"),
        "audit_schema_version": audit.get("schema_version"),
        "rules_loaded": len(rules),
        "findings": findings,
        "trace": trace,
    }


def validate_rules(rules: list[dict[str, Any]], root: str | Path | None = None) -> dict[str, Any]:
    results = [validate_rule(rule, root=root) for rule in rules]
    errors = [
        {"rule_id": rule.get("rule", {}).get("id"), "errors": result["errors"]}
        for rule, result in zip(rules, results)
        if result["errors"]
    ]
    warnings = [
        {"rule_id": rule.get("rule", {}).get("id"), "warnings": result["warnings"]}
        for rule, result in zip(rules, results)
        if result["warnings"]
    ]
    return {
        "schema": "evm-audit.detector_validation",
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
    }


def _evaluate_rule(audit: dict[str, Any], rule: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    scope = rule.get("rule", {}).get("scope", "function")
    if scope in {"contract", "cross_function", "multi_tx", "protocol"}:
        return _evaluate_stateful_rule(audit, rule)

    findings = []
    trace = []
    for fn in audit.get("functions", []):
        matched, details = _match_function(audit, fn, rule)
        trace.append({
            "rule_id": rule["rule"]["id"],
            "function": fn.get("identity", {}).get("selector"),
            "matched": matched,
            "details": details,
        })
        if matched:
            findings.append(build_function_finding(audit, fn, rule, details))
    return findings, trace


def _match_function(audit: dict[str, Any], fn: dict[str, Any], rule: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    requires = rule.get("requires", {})
    require_usable_primary_evidence = _require_usable_primary_evidence(rule)
    tags = _function_tags(fn) | _global_tags(audit)

    # Enrich tags with path_index + guard_catalog guards for this function
    fn_selector = fn.get("identity", {}).get("selector")
    state_model = audit.get("state_model", {})
    for path_entry in state_model.get("path_index", []):
        if path_entry.get("function") == fn_selector:
            for g in path_entry.get("guard_refs", []):
                tags.add(g)
    for cat_entry in state_model.get("guard_catalog", []):
        if cat_entry.get("function") == fn_selector:
            gid = cat_entry.get("id", "")
            if gid:
                tags.add(gid)
            gtype = cat_entry.get("type", "")
            if gtype:
                tags.add(gtype)

    required = set(requires.get("facts_all", []))
    missing = sorted(tag for tag in required if tag not in tags)
    forbidden = _counter_tags_hit(tags, rule.get("counter_evidence", {}).get("suppress_if_any", []))
    flow_checks = _match_flows(fn, requires.get("flows_all", []))
    arithmetic_checks = _match_arithmetic(fn, rule, require_usable_primary_evidence=require_usable_primary_evidence)
    effect_checks = _match_function_effects(fn, requires)
    coverage_results = coverage_checks(audit, rule)
    counter_evidence = _counter_evidence_details(tags, rule)
    witness = collect_witness(audit, rule, context={"function": fn, "effects": effect_checks})

    matched = (
        not missing
        and not forbidden
        and flow_checks["matched"]
        and arithmetic_checks["matched"]
        and effect_checks["matched"]
    )
    return matched, {
        "required_facts": sorted(required),
        "available_facts": sorted(tags),
        "missing_facts": missing,
        "suppressed_by": forbidden,
        "flow_checks": flow_checks,
        "arithmetic_checks": arithmetic_checks,
        "effect_checks": effect_checks,
        "coverage_checks": coverage_results,
        "counter_evidence": counter_evidence,
        "witness": witness,
    }


def _evaluate_stateful_rule(audit: dict[str, Any], rule: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    requires = rule.get("requires", {})
    state_model = audit.get("state_model", {})

    # ── Gate: facts_all must be present in global/function tags ──
    all_tags = _global_tags(audit)
    for fn in audit.get("functions", []):
        all_tags |= _function_tags(fn)
    required_facts = set(requires.get("facts_all", []))
    missing_facts = sorted(f for f in required_facts if f not in all_tags)
    if missing_facts:
        trace = [{
            "rule_id": rule["rule"]["id"],
            "scope": rule["rule"]["scope"],
            "matched": False,
            "details": {"missing_facts": missing_facts},
        }]
        return [], trace

    # ── Gate: authorized_path_effect_any must appear somewhere ──
    auth_effects = set(requires.get("authorized_path_effect_any", []))
    if auth_effects:
        contract_effects: set[str] = set()
        for fn in audit.get("functions", []):
            contract_effects |= _function_effects(fn)
        for slot in state_model.get("slot_index", []):
            contract_effects |= _slot_effects(slot)
        for call_entry in state_model.get("call_index", []):
            kind = call_entry.get("kind", "")
            if kind == "delegatecall":
                contract_effects.add("delegatecall")
            contract_effects.update(call_entry.get("reachable_effects", []))
            contract_effects.update(call_entry.get("return_flow_effects", []))
        # Also check sequence steps for effect references
        for step in requires.get("sequence", []):
            step_match = step.get("match", {})
            if "delegatecall" in step_match:
                contract_effects.add("delegatecall")
        if not auth_effects.intersection(contract_effects):
            trace = [{
                "rule_id": rule["rule"]["id"],
                "scope": rule["rule"]["scope"],
                "matched": False,
                "details": {"missing_authorized_effects": sorted(auth_effects)},
            }]
            return [], trace

    matched_sequences = _match_sequences(audit, rule, state_model)
    coverage_results = coverage_checks(audit, rule)
    counter_results = evaluate_sequence_counter_evidence(matched_sequences, rule, audit=audit)
    filtered_sequences = [seq for seq in matched_sequences if not seq.get("suppressed_by")]
    matched = bool(filtered_sequences)
    trace = [{
        "rule_id": rule["rule"]["id"],
        "scope": rule["rule"]["scope"],
        "matched": matched,
        "details": {
            "sequences": matched_sequences,
            "counter_evidence": counter_results,
            "coverage_checks": coverage_results,
        },
    }]
    if not matched:
        return [], trace
    finding = build_stateful_finding(audit, rule, filtered_sequences, coverage_results, counter_results)
    return [finding], trace


def _match_sequences(audit: dict[str, Any], rule: dict[str, Any], state_model: dict[str, Any]) -> list[dict[str, Any]]:
    sequence = rule.get("requires", {}).get("sequence", [])
    require_usable_primary_evidence = _require_usable_primary_evidence(rule)
    if not sequence:
        return _match_contract_predicates(audit, rule, state_model, require_usable_primary_evidence=require_usable_primary_evidence)

    contexts = [{"bindings": {}, "steps": [], "slot_refs": [], "guard_refs": [], "delegate_target_refs": []}]
    for step in sequence:
        next_contexts = []
        for context in contexts:
            matches = _match_step(step, state_model, context, require_usable_primary_evidence=require_usable_primary_evidence)
            for match in matches:
                next_contexts.append(match)
        contexts = next_contexts
    return contexts


def _match_contract_predicates(
    audit: dict[str, Any],
    rule: dict[str, Any],
    state_model: dict[str, Any],
    *,
    require_usable_primary_evidence: bool = False,
) -> list[dict[str, Any]]:
    predicates = rule.get("requires", {})
    matches = []
    has_structural_constraints = bool(
        predicates.get("storage_write") or predicates.get("external_call")
    )

    for slot in state_model.get("slot_index", []):
        write_constraint = predicates.get("storage_write", {})
        if not _match_slot_constraint(slot, write_constraint, {}, require_usable_primary_evidence=require_usable_primary_evidence):
            continue
        if write_constraint:
            if not any(_match_writer(writer, write_constraint) for writer in slot.get("writers", [])):
                continue
        effects = predicates.get("reachable_effect_any", [])
        if effects and not any(effect in _slot_effects(slot) for effect in effects):
            continue
        matches.append({
            "bindings": {"$slot": slot.get("slot")},
            "steps": [{"id": "contract_predicate", "slot": slot.get("slot"), "writers": slot.get("writers", [])}],
            "slot_refs": [slot.get("slot")],
            "guard_refs": slot.get("guards", []),
            "delegate_target_refs": [],
        })

    ext_call_constraint = predicates.get("external_call", {})
    if ext_call_constraint:
        effects = predicates.get("reachable_effect_any", [])
        for call in state_model.get("call_index", []):
            if not _match_external_call(
                call, ext_call_constraint, predicates, {},
                require_usable_primary_evidence=require_usable_primary_evidence,
            ):
                continue
            call_effects = set(call.get("return_flow_effects", []) + call.get("reachable_effects", []))
            if effects and not any(e in call_effects for e in effects):
                continue
            matches.append({
                "bindings": {"$target": call.get("target")},
                "steps": [{"id": "contract_predicate", "call_target": call.get("target"), "call": call}],
                "slot_refs": [],
                "guard_refs": call.get("guard_refs", []),
                "delegate_target_refs": [],
            })

    # Fallback: facts-only contract-scope rules with no structural constraints
    if not matches and not has_structural_constraints:
        required_effects = set(predicates.get("reachable_effect_any", []))
        contract_effects: set[str] = set()
        for fn in audit.get("functions", []):
            contract_effects |= _function_effects(fn)
        for slot in state_model.get("slot_index", []):
            contract_effects |= _slot_effects(slot)
        for call_entry in state_model.get("call_index", []):
            contract_effects.update(call_entry.get("reachable_effects", []))
        if not required_effects or required_effects.intersection(contract_effects):
            all_guards: list[str] = []
            for slot in state_model.get("slot_index", []):
                all_guards.extend(slot.get("guards", []))
            matches.append({
                "bindings": {},
                "steps": [{"id": "contract_level_fact_match"}],
                "slot_refs": [],
                "guard_refs": all_guards,
                "delegate_target_refs": [],
            })

    return matches


def _match_step(
    step: dict[str, Any],
    state_model: dict[str, Any],
    context: dict[str, Any],
    *,
    require_usable_primary_evidence: bool = False,
) -> list[dict[str, Any]]:
    match = step.get("match", {})
    results = []
    if "storage_write" in match:
        for slot in state_model.get("slot_index", []):
            if not _match_slot_constraint(
                slot,
                match["storage_write"],
                context["bindings"],
                require_usable_primary_evidence=require_usable_primary_evidence,
            ):
                continue
            for writer in slot.get("writers", []):
                if not _match_writer(writer, match["storage_write"]):
                    continue
                results.append(_extend_context(context, step, slot, writer=writer))
    elif "storage_read" in match:
        for slot in state_model.get("slot_index", []):
            if not _match_slot_constraint(
                slot,
                match["storage_read"],
                context["bindings"],
                require_usable_primary_evidence=require_usable_primary_evidence,
            ):
                continue
            for reader in slot.get("readers", []):
                if not _match_reader(reader, match):
                    continue
                results.append(_extend_context(context, step, slot, reader=reader))
    elif "delegatecall" in match:
        for call in state_model.get("call_index", []):
            if _match_delegatecall(
                call,
                match["delegatecall"],
                context["bindings"],
                require_usable_primary_evidence=require_usable_primary_evidence,
            ):
                results.append(_extend_context(context, step, None, call=call))
    elif "external_call" in match:
        for call in state_model.get("call_index", []):
            if _match_external_call(
                call,
                match["external_call"],
                match,
                context["bindings"],
                require_usable_primary_evidence=require_usable_primary_evidence,
            ):
                results.append(_extend_context(context, step, None, call=call))
    return results


def _extend_context(
    context: dict[str, Any],
    step: dict[str, Any],
    slot: dict[str, Any] | None,
    writer: dict[str, Any] | None = None,
    reader: dict[str, Any] | None = None,
    call: dict[str, Any] | None = None,
) -> dict[str, Any]:
    bindings = dict(context["bindings"])
    bind = step.get("bind", {})
    if slot:
        for key, name in bind.items():
            if not isinstance(name, str) or not name.startswith("$"):
                continue
            if key == "slot":
                bindings[name] = slot.get("slot")
            elif key == "path":
                bindings[name] = (writer or reader or {}).get("path")
            elif key == "guard":
                guard_refs = (writer or reader or {}).get("guard_refs", [])
                bindings[name] = guard_refs[0] if guard_refs else None
            elif key == "value_origin":
                bindings[name] = (writer or {}).get("write_origin")
    if call and not slot:
        for key, name in bind.items():
            if not isinstance(name, str) or not name.startswith("$"):
                continue
            if key == "call_target":
                bindings[name] = call.get("target")
    new_context = {
        "bindings": bindings,
        "steps": list(context["steps"]),
        "slot_refs": list(context["slot_refs"]),
        "guard_refs": list(context["guard_refs"]),
        "delegate_target_refs": list(context["delegate_target_refs"]),
    }
    entry = {"id": step.get("id")}
    if slot:
        entry["slot"] = slot.get("slot")
        entry["semantic_role"] = slot.get("semantic_role")
        new_context["slot_refs"].append(slot.get("slot"))
        new_context["guard_refs"].extend(slot.get("guards", []))
    if writer:
        entry["writer"] = writer
    if reader:
        entry["reader"] = reader
    if call:
        entry["call"] = call
        new_context["delegate_target_refs"].append(call.get("target"))
    new_context["steps"].append(entry)
    return new_context


def _match_slot_constraint(
    slot: dict[str, Any],
    constraint: dict[str, Any],
    bindings: dict[str, Any],
    *,
    require_usable_primary_evidence: bool = False,
) -> bool:
    if require_usable_primary_evidence and not _trust_usable(slot.get("trust")):
        return False
    roles = set(constraint.get("semantic_role_any", []))
    if roles and slot.get("semantic_role") not in roles:
        return False
    same_slot = constraint.get("same_slot_as")
    if same_slot and slot.get("slot") != bindings.get(same_slot):
        return False
    min_conf = float(constraint.get("min_role_confidence", 0.0))
    if float(slot.get("role_confidence", slot.get("confidence", 0.0))) < min_conf:
        return False
    if constraint.get("proxy_slot_kind"):
        proxy = slot.get("proxy", {})
        if proxy.get("slot_kind") != constraint.get("proxy_slot_kind"):
            return False
    return True


def _match_writer(writer: dict[str, Any], constraint: dict[str, Any]) -> bool:
    if constraint.get("user_controlled_write_value") and not writer.get("user_controlled_write_value"):
        return False
    if constraint.get("caller_reachability") and writer.get("caller_reachability") != constraint.get("caller_reachability"):
        return False
    if constraint.get("caller_constraint") and writer.get("caller_constraint") != constraint.get("caller_constraint"):
        return False
    origins = set(constraint.get("write_origin_any", []))
    if origins and writer.get("write_origin") not in origins:
        return False
    return True


def _match_reader(reader: dict[str, Any], match: dict[str, Any]) -> bool:
    constraint = match.get("storage_read", {})
    if constraint.get("used_in") and reader.get("used_in") != constraint.get("used_in"):
        return False
    effects = set(match.get("authorized_path_effect_any", []))
    if effects and not effects.intersection(set(reader.get("authorized_path_effects", []))):
        return False
    reachable = set(match.get("reachable_effect_any", []))
    if reachable and not reachable.intersection(set(reader.get("reachable_effects", []))):
        return False
    return True


def _match_delegatecall(
    call: dict[str, Any],
    constraint: dict[str, Any],
    bindings: dict[str, Any],
    *,
    require_usable_primary_evidence: bool = False,
) -> bool:
    if require_usable_primary_evidence and not _trust_usable(call.get("trust")):
        return False
    if call.get("kind") != "delegatecall":
        return False
    if constraint.get("target_origin_any"):
        if call.get("target_origin") not in set(constraint["target_origin_any"]):
            return False
    same_slot = constraint.get("same_slot_as")
    if same_slot and call.get("target_slot") != bindings.get(same_slot):
        return False
    controllability = constraint.get("target_controllability")
    if controllability and call.get("target_controllability") != controllability:
        return False
    return True


def _match_external_call(
    call: dict[str, Any],
    constraint: dict[str, Any],
    match_ctx: dict[str, Any],
    bindings: dict[str, Any],
    *,
    require_usable_primary_evidence: bool = False,
) -> bool:
    if require_usable_primary_evidence and not _trust_usable(call.get("trust")):
        return False
    kind = call.get("kind", "")
    if kind not in {"external_call", "call", "staticcall"}:
        return False
    if constraint.get("target_origin_any"):
        if call.get("target_origin") not in set(constraint["target_origin_any"]):
            return False
    controllability = constraint.get("target_controllability")
    if controllability and call.get("target_controllability") != controllability:
        return False
    validation = constraint.get("address_validation")
    if validation and call.get("address_validation") != validation:
        return False
    if constraint.get("return_value_consumed") and not call.get("return_value_consumed"):
        return False
    same_target = constraint.get("same_call_target_as")
    if same_target and call.get("target") != bindings.get(same_target):
        return False
    return_effects = set(constraint.get("return_flow_effect_any", []))
    if return_effects and not return_effects.intersection(set(call.get("return_flow_effects", []))):
        return False
    reachable = set(match_ctx.get("reachable_effect_any", []))
    if reachable:
        call_effects = set(call.get("return_flow_effects", []) + call.get("reachable_effects", []))
        if not reachable.intersection(call_effects):
            return False
    return True


def _function_tags(fn: dict[str, Any]) -> set[str]:
    tags = set(fn.get("behavior_tags", []))
    tags.update(fn.get("tags", []))
    for arith in fn.get("arithmetic", []):
        tags.update(arith.get("behavior_tags", []))
        if arith.get("operation"):
            tags.add(arith["operation"])
        if arith.get("economic_fact_kind"):
            tags.add(arith["economic_fact_kind"])
    for fact in fn.get("accounting", []):
        tags.update(fact.get("behavior_tags", []))
        if fact.get("kind"):
            tags.add(fact["kind"])
        if fact.get("mismatch_relation"):
            tags.add(fact["mismatch_relation"])
    # Detect guard-derived tags from function state
    for guard in fn.get("state", {}).get("guards", fn.get("guards", [])):
        if isinstance(guard, str):
            tags.add(guard)
    return tags


def _global_tags(audit: dict[str, Any]) -> set[str]:
    tags = set(audit.get("global_tags", []))
    for invariant in audit.get("invariants", []):
        if invariant.get("kind"):
            tags.add(invariant["kind"])
    for entry in audit.get("state_model", {}).get("proxy_index", []):
        if entry.get("proxy_standard"):
            tags.add(entry["proxy_standard"])

    # Include bytecode fingerprint tags (from known_bytecodes module)
    fingerprint = audit.get("bytecode_fingerprint", {})
    tags.update(fingerprint.get("tags", []))

    # Include guard catalog types as global tags for counter-evidence matching
    for entry in audit.get("state_model", {}).get("guard_catalog", []):
        gtype = entry.get("type", "")
        if gtype:
            tags.add(gtype)
        strength = entry.get("strength", "")
        if strength == "strong":
            tags.add("STRONG_GUARD_PRESENT")

    # Include initializer index presence
    initializer_index = audit.get("state_model", {}).get("initializer_index", [])
    if initializer_index:
        tags.add("INITIALIZABLE")
        tags.add("initializer_guard")

    return tags


def _match_flows(fn: dict[str, Any], flow_rules: list[dict[str, Any]]) -> dict[str, Any]:
    if not flow_rules:
        return {"matched": True, "matches": []}
    matches = []
    flow_texts = [json.dumps(flow, sort_keys=True) for flow in fn.get("flows", [])]
    action_texts = [json.dumps(action, sort_keys=True) for action in fn.get("actions", [])]
    call_texts = [json.dumps(call, sort_keys=True) for call in fn.get("external_calls", [])]
    tag_text = json.dumps(fn.get("behavior_tags", []), sort_keys=True)
    haystack = "\n".join(flow_texts + action_texts + call_texts + [json.dumps(fn.get("state", {}), sort_keys=True), tag_text])
    for rule in flow_rules:
        # Support both source/through/sink and from/to/through key conventions
        required_parts = []
        for primary, fallback in (("source", "from"), ("through", "through"), ("sink", "to")):
            value = rule.get(primary) or rule.get(fallback)
            if value:
                required_parts.append(str(value))
        ok = all(part in haystack for part in required_parts)
        matches.append({"rule": rule, "matched": ok})
    return {"matched": all(m["matched"] for m in matches), "matches": matches}


def _match_arithmetic(
    fn: dict[str, Any],
    rule: dict[str, Any],
    *,
    require_usable_primary_evidence: bool = False,
) -> dict[str, Any]:
    required = set(rule.get("requires", {}).get("economic_effect_any", []))
    category = rule.get("rule", {}).get("category")
    if not required and category not in {"arithmetic_invariant", "accounting_invariant"}:
        return {"matched": True, "matches": []}
    matches = []
    for fact in fn.get("arithmetic", []):
        if require_usable_primary_evidence and not _trust_usable(fact.get("trust")):
            continue
        tags = set(fact.get("behavior_tags", []))
        effects = set(fact.get("economic_effects", []))
        if required and not required.intersection(tags | effects):
            continue
        if fact.get("operation") in {"fixed_point_mul_div", "fixed_point_candidate"} or "fixed_point_floor_mul_or_div" in tags:
            matches.append(fact)
    for fact in fn.get("accounting", []):
        if require_usable_primary_evidence and not _trust_usable(fact.get("trust")):
            continue
        tags = set(fact.get("behavior_tags", []))
        effects = set(fact.get("economic_effects", []))
        if required and not required.intersection(tags | effects):
            continue
        matches.append(fact)
    # For non-arithmetic categories (e.g. access_control), economic_effect_any
    # may describe vulnerability impact that appears as behavior tags on the
    # function itself rather than arithmetic/accounting facts.
    if not matches and required and category not in {"arithmetic_invariant", "accounting_invariant"}:
        fn_tags = set(fn.get("behavior_tags", []))
        if required.intersection(fn_tags):
            return {"matched": True, "matches": []}
    return {"matched": bool(matches), "matches": matches}


def _match_function_effects(fn: dict[str, Any], requires: dict[str, Any]) -> dict[str, Any]:
    actual = _function_effects(fn)
    required = set(requires.get("reachable_effect_any", []))
    authorized = set(requires.get("authorized_path_effect_any", []))
    matched = True
    if required and not required.intersection(actual):
        matched = False
    if authorized and not authorized.intersection(actual):
        matched = False
    return {"matched": matched, "actual": sorted(actual)}


def _function_effects(fn: dict[str, Any]) -> set[str]:
    effects = set()
    for action in fn.get("actions", []):
        if action.get("semantic_effect"):
            effects.add(action["semantic_effect"])
        t = action.get("type")
        if t == "DELEGATECALL":
            effects.add("delegatecall")
        if t == "SELFDESTRUCT":
            effects.add("selfdestruct")
    for call in fn.get("external_calls", []):
        if call.get("semantic_effect"):
            effects.add(call["semantic_effect"])
    for read in fn.get("state", {}).get("reads", []):
        effects.update(read.get("reachable_effects", []))
    for fact in fn.get("accounting", []):
        effects.update(fact.get("economic_effects", []))
    return effects


def _slot_effects(slot: dict[str, Any]) -> set[str]:
    effects = set()
    for reader in slot.get("readers", []):
        effects.update(reader.get("reachable_effects", []))
        effects.update(reader.get("authorized_path_effects", []))
    return effects


def _counter_tags_hit(tags: set[str], configured: list[str]) -> list[str]:
    return sorted(token for token in configured if token in tags)


def _counter_evidence_details(tags: set[str], rule: dict[str, Any]) -> dict[str, Any]:
    counter = rule.get("counter_evidence", {})
    return {
        "suppress_if_any": _counter_tags_hit(tags, counter.get("suppress_if_any", [])),
        "downgrade_if_any": _counter_tags_hit(tags, counter.get("downgrade_if_any", [])),
        "inconclusive_if_any": _counter_tags_hit(tags, counter.get("inconclusive_if_any", [])),
        "manual_review_if_any": _counter_tags_hit(tags, counter.get("manual_review_if_any", [])),
    }


def _require_usable_primary_evidence(rule: dict[str, Any]) -> bool:
    analysis = rule.get("analysis_requirements", {})
    return bool(analysis.get("require_usable_primary_evidence", False))


def _trust_usable(trust: dict[str, Any] | None) -> bool:
    if trust is None:
        return True
    if "usable_as_detector_proof" not in trust:
        return True
    return bool((trust or {}).get("usable_as_detector_proof", False))

