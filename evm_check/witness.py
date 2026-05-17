"""Optional witness backends for detector corroboration."""

from __future__ import annotations

from typing import Any


def collect_witness(audit: dict[str, Any], rule: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any] | None:
    proof = rule.get("proof", {})
    preferred = proof.get("preferred_witness", "none")
    if preferred == "none":
        return None
    if preferred == "deterministic_accounting_witness":
        return _deterministic_accounting_witness(context or {})
    if preferred == "deterministic_arithmetic_witness":
        return _deterministic_rounding_witness(audit, context or {})
    if preferred == "transaction_sequence":
        return _transaction_sequence_witness(rule, context or {})
    if preferred in {"reachable_path", "invariant_argument"}:
        return {
            "kind": preferred,
            "source": "native_checker",
            "summary": "Matched detector predicates with bound state joins and effect constraints.",
        }
    adapters = proof.get("witness_generation", {}).get("optional_adapters", [])
    if adapters:
        return {
            "kind": preferred,
            "source": "adapter_placeholder",
            "summary": "Optional witness adapters are declared but not required for base detection.",
            "adapters": adapters,
        }
    return None


def _deterministic_rounding_witness(audit: dict[str, Any], context: dict[str, Any]) -> dict[str, Any] | None:
    fn = context.get("function", {})
    for fact in fn.get("arithmetic", []):
        if fact.get("operation") not in {"fixed_point_mul_div", "fixed_point_candidate"}:
            continue
        scale = int(fact.get("scaling_factor", 10**18))
        denominator = int(fact.get("denominator", 10**18))
        max_amount = 256
        for amount in range(1, max_amount + 1):
            product = amount * scale
            rounded = product // denominator
            remainder = product % denominator
            if remainder and rounded <= amount:
                return {
                    "kind": "deterministic_arithmetic_witness",
                    "source": "native_checker",
                    "witness_id": fact.get("id"),
                    "path_id": ((fn.get("paths") or [{}])[0]).get("id"),
                    "amount": amount,
                    "scaling_factor": scale,
                    "denominator": denominator,
                    "rounded": rounded,
                    "discarded_remainder": remainder,
                    "evidence_refs": {
                        "arithmetic_fact": fact.get("id"),
                        "offset": fact.get("offset"),
                        "block": fact.get("block"),
                    },
                }
    return None


def _transaction_sequence_witness(rule: dict[str, Any], context: dict[str, Any]) -> dict[str, Any] | None:
    sequences = context.get("sequences", [])
    if not sequences:
        return None
    first = sequences[0]
    evidence_refs = []
    path_ids = []
    for step in first.get("steps", []):
        writer = step.get("writer", {})
        reader = step.get("reader", {})
        call = step.get("call", {})
        path = writer.get("path") or reader.get("path") or call.get("path") or step.get("path")
        if path and path not in path_ids:
            path_ids.append(path)
        for key in ("action_id",):
            for row in (writer, reader, call):
                ref = row.get(key)
                if ref and ref not in evidence_refs:
                    evidence_refs.append(ref)
        if step.get("slot") and step["slot"] not in evidence_refs:
            evidence_refs.append(step["slot"])
    return {
        "kind": "transaction_sequence",
        "source": "native_checker",
        "witness_id": f"{rule.get('rule', {}).get('id')}:{len(first.get('steps', []))}_step_sequence",
        "path_ids": path_ids,
        "steps": first.get("steps", []),
        "bindings": first.get("bindings", {}),
        "evidence_refs": evidence_refs,
        "summary": f"Matched {len(first.get('steps', []))}-step exploit sequence for {rule.get('rule', {}).get('id')}.",
    }


def _deterministic_accounting_witness(context: dict[str, Any]) -> dict[str, Any] | None:
    fn = context.get("function", {})
    for fact in fn.get("accounting", []):
        if "balance_inflation_without_supply_change" not in set(fact.get("economic_effects", [])):
            continue
        evidence_refs = fact.get("evidence_refs", {})
        return {
            "kind": "deterministic_accounting_witness",
            "source": "native_checker",
            "witness_id": fact.get("id"),
            "path_id": fact.get("path_id"),
            "gross_amount": fact.get("gross_amount"),
            "fee_amount": fact.get("fee_amount"),
            "net_amount": fact.get("net_amount"),
            "proved_relation": fact.get("proved_relation"),
            "sender_debit": fact.get("sender_debit"),
            "recipient_credit": fact.get("recipient_credit"),
            "fee_credit": fact.get("fee_credit"),
            "side_credits": fact.get("side_credits", []),
            "total_credited": fact.get("sum_of_credits"),
            "total_supply_delta": fact.get("supply_delta"),
            "balance_sum_delta": fact.get("balance_sum_delta"),
            "invariant": fact.get("invariant"),
            "post_invariant_delta": fact.get("post_invariant_delta"),
            "mismatch_amount": fact.get("net_mismatch"),
            "mismatch_relation": fact.get("mismatch_relation"),
            "evidence_refs": {
                "sender_debit_action": evidence_refs.get("sender_debit_action"),
                "recipient_credit_action": evidence_refs.get("recipient_credit_action"),
                "fee_credit_action": evidence_refs.get("fee_credit_action"),
                "total_supply_nonwrite_proof": evidence_refs.get("total_supply_nonwrite_proof"),
            },
        }
    return None
