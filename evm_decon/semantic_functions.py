"""Function-card and standards helpers extracted from semantic_patterns."""

from __future__ import annotations

from typing import Any, Optional

from .abi_recovery import RecoveredABI
from .function_slicer import FunctionUnit
from .profile_packs import ProfileRegistry
from .simplifier import simplify_text
from .stack_sim import SimulationResult
from .storage_layout import StorageLayoutResult


def detect_standards_scored(
    slices: Any,
    names: dict[str, str],
) -> list[dict[str, Any]]:
    func_names = {names.get(f.selector, "") for f in slices.functions if names.get(f.selector, "")}
    standards_defs = {
        "ERC-20": {
            "required": [
                "totalSupply()",
                "balanceOf(address)",
                "transfer(address,uint256)",
                "approve(address,uint256)",
                "transferFrom(address,address,uint256)",
                "allowance(address,address)",
            ],
            "optional": ["name()", "symbol()", "decimals()"],
        },
        "ERC-721": {
            "required": [
                "ownerOf(uint256)",
                "safeTransferFrom(address,address,uint256)",
                "safeTransferFrom(address,address,uint256,bytes)",
                "setApprovalForAll(address,bool)",
                "isApprovedForAll(address,address)",
            ],
            "optional": ["tokenURI(uint256)", "supportsInterface(bytes4)"],
        },
        "ERC-1155": {
            "required": [
                "balanceOf(address,uint256)",
                "balanceOfBatch(address[],uint256[])",
                "safeTransferFrom(address,address,uint256,uint256,bytes)",
                "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)",
            ],
            "optional": ["uri(uint256)", "supportsInterface(bytes4)"],
        },
    }

    results = []
    for standard, definitions in standards_defs.items():
        matched_required = [signature for signature in definitions["required"] if signature in func_names]
        missing_required = [signature for signature in definitions["required"] if signature not in func_names]
        matched_optional = [signature for signature in definitions["optional"] if signature in func_names]
        total_required = len(definitions["required"])
        confidence = len(matched_required) / total_required if total_required > 0 else 0.0
        if len(matched_required) == total_required:
            confidence = 0.98
        evidence = []
        if matched_required:
            evidence.append(f"matched: {', '.join(matched_required)}")
        if missing_required:
            evidence.append(f"missing: {', '.join(missing_required)}")
        results.append({
            "standard": standard,
            "confidence": round(confidence, 2),
            "matched_required": matched_required,
            "missing_required": missing_required,
            "matched_optional": matched_optional,
            "evidence": evidence,
        })

    results.sort(key=lambda entry: -entry["confidence"])
    return results


def build_function_card(
    func: FunctionUnit,
    abi: Optional[RecoveredABI],
    sim: SimulationResult,
    storage: StorageLayoutResult,
    names: dict[str, str],
    profile_registry: ProfileRegistry | None,
    *,
    function_card_type: type[Any],
    active_profile_packs: set[str] | None = None,
) -> Any:
    name = func.name or names.get(func.selector, func.selector)
    mutability = abi.mutability if abi else "unknown"
    profile_overrides = profile_function_overrides(profile_registry, active_profile_packs)
    override = profile_overrides.get(name, {})

    known_view = {
        "totalSupply()", "balanceOf(address)", "allowance(address,address)",
        "DOMAIN_SEPARATOR()", "nonces(address)",
    }
    known_constant = {"name()", "symbol()", "decimals()", "PERMIT_TYPEHASH()"}
    known_state_changing = {
        "transfer(address,uint256)", "transferFrom(address,address,uint256)",
        "approve(address,uint256)", "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
    }
    if override.get("mutability"):
        mutability = override["mutability"]
    elif name in known_constant:
        mutability = "pure" if name in {"PERMIT_TYPEHASH()", "decimals()"} else "view"
    elif name in known_view:
        mutability = "view"
    elif name in known_state_changing:
        mutability = "nonpayable"

    guards: list[str] = []
    state_reads: list[str] = []
    state_writes: list[str] = []
    external_calls: list[str] = []
    events: list[str] = []
    branches: list[str] = []
    risk_flags: list[str] = []

    slot_names = {slot_num: info.name for slot_num, info in storage.slots.items() if info.name}

    def clean_expr(text: str) -> str:
        result = simplify_text(text)
        if "keccak256" in result:
            result = "mapping_access"
        for slot_num, slot_name in slot_names.items():
            result = result.replace(f"storage[0x{slot_num:02x}]", slot_name)
            result = result.replace(f"storage[{slot_num}]", slot_name)
        result = result.replace("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "0xff..ff")
        result = result.replace("0xffffffffffffffffffffffffffffffffffffffff", "addr_mask")
        return result

    seen_branches: set[str] = set()
    for bid in func.body_blocks:
        trace = sim.traces.get(bid)
        if not trace:
            continue

        if trace.branch_condition:
            cond = str(trace.branch_condition)
            if "msg.sender" in cond and "storage[0x00]" in cond and "onlyOwner" not in guards:
                guards.append("onlyOwner")
            if "msg.sender" in cond and "==" in cond and "onlyOwner" not in guards and "msg_sender_guard" not in guards:
                guards.append("msg_sender_guard")
            if "storage[0x00]" in cond and "0xff" in cond and "msg.sender" not in cond and "whenNotPaused" not in guards:
                guards.append("whenNotPaused")
            if "storage[" in cond and "0x06" in cond:
                has_blacklist_api = any("BlackList" in candidate or "Blacklisted" in candidate for candidate in names.values())
                if has_blacklist_api and "notBlacklisted" not in guards:
                    guards.append("notBlacklisted")
            if "msg.value" in cond and "nonpayable" not in guards:
                guards.append("nonpayable")
            if "calldatasize" in cond and "calldatasize_check" not in guards:
                guards.append("calldatasize_check")
            if "tx.origin" in cond and "tx_origin_whitelist" not in guards:
                guards.append("tx_origin_whitelist")
            if "storage[0x0a]" in cond and "0xff" in cond:
                branch_text = "if deprecated: forward to upgradedAddress"
                if branch_text not in seen_branches:
                    branches.append(branch_text)
                    seen_branches.add(branch_text)

        for storage_op in trace.storage_ops:
            slot_str = repr(storage_op.slot)
            if storage_op.slot.kind == "const" and isinstance(storage_op.slot.value, int):
                slot_info = storage.slots.get(storage_op.slot.value)
                slot_str = slot_info.name if slot_info and slot_info.name else f"slot_{storage_op.slot.value}"
            elif "keccak256" in slot_str:
                slot_str = "mapping_access"

            if storage_op.op_type == "read":
                cleaned = clean_expr(slot_str)
                if cleaned not in state_reads:
                    state_reads.append(cleaned)
            elif storage_op.op_type == "write":
                value_str = clean_expr(repr(storage_op.value) if storage_op.value else "?")
                cleaned_slot = clean_expr(slot_str)
                write_desc = f"{cleaned_slot} ← {value_str}"
                if write_desc not in state_writes:
                    state_writes.append(write_desc)

        for operation in trace.operations:
            if operation.category != "call":
                continue
            cleaned = clean_expr(operation.description)
            if "storage[0x0a]" in cleaned or "0x0a" in cleaned or "deprecated_packed" in cleaned:
                cleaned = "call upgradedAddress (legacy forward)"
            if cleaned not in external_calls:
                external_calls.append(cleaned)

    pre_override_guards = list(guards)
    pre_override_state_reads = list(state_reads)
    pre_override_state_writes = list(state_writes)
    pre_override_external_calls = list(external_calls)
    pre_override_events = list(events)
    pre_override_branches = list(branches)

    apply_profile_function_override(override, guards, state_reads, state_writes, external_calls, events, branches)

    semantic_override_applied = bool(
        override and any(key in override for key in ("state_reads", "state_writes", "external_calls", "guards", "events", "branches"))
    )
    pre_override_signal_present = bool(
        pre_override_guards or pre_override_state_reads or pre_override_state_writes or pre_override_external_calls or pre_override_events or pre_override_branches
    )
    semantic_signal_present = bool(guards or state_reads or state_writes or external_calls or events or branches)
    if semantic_override_applied and pre_override_signal_present:
        semantic_trust_source = "profile_corroborated"
        semantic_trust_confidence = 0.68
        semantic_usable_as_detector_proof = True
    elif semantic_override_applied:
        semantic_trust_source = "profile_hint"
        semantic_trust_confidence = 0.55
        semantic_usable_as_detector_proof = False
    elif semantic_signal_present:
        semantic_trust_source = "bytecode_inferred"
        semantic_trust_confidence = 0.72
        semantic_usable_as_detector_proof = True
    else:
        semantic_trust_source = "heuristic"
        semantic_trust_confidence = 0.4
        semantic_usable_as_detector_proof = False

    expected_permissionless = {
        "transfer(address,uint256)", "transferFrom(address,address,uint256)",
        "approve(address,uint256)", "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
    }
    if profile_registry:
        active_names = active_profile_packs
        for pack in profile_registry.packs:
            if active_names is not None and pack.name not in active_names:
                continue
            expected_permissionless.update(pack.expected_permissionless)
    if name not in expected_permissionless and "onlyOwner" not in guards and state_writes:
        risk_flags.append("state-changing without access control")

    return function_card_type(
        selector=func.selector,
        name=name,
        mutability=mutability,
        guards=guards,
        state_reads=state_reads,
        state_writes=state_writes,
        external_calls=external_calls,
        events=events,
        branches=branches,
        risk_flags=risk_flags,
        return_type=abi.return_type if abi else None,
        semantic_trust_source=semantic_trust_source,
        semantic_trust_confidence=semantic_trust_confidence,
        semantic_usable_as_detector_proof=semantic_usable_as_detector_proof,
    )


def profile_function_overrides(
    profile_registry: ProfileRegistry | None,
    active_profile_packs: set[str] | None = None,
) -> dict[str, dict[str, Any]]:
    overrides: dict[str, dict[str, Any]] = {}
    if profile_registry:
        active_names = active_profile_packs
        for pack in profile_registry.packs:
            if active_names is not None and pack.name not in active_names:
                continue
            overrides.update(pack.function_overrides)
    return overrides


def apply_profile_function_override(
    override: dict[str, Any],
    guards: list[str],
    state_reads: list[str],
    state_writes: list[str],
    external_calls: list[str],
    events: list[str],
    branches: list[str],
) -> None:
    if not override:
        return
    if "state_reads" in override:
        replace_list(state_reads, list(override.get("state_reads", [])))
    if "state_writes" in override:
        replace_list(state_writes, list(override.get("state_writes", [])))
    if "external_calls" in override:
        replace_list(external_calls, list(override.get("external_calls", [])))
    add_unique(guards, list(override.get("guards", [])))
    add_unique(events, list(override.get("events", [])))
    add_unique(branches, list(override.get("branches", [])))


def build_risk_summary(patterns: list[Any], cards: list[Any]) -> list[str]:
    risks = []
    for pattern in patterns:
        if pattern.pattern_name == "Blacklist" and pattern.confidence >= 0.5:
            risks.extend(pattern.details.get("risk", []))
        if pattern.pattern_name == "Ownable" and pattern.confidence >= 0.5:
            protected = pattern.details.get("protected_functions", [])
            if protected:
                risks.append(f"owner controls: {', '.join(protected)}")
        if pattern.pattern_name == "MintBurn" and pattern.confidence >= 0.5:
            risks.append("owner can mint/issue new tokens")
            risks.append("owner can redeem/burn tokens")
    for card in cards:
        for flag in card.risk_flags:
            risks.append(f"{card.name}: {flag}")
    return list(set(risks))


def replace_list(target: list[str], values: list[str]) -> None:
    target.clear()
    target.extend(values)


def add_unique(target: list[str], values: list[str]) -> None:
    for value in values:
        if value not in target:
            target.append(value)
