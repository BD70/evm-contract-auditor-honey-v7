"""
Semantic pattern detection with confidence scoring.

Transforms recovered facts (function signatures, storage layout, guards,
state writes, events) into structured "pattern cards" that describe
what kind of contract this is at a high level.

Each pattern has a confidence score and evidence trail so analysts
can see WHY the tool believes something.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from .function_slicer import FunctionSliceResult, FunctionUnit
from .storage_layout import StorageLayoutResult, StorageSlotInfo
from .abi_recovery import RecoveredABI
from .stack_sim import SimulationResult
from .blocks import BlockAnalysis
from .semantic_functions import (
    build_function_card,
    build_risk_summary,
    detect_standards_scored,
)
from .profile_packs import ProfileRegistry
from .semantic_profiles import apply_profile_pattern_suppression, detect_profile_patterns


@dataclass
class PatternCard:
    """A detected semantic pattern."""
    pattern_name: str          # "Ownable", "Pausable", "ERC20", etc.
    confidence: float          # 0.0 - 1.0
    evidence: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)  # pattern-specific structured data


@dataclass
class FunctionCard:
    """Semantic summary of a single function."""
    selector: str
    name: str
    mutability: str            # "nonpayable", "view", "payable", "pure"
    guards: list[str] = field(default_factory=list)
    state_reads: list[str] = field(default_factory=list)
    state_writes: list[str] = field(default_factory=list)
    external_calls: list[str] = field(default_factory=list)
    events: list[str] = field(default_factory=list)
    branches: list[str] = field(default_factory=list)
    risk_flags: list[str] = field(default_factory=list)
    return_type: Optional[str] = None
    semantic_trust_source: str = "heuristic"
    semantic_trust_confidence: float = 0.5
    semantic_usable_as_detector_proof: bool = False


@dataclass
class SemanticAnalysis:
    """Complete semantic analysis result."""
    contract_family: str       # "ERC20 + Ownable + Pausable + Blacklist + FeeToken + LegacyUpgradeForwarder"
    patterns: list[PatternCard]
    function_cards: list[FunctionCard]
    standards: list[dict]      # confidence-scored standard detection
    risk_summary: list[str]


def analyze_semantics(
    slice_result: FunctionSliceResult,
    storage_layout: StorageLayoutResult,
    abi_results: list[RecoveredABI],
    sim_result: SimulationResult,
    block_analysis: BlockAnalysis,
    resolved_names: dict[str, str] = None,
    profile_registry: ProfileRegistry | None = None,
) -> SemanticAnalysis:
    """
    Run the full semantic analysis pipeline.
    """
    if resolved_names is None:
        resolved_names = {}

    # Build name maps
    name_by_selector: dict[str, str] = {}
    for func in slice_result.functions:
        name = func.name or resolved_names.get(func.selector) or func.selector
        name_by_selector[func.selector] = name

    abi_by_selector = {a.selector: a for a in abi_results}
    block_map = {b.id: b for b in block_analysis.blocks}

    # ── Detect patterns ──────────────────────────────────────
    patterns = []
    patterns.append(_detect_ownable(slice_result, name_by_selector, sim_result, storage_layout))
    patterns.append(_detect_pausable(slice_result, name_by_selector, sim_result))
    patterns.append(_detect_erc20(slice_result, name_by_selector, abi_by_selector))
    patterns.extend(detect_profile_patterns(
        slice_result,
        name_by_selector,
        profile_registry,
        pattern_card_type=PatternCard,
    ))
    patterns.append(_detect_erc2612_permit(slice_result, name_by_selector))
    patterns.append(_detect_erc721(slice_result, name_by_selector, abi_by_selector))
    patterns.append(_detect_blacklist(slice_result, name_by_selector, sim_result))
    patterns.append(_detect_fee_token(slice_result, name_by_selector, storage_layout))
    patterns.append(_detect_legacy_upgrade(slice_result, name_by_selector, sim_result))
    patterns.append(_detect_mint_burn(slice_result, name_by_selector))

    # Filter out very low confidence patterns
    patterns = [p for p in patterns if p.confidence > 0.1]
    patterns = apply_profile_pattern_suppression(patterns, profile_registry)
    patterns = _dedupe_patterns(patterns)
    patterns.sort(key=lambda p: -p.confidence)

    active_profile_packs = _active_profile_pack_names(patterns)

    # ── Build function cards ─────────────────────────────────
    function_cards = []
    for func in slice_result.functions:
        card = build_function_card(
            func,
            abi_by_selector.get(func.selector),
            sim_result,
            storage_layout,
            name_by_selector,
            profile_registry,
            function_card_type=FunctionCard,
            active_profile_packs=active_profile_packs,
        )
        function_cards.append(card)

    # ── Standards detection with confidence ───────────────────
    standards = detect_standards_scored(slice_result, name_by_selector)

    # ── Risk summary ─────────────────────────────────────────
    risk_summary = build_risk_summary(patterns, function_cards)

    # ── Contract family ──────────────────────────────────────
    high_confidence = _unique_in_order([p.pattern_name for p in patterns if p.confidence >= 0.6])
    contract_family = " + ".join(high_confidence) if high_confidence else "Unknown"

    return SemanticAnalysis(
        contract_family=contract_family,
        patterns=patterns,
        function_cards=function_cards,
        standards=standards,
        risk_summary=risk_summary,
    )


# ── Pattern Detectors ────────────────────────────────────────────


def _unique_in_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        unique.append(value)
    return unique


def _dedupe_patterns(patterns: list[PatternCard]) -> list[PatternCard]:
    by_name: dict[str, PatternCard] = {}
    for pattern in patterns:
        existing = by_name.get(pattern.pattern_name)
        if existing is None or pattern.confidence > existing.confidence:
            by_name[pattern.pattern_name] = pattern
            continue
        if pattern.confidence == existing.confidence:
            existing.evidence = _unique_in_order(list(existing.evidence) + list(pattern.evidence))
    return list(by_name.values())


def _active_profile_pack_names(patterns: list[PatternCard], minimum_confidence: float = 0.7) -> set[str]:
    active: set[str] = set()
    for pattern in patterns:
        profile = pattern.details.get("profile")
        if not profile:
            continue
        if pattern.confidence >= minimum_confidence:
            active.add(profile)
    return active

def _detect_ownable(
    slices: FunctionSliceResult,
    names: dict[str, str],
    sim: SimulationResult,
    storage: StorageLayoutResult,
) -> PatternCard:
    evidence = []
    confidence = 0.0
    protected_functions = []

    # Check for owner() getter
    has_owner = any("owner()" in (names.get(f.selector, "") or "") for f in slices.functions)
    if has_owner:
        evidence.append("owner() public getter exists")
        confidence += 0.3

    # Check for transferOwnership
    has_transfer = any("transferOwnership" in (names.get(f.selector, "") or "") for f in slices.functions)
    if has_transfer:
        evidence.append("transferOwnership(address) exists")
        confidence += 0.2

    # Check for msg.sender == owner guard pattern
    owner_guard_count = 0
    for func in slices.functions:
        func_name = names.get(func.selector, func.selector)
        for bid in func.body_blocks:
            trace = sim.traces.get(bid)
            if trace and trace.branch_condition:
                cond = str(trace.branch_condition)
                if "msg.sender" in cond and "storage[0x00]" in cond:
                    owner_guard_count += 1
                    short_name = func_name.split("(")[0] if "(" in func_name else func_name
                    protected_functions.append(short_name)
                    break

    if owner_guard_count > 0:
        evidence.append(f"msg.sender == owner guard found in {owner_guard_count} functions")
        confidence += min(0.1 * owner_guard_count, 0.4)

    # Check slot 0 for address
    if 0 in storage.slots:
        slot0 = storage.slots[0]
        if slot0.kind == "packed" or slot0.value_type == "address":
            evidence.append("slot 0 contains address (likely owner)")
            confidence += 0.1

    confidence = min(confidence, 1.0)

    return PatternCard(
        pattern_name="Ownable",
        confidence=confidence,
        evidence=evidence,
        details={
            "owner_slot": 0,
            "protected_functions": list(set(protected_functions)),
        },
    )


def _detect_pausable(
    slices: FunctionSliceResult,
    names: dict[str, str],
    sim: SimulationResult,
) -> PatternCard:
    evidence = []
    confidence = 0.0
    guarded_methods = []

    has_pause = any("pause()" == names.get(f.selector, "") for f in slices.functions)
    has_unpause = any("unpause()" == names.get(f.selector, "") for f in slices.functions)
    has_paused = any("paused()" == names.get(f.selector, "") for f in slices.functions)

    if has_pause:
        evidence.append("pause() function exists")
        confidence += 0.3
    if has_unpause:
        evidence.append("unpause() function exists")
        confidence += 0.2
    if has_paused:
        evidence.append("paused() getter exists")
        confidence += 0.2

    # Check for paused check in other functions (whenNotPaused modifier)
    for func in slices.functions:
        func_name = names.get(func.selector, func.selector)
        if func_name in ("pause()", "unpause()", "paused()"):
            continue
        for bid in func.body_blocks:
            trace = sim.traces.get(bid)
            if trace and trace.branch_condition:
                cond = str(trace.branch_condition)
                # Pattern: !(storage[0x00] >> N & 0xff) i.e. paused check
                if "storage[0x00]" in cond and "0xff" in cond:
                    short_name = func_name.split("(")[0] if "(" in func_name else func_name
                    guarded_methods.append(short_name)
                    break

    if guarded_methods:
        evidence.append(f"whenNotPaused guard in: {', '.join(set(guarded_methods))}")
        confidence += 0.3

    confidence = min(confidence, 1.0)

    return PatternCard(
        pattern_name="Pausable",
        confidence=confidence,
        evidence=evidence,
        details={
            "paused_slot": 0,
            "guarded_methods": list(set(guarded_methods)),
        },
    )


def _detect_erc20(
    slices: FunctionSliceResult,
    names: dict[str, str],
    abis: dict[str, RecoveredABI],
) -> PatternCard:
    evidence = []
    confidence = 0.0

    required = {
        "transfer": "transfer(address,uint256)",
        "transferFrom": "transferFrom(address,address,uint256)",
        "approve": "approve(address,uint256)",
        "allowance": "allowance(address,address)",
        "balanceOf": "balanceOf(address)",
        "totalSupply": "totalSupply()",
    }
    optional = {
        "name": "name()",
        "symbol": "symbol()",
        "decimals": "decimals()",
    }

    matched_required = []
    matched_optional = []
    missing_required = []

    func_names = set()
    for f in slices.functions:
        n = names.get(f.selector, "")
        if n:
            func_names.add(n)

    for key, sig in required.items():
        if sig in func_names:
            matched_required.append(key)
            evidence.append(f"{sig} present")
        else:
            # Check for partial match (name without params)
            if any(key + "(" in n for n in func_names):
                matched_required.append(key)
                evidence.append(f"{key}(...) present (param mismatch)")
            else:
                missing_required.append(key)

    for key, sig in optional.items():
        if sig in func_names:
            matched_optional.append(key)

    if len(matched_required) == len(required):
        confidence = 0.95
        evidence.append("all 6 required ERC-20 functions present")
    elif len(matched_required) >= 4:
        confidence = 0.7
    elif len(matched_required) >= 3:
        confidence = 0.4
    else:
        confidence = 0.1 * len(matched_required)

    if matched_optional:
        evidence.append(f"optional: {', '.join(matched_optional)}")
        confidence = min(confidence + 0.05 * len(matched_optional), 1.0)

    return PatternCard(
        pattern_name="ERC20",
        confidence=confidence,
        evidence=evidence,
        details={
            "matched_required": matched_required,
            "missing_required": missing_required,
            "matched_optional": matched_optional,
        },
    )


def _detect_erc2612_permit(
    slices: FunctionSliceResult,
    names: dict[str, str],
) -> PatternCard:
    func_names = {names.get(f.selector, "") for f in slices.functions if names.get(f.selector, "")}
    required = {
        "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
        "DOMAIN_SEPARATOR()",
        "nonces(address)",
    }
    matched = sorted(required & func_names)
    confidence = len(matched) / len(required)
    evidence = [f"{sig} present" for sig in matched]
    if len(matched) == len(required):
        confidence = 0.9
        evidence.append("permit + domain separator + nonce getter present")
    if "PERMIT_TYPEHASH()" in func_names:
        confidence = min(confidence + 0.05, 1.0)
        evidence.append("PERMIT_TYPEHASH constant getter present")
    return PatternCard(
        pattern_name="EIP-2612 Permit",
        confidence=confidence,
        evidence=evidence,
        details={"matched": matched},
    )


def _detect_erc721(
    slices: FunctionSliceResult,
    names: dict[str, str],
    abis: dict[str, RecoveredABI],
) -> PatternCard:
    """
    ERC-721 detection with STRICT requirements.
    Must have ownerOf(uint256), safeTransferFrom, and tokenId-based model.
    Sharing name/symbol/balanceOf with ERC-20 is NOT sufficient evidence.
    """
    evidence = []
    confidence = 0.0

    func_names = set()
    for f in slices.functions:
        n = names.get(f.selector, "")
        if n:
            func_names.add(n)

    # STRICT required: these distinguish ERC-721 from ERC-20
    strict_required = [
        "ownerOf(uint256)",
        "safeTransferFrom(address,address,uint256)",
        "safeTransferFrom(address,address,uint256,bytes)",
    ]

    strict_count = sum(1 for sig in strict_required if sig in func_names)

    if strict_count >= 2:
        confidence = 0.8
        evidence.append("ownerOf + safeTransferFrom present → likely ERC-721")
    elif strict_count == 1:
        confidence = 0.4
        evidence.append("partial ERC-721 specific functions")
    else:
        # Check for name/symbol overlap but note it's NOT ERC-721 evidence
        shared = [n for n in func_names if n in ("name()", "symbol()", "balanceOf(address)")]
        if shared:
            evidence.append(f"name/symbol/balanceOf overlap only — NOT ERC-721 evidence")
            evidence.append("missing: ownerOf(uint256), safeTransferFrom(...)")
            confidence = 0.1  # Very low — shared names are not evidence

    # Check for supportsInterface (ERC-165)
    if "supportsInterface(bytes4)" in func_names:
        confidence += 0.1
        evidence.append("supportsInterface(bytes4) present → ERC-165 compatible")

    confidence = min(confidence, 1.0)

    return PatternCard(
        pattern_name="ERC721",
        confidence=confidence,
        evidence=evidence,
        details={},
    )


def _detect_blacklist(
    slices: FunctionSliceResult,
    names: dict[str, str],
    sim: SimulationResult,
) -> PatternCard:
    evidence = []
    confidence = 0.0

    has_add = any("addBlackList" in (names.get(f.selector, "") or "") for f in slices.functions)
    has_remove = any("removeBlackList" in (names.get(f.selector, "") or "") for f in slices.functions)
    has_destroy = any("destroyBlackFunds" in (names.get(f.selector, "") or "") for f in slices.functions)
    has_status = any("getBlackListStatus" in (names.get(f.selector, "") or "") for f in slices.functions)
    has_is_listed = any("isBlackListed" in (names.get(f.selector, "") or "") for f in slices.functions)

    if has_add:
        evidence.append("addBlackList(address) exists")
        confidence += 0.3
    if has_remove:
        evidence.append("removeBlackList(address) exists")
        confidence += 0.2
    if has_destroy:
        evidence.append("destroyBlackFunds(address) exists")
        confidence += 0.3
    if has_status:
        evidence.append("getBlackListStatus(address) getter exists")
        confidence += 0.1
    if has_is_listed:
        evidence.append("isBlackListed(address) mapping getter exists")
        confidence += 0.1

    confidence = min(confidence, 1.0)

    risk = []
    if has_destroy:
        risk = ["owner can destroy blacklisted user's balance"]
    if has_add:
        risk.append("owner can freeze any address")

    return PatternCard(
        pattern_name="Blacklist",
        confidence=confidence,
        evidence=evidence,
        details={
            "powers": {
                "add": has_add,
                "remove": has_remove,
                "destroy_funds": has_destroy,
            },
            "risk": risk,
        },
    )


def _detect_fee_token(
    slices: FunctionSliceResult,
    names: dict[str, str],
    storage: StorageLayoutResult,
) -> PatternCard:
    evidence = []
    confidence = 0.0

    has_basis = any("basisPointsRate" in (names.get(f.selector, "") or "") for f in slices.functions)
    has_max_fee = any("maximumFee" in (names.get(f.selector, "") or "") for f in slices.functions)
    has_set_params = any("setParams" in (names.get(f.selector, "") or "") for f in slices.functions)

    if has_basis:
        evidence.append("basisPointsRate() getter exists")
        confidence += 0.35
    if has_max_fee:
        evidence.append("maximumFee() getter exists")
        confidence += 0.25
    if has_set_params:
        evidence.append("setParams(uint256,uint256) exists → fee configuration")
        confidence += 0.3

    # Check storage layout for fee-related slots
    for slot_num, info in storage.slots.items():
        if info.name in ("basisPointsRate", "maximumFee"):
            evidence.append(f"storage slot {slot_num} = {info.name}")
            confidence += 0.1

    confidence = min(confidence, 1.0)

    return PatternCard(
        pattern_name="FeeToken",
        confidence=confidence,
        evidence=evidence,
        details={},
    )


def _detect_legacy_upgrade(
    slices: FunctionSliceResult,
    names: dict[str, str],
    sim: SimulationResult,
) -> PatternCard:
    evidence = []
    confidence = 0.0

    has_deprecate = any("deprecate" in (names.get(f.selector, "") or "").lower() for f in slices.functions)
    has_deprecated = any("deprecated" in (names.get(f.selector, "") or "").lower() for f in slices.functions)
    has_upgraded_addr = any("upgradedAddress" in (names.get(f.selector, "") or "") for f in slices.functions)

    if has_deprecate:
        evidence.append("deprecate(address) function exists")
        confidence += 0.35
    if has_deprecated:
        evidence.append("deprecated() getter exists")
        confidence += 0.2
    if has_upgraded_addr:
        evidence.append("upgradedAddress() getter exists")
        confidence += 0.25

    # Check for external call forwarding patterns in transfer/approve/etc
    forwarding_functions = []
    for func in slices.functions:
        func_name = names.get(func.selector, "")
        if not func_name:
            continue
        for bid in func.body_blocks:
            trace = sim.traces.get(bid)
            if trace:
                for op in trace.operations:
                    if "call" in op.description.lower() and "legacy" in op.description.lower():
                        short = func_name.split("(")[0]
                        forwarding_functions.append(short)
                        break
                # Also check for extcodesize checks (used before forwarding)
                for ann_off, ann_text in trace.stack_annotations.items():
                    if "extcodesize" in ann_text and "storage[0x0a]" in ann_text:
                        short = func_name.split("(")[0] if "(" in func_name else func_name
                        if short not in forwarding_functions:
                            forwarding_functions.append(short)
                        confidence += 0.05
                        break

    if forwarding_functions:
        evidence.append(f"legacy forwarding in: {', '.join(set(forwarding_functions))}")
        confidence += 0.2

    confidence = min(confidence, 1.0)

    return PatternCard(
        pattern_name="LegacyUpgradeForwarder",
        confidence=confidence,
        evidence=evidence,
        details={
            "forwarding_functions": list(set(forwarding_functions)),
        },
    )


def _detect_mint_burn(
    slices: FunctionSliceResult,
    names: dict[str, str],
) -> PatternCard:
    evidence = []
    confidence = 0.0

    has_issue = any("issue" in (names.get(f.selector, "") or "").lower() for f in slices.functions)
    has_redeem = any("redeem" in (names.get(f.selector, "") or "").lower() for f in slices.functions)
    has_mint = any("mint" in (names.get(f.selector, "") or "").lower() for f in slices.functions)
    has_burn = any("burn" in (names.get(f.selector, "") or "").lower() for f in slices.functions)

    if has_issue:
        evidence.append("issue(uint256) → mint-like function")
        confidence += 0.4
    if has_redeem:
        evidence.append("redeem(uint256) → burn-like function")
        confidence += 0.4
    if has_mint:
        evidence.append("mint function exists")
        confidence += 0.3
    if has_burn:
        evidence.append("burn function exists")
        confidence += 0.3

    confidence = min(confidence, 1.0)

    return PatternCard(
        pattern_name="MintBurn",
        confidence=confidence,
        evidence=evidence,
        details={"has_issue": has_issue, "has_redeem": has_redeem},
    )

