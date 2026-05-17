"""
Storage layout recovery engine.

Converts raw storage access patterns (keccak256-derived slots, packed
fields, dynamic strings) into a named storage layout matching what
the original Solidity source would have declared.

Key insight: Solidity uses predictable formulas:
  - Simple slot:     storage[N]
  - Mapping:         storage[keccak256(key . slot)]
  - Nested mapping:  storage[keccak256(key2 . keccak256(key1 . slot))]
  - Dynamic array:   storage[keccak256(slot) + index]
  - String/bytes:    slot holds length; if long, data at keccak256(slot)
  - Packed fields:   AND/SHR/SHL masks on a single slot
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from .stack_sim import SimulationResult, BlockTrace, StorageOp
from .blocks import BlockAnalysis
from .function_slicer import FunctionSliceResult
from .profile_packs import ProfileRegistry


@dataclass
class StorageSlotInfo:
    """Recovered information about a single storage slot."""
    slot: int
    kind: str                   # "value", "mapping", "nested_mapping", "dynamic_array", "string", "packed"
    name: Optional[str] = None  # inferred from public getter
    value_type: Optional[str] = None  # "uint256", "address", "bool", "string"
    key_types: list[str] = field(default_factory=list)  # for mappings
    packing: list[dict] = field(default_factory=list)    # for packed: [{offset, width, type, name}]
    confidence: float = 0.5
    evidence: list[str] = field(default_factory=list)
    accessed_by: list[str] = field(default_factory=list)  # selectors that access this slot


@dataclass
class StorageLayoutResult:
    """Complete recovered storage layout."""
    slots: dict[int, StorageSlotInfo]          # slot number → info
    mapping_accesses: list[dict]                # detailed mapping access records
    unresolved_accesses: list[dict]             # accesses we couldn't classify


# Map from resolved getter name to slot naming info
_GETTER_TO_SLOT = {
    "balances(address)": {"name": "balances", "kind": "mapping", "key_types": ["address"], "value_type": "uint256"},
    "allowed(address,address)": {"name": "allowed", "kind": "nested_mapping", "key_types": ["address", "address"], "value_type": "uint256"},
    "isBlackListed(address)": {"name": "isBlackListed", "kind": "mapping", "key_types": ["address"], "value_type": "bool"},
    "balanceOf(address)": {"name": "balanceOf", "kind": "mapping", "key_types": ["address"], "value_type": "uint256"},
    "allowance(address,address)": {"name": "allowance", "kind": "nested_mapping", "key_types": ["address", "address"], "value_type": "uint256"},
    "getBlackListStatus(address)": {"name": "isBlackListed", "kind": "mapping", "key_types": ["address"], "value_type": "bool"},
    "owner()": {"name": "owner", "kind": "packed", "value_type": "address"},
    "paused()": {"name": "paused", "kind": "packed", "value_type": "bool"},
    "name()": {"name": "name", "kind": "string", "value_type": "string"},
    "symbol()": {"name": "symbol", "kind": "string", "value_type": "string"},
    "decimals()": {"name": "decimals", "kind": "value", "value_type": "uint256"},
    "totalSupply()": {"name": "_totalSupply", "kind": "value", "value_type": "uint256"},
    "_totalSupply()": {"name": "_totalSupply", "kind": "value", "value_type": "uint256"},
    "deprecated()": {"name": "deprecated", "kind": "packed", "value_type": "bool"},
    "upgradedAddress()": {"name": "upgradedAddress", "kind": "packed", "value_type": "address"},
    "basisPointsRate()": {"name": "basisPointsRate", "kind": "value", "value_type": "uint256"},
    "maximumFee()": {"name": "maximumFee", "kind": "value", "value_type": "uint256"},
    "MAX_UINT()": {"name": "MAX_UINT", "kind": "value", "value_type": "uint256"},
    "DOMAIN_SEPARATOR()": {"name": "DOMAIN_SEPARATOR", "kind": "value", "value_type": "bytes32"},
    "nonces(address)": {"name": "nonces", "kind": "mapping", "key_types": ["address"], "value_type": "uint256"},
    "factory()": {"name": "factory", "kind": "value", "value_type": "address"},
    "token0()": {"name": "token0", "kind": "value", "value_type": "address"},
    "token1()": {"name": "token1", "kind": "value", "value_type": "address"},
    "price0CumulativeLast()": {"name": "price0CumulativeLast", "kind": "value", "value_type": "uint256"},
    "price1CumulativeLast()": {"name": "price1CumulativeLast", "kind": "value", "value_type": "uint256"},
    "kLast()": {"name": "kLast", "kind": "value", "value_type": "uint256"},
}


def recover_storage_layout(
    block_analysis: BlockAnalysis,
    sim_result: SimulationResult,
    slice_result: Optional[FunctionSliceResult] = None,
    resolved_names: dict[str, str] = None,
    profile_registry: ProfileRegistry | None = None,
) -> StorageLayoutResult:
    """
    Recover the storage layout from bytecode analysis.
    
    Args:
        block_analysis: Basic block analysis
        sim_result: Stack simulation results  
        slice_result: Function slicing results (optional, for function attribution)
        resolved_names: Map of selector → resolved name (for getter-based naming)
    """
    if resolved_names is None:
        resolved_names = {}

    slots: dict[int, StorageSlotInfo] = {}
    mapping_accesses: list[dict] = []
    unresolved: list[dict] = []

    # ── Step 1: Collect all storage operations ────────────────
    all_storage_ops: list[tuple[int, StorageOp]] = []  # (block_id, op)
    
    for bid, trace in sim_result.traces.items():
        for op in trace.storage_ops:
            all_storage_ops.append((bid, op))

    # ── Step 2: Classify each storage access ─────────────────
    for bid, op in all_storage_ops:
        slot_str = repr(op.slot)
        
        # Determine which function this block belongs to
        owning_selector = None
        if slice_result:
            owning_selector = slice_result.block_to_function.get(bid)

        # Direct constant slot access: storage[N]
        if op.slot.kind == "const" and isinstance(op.slot.value, int):
            slot_num = op.slot.value
            _ensure_slot(slots, slot_num)
            if owning_selector:
                if owning_selector not in slots[slot_num].accessed_by:
                    slots[slot_num].accessed_by.append(owning_selector)
            continue

        # Keccak-derived access (mapping pattern)
        if "keccak256" in slot_str:
            record = {
                "block": bid,
                "slot_expr": slot_str,
                "op_type": op.op_type,
                "owning_selector": owning_selector,
            }
            mapping_accesses.append(record)
            
            # Try to extract base slot from the keccak pattern
            base_slot = _extract_mapping_base_slot(slot_str)
            if base_slot is not None:
                _ensure_slot(slots, base_slot)
                if slots[base_slot].kind == "value":
                    slots[base_slot].kind = "mapping"
                    slots[base_slot].evidence.append(f"keccak-derived access in block {bid}")
                if owning_selector:
                    if owning_selector not in slots[base_slot].accessed_by:
                        slots[base_slot].accessed_by.append(owning_selector)
            else:
                unresolved.append(record)
            continue

        # Expression-based slot (computed at runtime)
        unresolved.append({
            "block": bid,
            "slot_expr": slot_str,
            "op_type": op.op_type,
            "owning_selector": owning_selector,
        })

    # ── Step 3: Infer names from resolved getters ─────────────
    if slice_result:
        for func in slice_result.functions:
            getter_name = func.name
            if getter_name and getter_name in _GETTER_TO_SLOT:
                info = _GETTER_TO_SLOT[getter_name]
                # Find which slot this getter accesses
                for bid in func.body_blocks:
                    trace = sim_result.traces.get(bid)
                    if trace:
                        for op in trace.storage_ops:
                            if op.op_type == "read" and op.slot.kind == "const":
                                slot_num = op.slot.value
                                _ensure_slot(slots, slot_num)
                                slot_info = slots[slot_num]
                                
                                # A mapping getter doesn't read its base slot as a constant;
                                # if it reads a constant slot, it's likely a guard (like 'paused' or 'deprecated').
                                if info.get("kind") in ("mapping", "nested_mapping"):
                                    continue
                                
                                if info.get("name"):
                                    if info.get("kind") == "packed":
                                        if not slot_info.packing:
                                            slot_info.packing = []
                                        # Avoid adding duplicate
                                        if not any(p.get("name") == info["name"] for p in slot_info.packing):
                                            slot_info.packing.append({
                                                "name": info["name"], 
                                                "type": info.get("value_type", "unknown")
                                            })
                                        if not slot_info.name or not slot_info.name.endswith("_packed"):
                                            slot_info.name = info["name"] + "_packed"
                                    else:
                                        if not slot_info.name or not slot_info.name.endswith("_packed"):
                                            slot_info.name = info["name"]
                                
                                if info.get("kind") and slot_info.kind != "packed":
                                    slot_info.kind = info["kind"]
                                if info.get("value_type") and not slot_info.value_type:
                                    slot_info.value_type = info["value_type"]
                                if info.get("key_types") and not slot_info.key_types:
                                    slot_info.key_types = info["key_types"]
                                
                                slot_info.confidence = max(slot_info.confidence, 0.9)
                                slot_info.evidence.append(f"getter {getter_name} reads slot {slot_num}")

    # ── Step 4: Apply protocol-specific getter anchors ────────
    _apply_profile_getter_anchors(slots, resolved_names, profile_registry)

    # ── Step 5: Detect packed slots ───────────────────────────
    _detect_packed_slots(slots, sim_result)

    # ── Step 6: Detect string slots ───────────────────────────
    _detect_string_slots(slots, sim_result)

    # ── Step 7: Apply heuristic naming for remaining slots ────
    _apply_heuristic_names(slots, resolved_names)

    return StorageLayoutResult(
        slots=slots,
        mapping_accesses=mapping_accesses,
        unresolved_accesses=unresolved,
    )


def _apply_profile_getter_anchors(
    slots: dict[int, StorageSlotInfo],
    resolved_names: dict[str, str],
    profile_registry: ProfileRegistry | None,
):
    """Anchor storage layouts from optional data profiles."""
    names = set(resolved_names.values())
    if profile_registry:
        for pack in profile_registry.packs:
            for anchor_group in pack.storage_anchors:
                required = set(anchor_group.get("requires_selectors", []))
                if required and not required.issubset(names):
                    continue
                for row in anchor_group.get("slots", []):
                    slot_num = int(row["slot"])
                    _ensure_slot(slots, slot_num)
                    info = slots[slot_num]
                    info.name = row.get("name")
                    info.kind = row.get("kind", info.kind)
                    info.value_type = row.get("value_type")
                    info.key_types = list(row.get("key_types", []))
                    info.packing = list(row.get("packing", []))
                    info.confidence = max(info.confidence, float(row.get("confidence", 0.9)))
                    info.evidence.append(f"profile anchor: {pack.name}")

    # Generic ERC20 layout used by many simple contracts. Only fill missing
    # names so custom evidence can override it.
    if {"totalSupply()", "balanceOf(address)", "allowance(address,address)"}.issubset(names):
        generic = {
            0: ("totalSupply", "value", "uint256", []),
            1: ("balanceOf", "mapping", "uint256", ["address"]),
            2: ("allowance", "nested_mapping", "uint256", ["address", "address"]),
        }
        for slot_num, (name, kind, value_type, key_types) in generic.items():
            _ensure_slot(slots, slot_num)
            info = slots[slot_num]
            if not info.name:
                info.name = name
                info.kind = kind
                info.value_type = value_type
                info.key_types = list(key_types)
                info.confidence = max(info.confidence, 0.8)
                info.evidence.append("ERC20 getter anchor")


def _ensure_slot(slots: dict[int, StorageSlotInfo], slot_num: int):
    """Ensure a slot entry exists."""
    if slot_num not in slots:
        slots[slot_num] = StorageSlotInfo(slot=slot_num, kind="value")


def _extract_mapping_base_slot(slot_expr: str) -> Optional[int]:
    """
    Try to extract the base slot from a keccak expression.
    
    Patterns:
    - keccak256(mem[0x40:0x40+0x00]) where memory setup shows slot at 0x20
      → this is the standard Solidity mapping pattern
    - Direct slot reference in memory operations
    """
    import re

    # Look for memory references that contain slot numbers
    # Pattern: memory[0xNN] = 0x20 → keccak is computing mapping at slot=value_at_0xNN
    # This is heuristic; the real slot is the 2nd word stored before SHA3
    
    # Try to find explicit slot numbers in the expression
    # keccak256(mem[X:X+0x40]) typically has slot at mem[X+0x20]
    
    # For now, use the evidence from the surrounding memory operations
    # The full recovery happens when we cross-reference with getter analysis
    
    return None


def _detect_packed_slots(slots: dict[int, StorageSlotInfo], sim_result: SimulationResult):
    """
    Detect packed storage slots.
    
    Solidity packs small types into single slots:
    - address (20 bytes) + bool (1 byte) = packed in one slot
    - Detection: AND with masks like 0xff (bool) or 0xfff...fff (address)
      followed by SHR/SHL on the same slot
    """
    for bid, trace in sim_result.traces.items():
        for ann_off, ann_text in trace.stack_annotations.items():
            # Pattern: (0x00 / storage[N]) & 0xff → packed bool at high bytes
            if "storage[" in ann_text and "& 0xff" in ann_text:
                import re
                m = re.search(r'storage\[0x([0-9a-fA-F]+)\]', ann_text)
                if m:
                    try:
                        slot_num = int(m.group(1), 16)
                        _ensure_slot(slots, slot_num)
                        if slots[slot_num].kind == "value" and slots[slot_num].value_type == "address":
                            slots[slot_num].evidence.append(
                                f"address getter mask (& 0xff) in block {bid}"
                            )
                        elif slots[slot_num].kind == "value":
                            slots[slot_num].kind = "packed"
                            slots[slot_num].evidence.append(
                                f"byte-masked access (& 0xff) in block {bid}"
                            )
                    except ValueError:
                        pass

            # Pattern: storage[N] & 0xfff...fff → packed address
            if "storage[" in ann_text and "ffffffffffffffffffffffffffffffffffffffff" in ann_text:
                import re
                m = re.search(r'storage\[0x([0-9a-fA-F]+)\]', ann_text)
                if m:
                    try:
                        slot_num = int(m.group(1), 16)
                        _ensure_slot(slots, slot_num)
                        if slots[slot_num].kind == "value" and slots[slot_num].value_type == "address":
                            slots[slot_num].evidence.append(
                                f"address mask in block {bid}"
                            )
                        elif slots[slot_num].kind in ("value", "packed"):
                            slots[slot_num].kind = "packed"
                            if not slots[slot_num].packing:
                                slots[slot_num].packing = [
                                    {"offset": 0, "width": 160, "type": "address"},
                                ]
                            slots[slot_num].evidence.append(
                                f"address-masked access in block {bid}"
                            )
                    except ValueError:
                        pass


def _detect_string_slots(slots: dict[int, StorageSlotInfo], sim_result: SimulationResult):
    """
    Detect dynamic string storage slots.
    
    Solidity strings:
    - Short strings (< 32 bytes): stored inline in the slot, low bit = 0
    - Long strings: slot stores length*2+1, data at keccak256(slot)
    - Detection: bit-manipulation patterns like `storage[N] & 0x01`
    """
    for bid, trace in sim_result.traces.items():
        for ann_off, ann_text in trace.stack_annotations.items():
            # Pattern: storage[N] & 0x01 → checking string length encoding
            if "storage[" in ann_text and "& 0x01" in ann_text:
                import re
                m = re.search(r'storage\[0x([0-9a-fA-F]+)\]', ann_text)
                if m:
                    try:
                        slot_num = int(m.group(1), 16)
                        _ensure_slot(slots, slot_num)
                        # Strings are typically at higher slots and show this bit pattern
                        if slot_num >= 7:  # heuristic: strings usually in later slots
                            slots[slot_num].kind = "string"
                            slots[slot_num].value_type = "string"
                            slots[slot_num].evidence.append(
                                f"bit-0 check pattern (string length) in block {bid}"
                            )
                    except ValueError:
                        pass


def _apply_heuristic_names(
    slots: dict[int, StorageSlotInfo],
    resolved_names: dict[str, str],
):
    """Apply heuristic naming for slots that weren't named by getters."""
    
    # Well-known slot assignments for common contract patterns
    # These are based on Solidity's storage layout rules
    known_layouts = {
        # Ownable pattern: slot 0 = owner (packed with other bools)
        0: {"fallback_name": "owner_slot", "fallback_type": "address+packed"},
        1: {"fallback_name": "_totalSupply", "fallback_type": "uint256"},
    }

    for slot_num, slot_info in slots.items():
        if slot_info.name is not None:
            continue  # already named

        if slot_num in known_layouts:
            layout = known_layouts[slot_num]
            if slot_info.kind == "packed" and slot_num == 0:
                slot_info.name = "owner_slot"
                slot_info.packing = [
                    {"offset": 0, "width": 160, "type": "address", "name": "owner"},
                    {"offset": 160, "width": 8, "type": "bool", "name": "paused"},
                ]
                slot_info.confidence = 0.7
                slot_info.evidence.append("slot 0 with packed access → likely Ownable+Pausable")


def format_storage_layout(layout: StorageLayoutResult) -> str:
    """Format the storage layout as a human-readable string."""
    lines = []
    
    for slot_num in sorted(layout.slots.keys()):
        info = layout.slots[slot_num]
        name = info.name or f"slot_{slot_num}"
        
        if info.kind == "packed" and info.packing:
            fields = []
            for p in info.packing:
                pname = p.get("name", "?")
                ptype = p.get("type", "?")
                fields.append(f"{pname} ({ptype})")
            fields_str = " + ".join(fields)
            lines.append(f"  slot {slot_num}:  {fields_str}  — packed")
        elif info.kind == "mapping":
            keys = ", ".join(info.key_types) if info.key_types else "?"
            vtype = info.value_type or "uint256"
            lines.append(f"  slot {slot_num}:  {name}: mapping({keys} => {vtype})")
        elif info.kind == "nested_mapping":
            if len(info.key_types) >= 2:
                lines.append(
                    f"  slot {slot_num}:  {name}: mapping({info.key_types[0]} "
                    f"=> mapping({info.key_types[1]} => {info.value_type or 'uint256'}))"
                )
            else:
                lines.append(f"  slot {slot_num}:  {name}: nested mapping")
        elif info.kind == "string":
            lines.append(f"  slot {slot_num}:  {name} (string)")
        else:
            vtype = info.value_type or "uint256"
            lines.append(f"  slot {slot_num}:  {name} ({vtype})")

        # Show confidence
        if info.confidence < 0.9:
            lines[-1] += f"  [confidence: {info.confidence:.0%}]"

    return "\n".join(lines)
