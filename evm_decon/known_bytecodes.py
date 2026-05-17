"""
Known bytecode pattern fingerprinting.

Detects well-known contract patterns from raw bytecode constants and opcode
sequences. This prevents false positives by identifying patterns like ERC-1967
proxy contracts, OpenZeppelin's TransparentUpgradeableProxy, UUPS proxies,
reentrancy guards, and initializer patterns at the bytecode level.

The module emits contract-level tags that downstream rules can use in
counter-evidence and suppression logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ── ERC-1967 well-known storage slot constants ──────────────────────────────
# These are keccak256 hashes of standard strings minus 1.
# Their presence in bytecode is near-certain evidence of a proxy pattern.

ERC1967_IMPLEMENTATION_SLOT = "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
ERC1967_ADMIN_SLOT = "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
ERC1967_BEACON_SLOT = "a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
ERC1967_ROLLBACK_SLOT = "4910fdfa16fed3260ed0e7147f7cc6da11a60208b5b9406d12a635614ffd9143"

# ERC-1167 minimal proxy clone prefix (EIP-1167)
ERC1167_PREFIX = "363d3d373d3d3d363d73"
ERC1167_SUFFIX = "5af43d82803e903d91602b57fd5bf3"

# Vyper minimal proxy pattern (alternative clone)
VYPER_PROXY_PREFIX = "366000600037611000600036600073"

# UUPS proxiableUUID selector
UUPS_SELECTOR = "52d1902d"

# Well-known function selectors for proxy operations
UPGRADE_TO_SELECTOR = "3659cfe6"           # upgradeTo(address)
UPGRADE_TO_AND_CALL_SELECTOR = "4f1ef286"  # upgradeToAndCall(address,bytes)
CHANGE_ADMIN_SELECTOR = "8f283970"         # changeAdmin(address)
ADMIN_SELECTOR = "f851a440"               # admin()
IMPLEMENTATION_SELECTOR = "5c60da1b"       # implementation()

# ── Diamond Proxy (EIP-2535) selectors ──────────────────────────────────
DIAMOND_CUT_SELECTOR = "1f931c1c"          # diamondCut(...)
DIAMOND_FACETS_SELECTOR = "7a0ed627"       # facets()
DIAMOND_FACET_SELECTORS = "adfca15e"       # facetFunctionSelectors(address)
DIAMOND_FACET_ADDRESSES = "52ef6b2c"       # facetAddresses()
DIAMOND_FACET_ADDRESS = "cdffacc6"         # facetAddress(bytes4)

# ── Gnosis Safe Proxy selectors ─────────────────────────────────────────
SAFE_MASTER_COPY_SELECTOR = "a619486e"     # masterCopy()
SAFE_SINGLETON_SELECTOR = "736bf590"       # singleton() (newer Safe versions)
SAFE_SETUP_SELECTOR = "b63e800d"           # setup(...)

# ── Compound Unitroller selectors ───────────────────────────────────────
COMPTROLLER_IMPL_SELECTOR = "bb82aa5e"     # comptrollerImplementation()
SET_PENDING_IMPL_SELECTOR = "b71d1a0c"     # _setPendingImplementation(address)
ACCEPT_IMPL_SELECTOR = "e992a041"          # _acceptImplementation()

# ── EIP-897 DelegateProxy selectors ─────────────────────────────────────
PROXY_TYPE_SELECTOR = "4555d5c9"           # proxyType()

# OpenZeppelin's _ENTERED / _NOT_ENTERED reentrancy guard constants
OZ_REENTRANCY_NOT_ENTERED = "0000000000000000000000000000000000000000000000000000000000000001"
OZ_REENTRANCY_ENTERED = "0000000000000000000000000000000000000000000000000000000000000002"

# ── OpenZeppelin Ownable selectors ───────────────────────────────────────
OZ_OWNER_SELECTOR = "8da5cb5b"             # owner()
OZ_TRANSFER_OWNERSHIP_SELECTOR = "f2fde38b"  # transferOwnership(address)
OZ_RENOUNCE_OWNERSHIP_SELECTOR = "715018a6"  # renounceOwnership()

# ── OpenZeppelin Ownable2Step selectors ──────────────────────────────────
OZ_PENDING_OWNER_SELECTOR = "e30c3978"     # pendingOwner()
OZ_ACCEPT_OWNERSHIP_SELECTOR = "79ba5097"  # acceptOwnership()

# ── OpenZeppelin AccessControl selectors ─────────────────────────────────
OZ_HAS_ROLE_SELECTOR = "91d14854"          # hasRole(bytes32,address)
OZ_GRANT_ROLE_SELECTOR = "2f2ff15d"        # grantRole(bytes32,address)
OZ_REVOKE_ROLE_SELECTOR = "d547741f"       # revokeRole(bytes32,address)
OZ_RENOUNCE_ROLE_SELECTOR = "36568abe"     # renounceRole(bytes32,address)
OZ_GET_ROLE_ADMIN_SELECTOR = "248a9ca3"    # getRoleAdmin(bytes32)

# ── OpenZeppelin Pausable selectors ──────────────────────────────────────
OZ_PAUSED_SELECTOR = "5c975abb"            # paused()
OZ_PAUSE_SELECTOR = "8456cb59"             # pause()
OZ_UNPAUSE_SELECTOR = "3f4ba83a"           # unpause()

# ── OpenZeppelin TimelockController selectors ────────────────────────────
OZ_TIMELOCK_GET_MIN_DELAY = "f27a0c92"     # getMinDelay()
OZ_TIMELOCK_SCHEDULE = "01d5062a"          # schedule(address,uint256,bytes,bytes32,bytes32,uint256)
OZ_TIMELOCK_EXECUTE = "134008d3"           # execute(address,uint256,bytes,bytes32,bytes32)
OZ_TIMELOCK_CANCEL = "c4d252f5"            # cancel(bytes32)
OZ_TIMELOCK_IS_OPERATION = "31d50750"      # isOperation(bytes32)


@dataclass
class BytecodeFingerprint:
    """Result of bytecode pattern fingerprinting."""
    tags: list[str] = field(default_factory=list)
    proxy_type: str | None = None
    # ERC-1967 slots
    has_erc1967_impl_slot: bool = False
    has_erc1967_admin_slot: bool = False
    has_erc1967_beacon_slot: bool = False
    has_erc1967_rollback_slot: bool = False
    # Standard proxy patterns
    has_proxy_forwarding: bool = False
    has_uups: bool = False
    has_erc1167_clone: bool = False
    # Advanced proxy types
    has_diamond: bool = False
    has_gnosis_safe: bool = False
    has_compound_unitroller: bool = False
    has_eip897: bool = False
    has_slot0_proxy: bool = False
    has_vyper_proxy: bool = False
    # Guards
    has_reentrancy_guard_constants: bool = False
    has_initializer_pattern: bool = False
    has_two_step_upgrade: bool = False
    # OZ library patterns
    has_oz_ownable: bool = False
    has_oz_ownable2step: bool = False
    has_oz_access_control: bool = False
    has_oz_pausable: bool = False
    has_oz_timelock: bool = False
    has_safe_erc20: bool = False
    # Extracted data
    implementation_address: str | None = None  # For ERC-1167 clones
    detected_admin_check_offsets: list[int] = field(default_factory=list)
    proxy_selectors_found: list[str] = field(default_factory=list)
    diamond_loupe_selectors: int = 0  # Count of loupe selectors found
    details: dict[str, Any] = field(default_factory=dict)


def fingerprint_bytecode(bytecode_hex: str) -> BytecodeFingerprint:
    """Analyze raw bytecode hex for known patterns.

    Args:
        bytecode_hex: hex string of runtime bytecode (with or without 0x prefix)

    Returns:
        BytecodeFingerprint with detected patterns and tags
    """
    bc = bytecode_hex.lower().replace("0x", "").strip()
    result = BytecodeFingerprint()

    # ── ERC-1967 slot detection ─────────────────────────────────────────
    _detect_erc1967(bc, result)

    # ── Proxy forwarding pattern ────────────────────────────────────────
    _detect_proxy_forwarding(bc, result)

    # ── ERC-1167 minimal proxy clone ────────────────────────────────────
    _detect_erc1167(bc, result)

    # ── Vyper minimal proxy ─────────────────────────────────────────────
    _detect_vyper_proxy(bc, result)

    # ── UUPS pattern ────────────────────────────────────────────────────
    _detect_uups(bc, result)

    # ── Proxy selector detection ────────────────────────────────────────
    _detect_proxy_selectors(bc, result)

    # ── Diamond Proxy (EIP-2535) ────────────────────────────────────────
    _detect_diamond(bc, result)

    # ── Gnosis Safe Proxy ───────────────────────────────────────────────
    _detect_gnosis_safe(bc, result)

    # ── Compound Unitroller ─────────────────────────────────────────────
    _detect_compound_unitroller(bc, result)

    # ── EIP-897 DelegateProxy ───────────────────────────────────────────
    _detect_eip897(bc, result)

    # ── Generic slot-0 proxy ────────────────────────────────────────────
    _detect_slot0_proxy(bc, result)

    # ── OpenZeppelin library fingerprints ───────────────────────────────
    _detect_oz_ownable(bc, result)
    _detect_oz_ownable2step(bc, result)
    _detect_oz_access_control(bc, result)
    _detect_oz_pausable(bc, result)
    _detect_oz_timelock(bc, result)
    _detect_safe_erc20(bc, result)

    # ── Reentrancy guard constants ──────────────────────────────────────
    _detect_reentrancy_guard(bc, result)

    # ── Initializer pattern ─────────────────────────────────────────────
    _detect_initializer(bc, result)

    # ── Classify proxy type ─────────────────────────────────────────────
    _classify_proxy_type(result)

    # ── Build final tag list ────────────────────────────────────────────
    _build_tags(result)

    return result


def _detect_erc1967(bc: str, result: BytecodeFingerprint) -> None:
    """Detect ERC-1967 storage slot constants in bytecode."""
    if ERC1967_IMPLEMENTATION_SLOT in bc:
        result.has_erc1967_impl_slot = True
    if ERC1967_ADMIN_SLOT in bc:
        result.has_erc1967_admin_slot = True
    if ERC1967_BEACON_SLOT in bc:
        result.has_erc1967_beacon_slot = True
    if ERC1967_ROLLBACK_SLOT in bc:
        result.has_erc1967_rollback_slot = True


def _detect_proxy_forwarding(bc: str, result: BytecodeFingerprint) -> None:
    """Detect proxy forwarding pattern: CALLDATACOPY + DELEGATECALL + RETURNDATACOPY.

    The canonical OZ proxy assembly does:
      calldatacopy(0, 0, calldatasize())
      let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
      returndatacopy(0, 0, returndatasize())
      switch result
      case 0 { revert(0, returndatasize()) }
      default { return(0, returndatasize()) }

    In bytecode, this is:
      CALLDATASIZE CALLDATACOPY ... DELEGATECALL ... RETURNDATASIZE RETURNDATACOPY
      ... ISZERO ... REVERT ... RETURN
    """
    # Opcodes:
    # CALLDATASIZE = 36, CALLDATACOPY = 37
    # DELEGATECALL = f4
    # RETURNDATASIZE = 3d, RETURNDATACOPY = 3e
    # ISZERO = 15
    # REVERT = fd, RETURN = f3

    has_calldatacopy = "37" in bc  # CALLDATACOPY
    has_delegatecall = "f4" in bc  # DELEGATECALL
    has_returndatacopy = "3e" in bc  # RETURNDATACOPY

    if has_calldatacopy and has_delegatecall and has_returndatacopy:
        # Look for the full proxy forwarding sequence
        # Find DELEGATECALL, then check that RETURNDATACOPY follows within ~30 bytes
        dc_pos = bc.find("f4")
        while dc_pos != -1:
            # Check if RETURNDATACOPY (3e) follows within a reasonable range
            window = bc[dc_pos:dc_pos + 60]  # 30 bytes = 60 hex chars
            rdc_pos = window.find("3e")
            if rdc_pos != -1:
                # Check for return/revert after returndatacopy
                after_rdc = bc[dc_pos + rdc_pos:dc_pos + rdc_pos + 40]
                has_revert = "fd" in after_rdc
                has_return = "f3" in after_rdc
                if has_revert and has_return:
                    result.has_proxy_forwarding = True
                    break
            dc_pos = bc.find("f4", dc_pos + 2)


def _detect_erc1167(bc: str, result: BytecodeFingerprint) -> None:
    """Detect ERC-1167 minimal proxy clone pattern and extract implementation address."""
    if ERC1167_PREFIX in bc and ERC1167_SUFFIX in bc:
        result.has_erc1167_clone = True
        # Extract the 20-byte implementation address embedded in the clone bytecode
        # Pattern: <prefix><20-byte-addr><suffix>
        prefix_pos = bc.find(ERC1167_PREFIX)
        if prefix_pos != -1:
            addr_start = prefix_pos + len(ERC1167_PREFIX)
            addr_end = addr_start + 40  # 20 bytes = 40 hex chars
            if addr_end <= len(bc):
                addr = bc[addr_start:addr_end]
                if len(addr) == 40 and addr != "0" * 40:
                    result.implementation_address = "0x" + addr


def _detect_vyper_proxy(bc: str, result: BytecodeFingerprint) -> None:
    """Detect Vyper minimal proxy pattern (alternative to ERC-1167)."""
    if VYPER_PROXY_PREFIX in bc:
        result.has_vyper_proxy = True
        result.has_erc1167_clone = True  # Treat as a clone variant
        # Extract address from Vyper pattern
        prefix_pos = bc.find(VYPER_PROXY_PREFIX)
        if prefix_pos != -1:
            addr_start = prefix_pos + len(VYPER_PROXY_PREFIX)
            addr_end = addr_start + 40
            if addr_end <= len(bc):
                addr = bc[addr_start:addr_end]
                if len(addr) == 40 and addr != "0" * 40:
                    result.implementation_address = "0x" + addr


def _detect_diamond(bc: str, result: BytecodeFingerprint) -> None:
    """Detect Diamond Proxy (EIP-2535) via loupe function selectors.

    A diamond MUST implement the 4 loupe functions. The presence of 3+ loupe
    selectors plus the diamondCut selector is near-certain evidence.
    """
    loupe_count = 0
    loupe_selectors = [
        DIAMOND_FACETS_SELECTOR,
        DIAMOND_FACET_SELECTORS,
        DIAMOND_FACET_ADDRESSES,
        DIAMOND_FACET_ADDRESS,
    ]
    for sel in loupe_selectors:
        if sel in bc:
            loupe_count += 1

    has_diamond_cut = DIAMOND_CUT_SELECTOR in bc
    result.diamond_loupe_selectors = loupe_count

    # Require at least 3 loupe selectors OR (2 loupe + diamondCut)
    if loupe_count >= 3 or (loupe_count >= 2 and has_diamond_cut):
        result.has_diamond = True
        if has_diamond_cut:
            result.proxy_selectors_found.append("diamondCut(...)")
        for sel, name in zip(loupe_selectors, [
            "facets()", "facetFunctionSelectors(address)",
            "facetAddresses()", "facetAddress(bytes4)"
        ]):
            if sel in bc:
                result.proxy_selectors_found.append(name)


def _detect_gnosis_safe(bc: str, result: BytecodeFingerprint) -> None:
    """Detect Gnosis Safe proxy pattern.

    Safe proxies store the singleton/masterCopy address at storage slot 0
    and delegate all calls to it. Detection:
    - masterCopy() selector (0xa619486e) or singleton() (0x736bf590) in bytecode
    - SLOAD(0) → DELEGATECALL pattern in fallback
    """
    has_master_copy = SAFE_MASTER_COPY_SELECTOR in bc
    has_singleton = SAFE_SINGLETON_SELECTOR in bc
    has_setup = SAFE_SETUP_SELECTOR in bc

    if has_master_copy or has_singleton:
        result.has_gnosis_safe = True
        if has_master_copy:
            result.proxy_selectors_found.append("masterCopy()")
        if has_singleton:
            result.proxy_selectors_found.append("singleton()")
        if has_setup:
            result.proxy_selectors_found.append("setup(...)")
    elif has_setup and "f4" in bc:
        # setup() + DELEGATECALL without masterCopy/singleton selector
        # could be a Safe variant — mark with lower confidence
        # Only if we also see SLOAD(0) pattern
        if "600054" in bc:
            result.has_gnosis_safe = True
            result.proxy_selectors_found.append("setup(...)")


def _detect_compound_unitroller(bc: str, result: BytecodeFingerprint) -> None:
    """Detect Compound Unitroller (two-step upgrade proxy).

    Unitroller uses a pending-then-accept pattern:
    - _setPendingImplementation(address)
    - _acceptImplementation()
    Plus a comptrollerImplementation() getter.
    """
    has_comptroller_impl = COMPTROLLER_IMPL_SELECTOR in bc
    has_set_pending = SET_PENDING_IMPL_SELECTOR in bc
    has_accept = ACCEPT_IMPL_SELECTOR in bc

    # Need at least 2 of 3 indicators
    count = sum([has_comptroller_impl, has_set_pending, has_accept])
    if count >= 2:
        result.has_compound_unitroller = True
        result.has_two_step_upgrade = True
        if has_comptroller_impl:
            result.proxy_selectors_found.append("comptrollerImplementation()")
        if has_set_pending:
            result.proxy_selectors_found.append("_setPendingImplementation(address)")
        if has_accept:
            result.proxy_selectors_found.append("_acceptImplementation()")


def _detect_eip897(bc: str, result: BytecodeFingerprint) -> None:
    """Detect EIP-897 DelegateProxy via proxyType() selector."""
    has_proxy_type = PROXY_TYPE_SELECTOR in bc
    has_implementation = IMPLEMENTATION_SELECTOR in bc

    if has_proxy_type and has_implementation:
        result.has_eip897 = True
        result.proxy_selectors_found.append("proxyType()")
    elif has_proxy_type and "f4" in bc:
        # proxyType() + DELEGATECALL = likely an EIP-897 proxy
        result.has_eip897 = True
        result.proxy_selectors_found.append("proxyType()")


def _detect_oz_ownable(bc: str, result: BytecodeFingerprint) -> None:
    """Detect OZ Ownable by requiring owner() + transferOwnership(address) selectors."""
    has_owner = OZ_OWNER_SELECTOR in bc
    has_transfer = OZ_TRANSFER_OWNERSHIP_SELECTOR in bc
    if has_owner and has_transfer:
        result.has_oz_ownable = True


def _detect_oz_ownable2step(bc: str, result: BytecodeFingerprint) -> None:
    """Detect OZ Ownable2Step by requiring pendingOwner() + acceptOwnership() selectors.

    These selectors only appear together in Ownable2Step — each alone could be custom.
    """
    has_pending = OZ_PENDING_OWNER_SELECTOR in bc
    has_accept = OZ_ACCEPT_OWNERSHIP_SELECTOR in bc
    if has_pending and has_accept:
        result.has_oz_ownable2step = True
        result.has_two_step_upgrade = True


def _detect_oz_access_control(bc: str, result: BytecodeFingerprint) -> None:
    """Detect OZ AccessControl by requiring 3 of 5 role-management selectors.

    Requiring ≥3 avoids FP from contracts that happen to have hasRole or grantRole
    without full AccessControl.
    """
    access_selectors = [
        OZ_HAS_ROLE_SELECTOR,
        OZ_GRANT_ROLE_SELECTOR,
        OZ_REVOKE_ROLE_SELECTOR,
        OZ_RENOUNCE_ROLE_SELECTOR,
        OZ_GET_ROLE_ADMIN_SELECTOR,
    ]
    count = sum(1 for sel in access_selectors if sel in bc)
    if count >= 3:
        result.has_oz_access_control = True


def _detect_oz_pausable(bc: str, result: BytecodeFingerprint) -> None:
    """Detect OZ Pausable by requiring paused() + pause() or unpause() selector.

    Two signals required to avoid FP from contracts that define paused() alone.
    """
    has_paused = OZ_PAUSED_SELECTOR in bc
    has_pause_action = OZ_PAUSE_SELECTOR in bc or OZ_UNPAUSE_SELECTOR in bc
    if has_paused and has_pause_action:
        result.has_oz_pausable = True


def _detect_oz_timelock(bc: str, result: BytecodeFingerprint) -> None:
    """Detect OZ TimelockController by requiring getMinDelay() + schedule() or execute().

    Two corroborating selectors reduce FP risk.
    """
    has_min_delay = OZ_TIMELOCK_GET_MIN_DELAY in bc
    has_schedule_or_execute = OZ_TIMELOCK_SCHEDULE in bc or OZ_TIMELOCK_EXECUTE in bc
    if has_min_delay and has_schedule_or_execute:
        result.has_oz_timelock = True


def _detect_safe_erc20(bc: str, result: BytecodeFingerprint) -> None:
    """Detect OZ SafeERC20 pattern: RETURNDATASIZE check after ERC20 call.

    SafeERC20 wraps ERC20 calls with:
      CALL → RETURNDATASIZE == 0 OR (RETURNDATASIZE >= 32 AND mload(ptr) != 0)
    In bytecode: CALL(f1) → RETURNDATASIZE(3d) → ISZERO(15) → or branch to mload check.
    We look for the compact pattern: f1 ... 3d ... 15 within 20 bytes.
    """
    # Pattern: CALL (f1), then RETURNDATASIZE (3d), then ISZERO (15) within 20 bytes
    pos = 0
    bc_len = len(bc)
    found = False
    while pos < bc_len - 6 and not found:
        if bc[pos:pos + 2] == "f1":  # CALL opcode
            # Look for 3d (RETURNDATASIZE) then 15 (ISZERO) within 40 hex chars (20 bytes)
            window = bc[pos:pos + 40]
            rds_pos = window.find("3d")
            if rds_pos != -1:
                iszero_pos = window.find("15", rds_pos)
                if iszero_pos != -1:
                    result.has_safe_erc20 = True
                    found = True
        pos += 2


def _detect_slot0_proxy(bc: str, result: BytecodeFingerprint) -> None:
    """Detect generic slot-0 proxy: SLOAD(0) followed by DELEGATECALL.

    Many custom proxies (including older Gnosis Safe, custom admin proxies)
    store the implementation address at slot 0 and use a minimal fallback.

    Pattern in bytecode: PUSH1 0x00 (6000) + SLOAD (54) ... DELEGATECALL (f4)
    We require this in a compact window to avoid false positives.
    """
    # Already detected as a more specific type? Skip.
    if result.has_gnosis_safe or result.has_erc1167_clone or result.has_erc1967_impl_slot:
        return

    # Look for PUSH1 0x00 SLOAD = 600054
    # Then DELEGATECALL within 60 bytes (30 opcodes)
    pattern = "600054"
    pos = bc.find(pattern)
    while pos != -1:
        # Check for DELEGATECALL within ~60 bytes after SLOAD(0)
        window = bc[pos:pos + 120]  # 60 bytes = 120 hex chars
        if "f4" in window:
            # Confirm it's in a fallback-like context by checking
            # for CALLDATACOPY (37) or CALLDATASIZE (36) nearby
            extended = bc[max(0, pos - 40):pos + 120]
            if "36" in extended or "37" in extended:
                result.has_slot0_proxy = True
                break
        pos = bc.find(pattern, pos + 6)


def _detect_uups(bc: str, result: BytecodeFingerprint) -> None:
    """Detect UUPS proxy pattern via proxiableUUID selector."""
    if UUPS_SELECTOR in bc:
        result.has_uups = True


def _detect_proxy_selectors(bc: str, result: BytecodeFingerprint) -> None:
    """Detect well-known proxy function selectors in bytecode."""
    selector_map = {
        UPGRADE_TO_SELECTOR: "upgradeTo(address)",
        UPGRADE_TO_AND_CALL_SELECTOR: "upgradeToAndCall(address,bytes)",
        CHANGE_ADMIN_SELECTOR: "changeAdmin(address)",
        ADMIN_SELECTOR: "admin()",
        IMPLEMENTATION_SELECTOR: "implementation()",
    }
    for sel, name in selector_map.items():
        if sel in bc:
            result.proxy_selectors_found.append(name)


def _detect_reentrancy_guard(bc: str, result: BytecodeFingerprint) -> None:
    """Detect reentrancy guard constants in bytecode.

    OpenZeppelin ReentrancyGuard uses:
    - _NOT_ENTERED = 1
    - _ENTERED = 2

    Pattern: SLOAD slot → compare to 1 → if not 1, revert → SSTORE 2 → ... → SSTORE 1

    We look for the constant 2 being stored (PUSH1 02 SSTORE pattern) which is
    distinctive of reentrancy guards. We also detect slot-based reentrancy by
    looking for the read-check-write-restore pattern.
    """
    # Check for the _NOT_ENTERED=1, _ENTERED=2 constant pattern
    # PUSH1 0x02 followed closely by SSTORE, and PUSH1 0x01 SSTORE elsewhere
    # This is more reliably detected from the raw opcode sequence.

    # Simpler heuristic: if the bytecode contains both PUSH1 01 55 (SSTORE 1)
    # and PUSH1 02 55 (SSTORE 2) patterns, it likely has a reentrancy guard.
    # PUSH1 = 60, SSTORE = 55
    has_store_1 = "600155" in bc  # PUSH1 01 SSTORE
    has_store_2 = "600255" in bc  # PUSH1 02 SSTORE

    if has_store_1 and has_store_2:
        result.has_reentrancy_guard_constants = True


def _detect_initializer(bc: str, result: BytecodeFingerprint) -> None:
    """Detect initializer pattern.

    OpenZeppelin Initializable uses a storage slot that starts as 0,
    is set during initialization, and checked to prevent re-initialization.

    In OZ v4+, the _initialized variable is a uint8 at a specific slot.
    The pattern: SLOAD(slot) → check != 0 → REVERT; then SSTORE 1/true.

    We detect the initialized counter constant (0xff for OZ v5 reinitializer max).
    """
    # OZ Initializable v4: uses _initialized (uint8) and _initializing (bool)
    # The max reinitializer value 0xff (255) is a strong signal
    # PUSH1 0xff = 60ff
    # Also look for the OZ InitializedV5 slot constant
    oz_init_slot_v5 = "f0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00"
    if oz_init_slot_v5 in bc:
        result.has_initializer_pattern = True
    elif "60ff" in bc:
        # Could be Initializable max reinitializer value
        # Needs storage context to confirm, but mark as possible
        result.has_initializer_pattern = True


def _classify_proxy_type(result: BytecodeFingerprint) -> None:
    """Classify the specific proxy type based on detected patterns."""
    # Most specific patterns first
    if result.has_erc1167_clone:
        result.proxy_type = "ERC1167_CLONE"
    elif result.has_diamond:
        result.proxy_type = "DIAMOND_PROXY"
    elif result.has_gnosis_safe:
        result.proxy_type = "GNOSIS_SAFE_PROXY"
    elif result.has_compound_unitroller:
        result.proxy_type = "COMPOUND_UNITROLLER"
    elif result.has_proxy_forwarding and result.has_erc1967_impl_slot:
        if result.has_erc1967_admin_slot:
            if result.has_uups:
                result.proxy_type = "UUPS_PROXY"
            else:
                result.proxy_type = "TRANSPARENT_PROXY"
        elif result.has_erc1967_beacon_slot:
            result.proxy_type = "BEACON_PROXY"
        elif result.has_uups:
            result.proxy_type = "UUPS_PROXY"
        else:
            result.proxy_type = "ERC1967_PROXY"
    elif result.has_uups and result.has_erc1967_impl_slot:
        result.proxy_type = "UUPS_PROXY"
    elif result.has_eip897:
        result.proxy_type = "EIP897_DELEGATE_PROXY"
    elif result.has_erc1967_impl_slot:
        result.proxy_type = "ERC1967_PROXY"
    elif result.has_slot0_proxy:
        result.proxy_type = "SLOT0_PROXY"
    elif result.has_vyper_proxy:
        result.proxy_type = "VYPER_MINIMAL_PROXY"
    elif result.has_proxy_forwarding:
        result.proxy_type = "GENERIC_PROXY"


def _build_tags(result: BytecodeFingerprint) -> None:
    """Build the final list of tags from detected patterns."""
    tags = []

    if result.has_erc1967_impl_slot:
        tags.extend(["ERC1967_PROXY", "ERC-1967"])
    if result.has_erc1967_admin_slot:
        tags.extend(["ERC1967_ADMIN_SLOT", "proxy_admin_guard"])
    if result.has_erc1967_beacon_slot:
        tags.append("ERC1967_BEACON_SLOT")
    if result.has_proxy_forwarding:
        tags.extend(["PROXY_FORWARDING_PATTERN", "PROXY_FORWARDING_DELEGATECALL",
                      "assembly_return_value_handling", "verified_return_check_cross_block"])
    if result.has_erc1167_clone:
        tags.extend(["ERC1167_CLONE", "erc1167_fixed_clone_target"])
    if result.has_vyper_proxy:
        tags.append("VYPER_MINIMAL_PROXY")
    if result.has_diamond:
        tags.extend(["DIAMOND_PROXY", "EIP2535_DIAMOND", "DIAMOND_FACET_ROUTING",
                      "proxy_safe_delegatecall", "fixed_delegatecall_target"])
    if result.has_gnosis_safe:
        tags.extend(["GNOSIS_SAFE_PROXY", "SAFE_PROXY", "SLOT0_PROXY",
                      "proxy_safe_delegatecall"])
    if result.has_compound_unitroller:
        tags.extend(["COMPOUND_UNITROLLER", "TWO_STEP_UPGRADE", "proxy_safe_delegatecall"])
    if result.has_eip897:
        tags.append("EIP897_DELEGATE_PROXY")
    if result.has_slot0_proxy:
        tags.extend(["SLOT0_PROXY", "GENERIC_STORAGE_PROXY"])
    if result.has_two_step_upgrade:
        tags.extend(["TWO_STEP_UPGRADE", "two_step_acceptance_by_new_admin"])
    if result.proxy_type:
        tags.append(result.proxy_type)
        safe_types = {"TRANSPARENT_PROXY", "UUPS_PROXY", "BEACON_PROXY",
                      "ERC1967_PROXY", "ERC1167_CLONE", "DIAMOND_PROXY",
                      "GNOSIS_SAFE_PROXY", "COMPOUND_UNITROLLER",
                      "EIP897_DELEGATE_PROXY", "VYPER_MINIMAL_PROXY"}
        if result.proxy_type in safe_types:
            tags.append("KNOWN_SAFE_PROXY_PATTERN")
    if result.has_uups:
        tags.append("UUPS_PATTERN")
    if result.has_erc1967_admin_slot and result.has_proxy_forwarding:
        tags.extend(["admin_guarded_function", "ADMIN_GUARD"])
    if result.has_reentrancy_guard_constants:
        tags.extend(["REENTRANCY_GUARD", "reentrancy_guard", "mutex_lock", "OZ_REENTRANCY_GUARD"])
    if result.has_initializer_pattern:
        tags.extend(["INITIALIZABLE", "initializer_guard"])
    if result.proxy_selectors_found:
        tags.append("PROXY_UPGRADE_SELECTORS")
    if result.implementation_address:
        tags.append("IMPLEMENTATION_ADDRESS_EXTRACTED")
    # OZ library fingerprints
    if result.has_oz_ownable:
        tags.extend(["OZ_OWNABLE", "owner_or_admin_guard"])
    if result.has_oz_ownable2step:
        tags.extend(["OZ_OWNABLE2STEP", "two_step_acceptance_by_new_admin", "owner_or_admin_guard"])
    if result.has_oz_access_control:
        tags.extend(["OZ_ACCESS_CONTROL", "role_admin_guard", "STRONG_AUTH_GUARD"])
    if result.has_oz_pausable:
        tags.extend(["OZ_PAUSABLE", "pause_guard"])
    if result.has_oz_timelock:
        tags.extend(["OZ_TIMELOCK_CONTROLLER", "timelock_or_governance_guard", "timelock_guard"])
    if result.has_safe_erc20:
        tags.extend(["SAFE_ERC20_USAGE", "safeTransfer"])
    all_safe = {"TRANSPARENT_PROXY", "UUPS_PROXY", "BEACON_PROXY", "ERC1967_PROXY",
                "DIAMOND_PROXY", "GNOSIS_SAFE_PROXY", "COMPOUND_UNITROLLER",
                "EIP897_DELEGATE_PROXY"}
    if result.proxy_type in all_safe:
        tags.extend(["SSTORE_BEFORE_CALL_ONLY", "proxy_safe_delegatecall"])

    result.tags = sorted(set(tags))

