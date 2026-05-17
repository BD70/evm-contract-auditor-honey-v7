# Counter Evidence

Counter-evidence is not a comment field. It is part of the detector contract.

## Four Outcomes

- `suppress_if_any`: detector should not fire
- `downgrade_if_any`: finding remains but severity drops
- `inconclusive_if_any`: finding should become `analysis_inconclusive`
- `manual_review_if_any`: keep finding but surface analyst review need

## Structured Guard Classes

Recommended guard families:

- initializer single-use
- factory-only initializer
- two-step ownership acceptance
- governance or timelock gated admin updates
- signature authorization with nonce and replay protection
- fixed ERC-1167 clone target

## Signature Guard Standard

A strong signature guard should usually cover:

- target slot or target action
- new value
- chain or domain separation
- contract address
- nonce consumption
- deadline or replay bound

Weak signature evidence should downgrade, not suppress.

---

## Full Counter-Evidence Token Catalog

### Library and Proxy Fingerprint Tokens

These tokens are emitted by `evm_decon/known_bytecodes.py` and merged into the
counter-evidence evaluation automatically via `state_model.library_fingerprints`.
Every `id` in that array is available as a token in `suppress_if_any`,
`downgrade_if_any`, and `inconclusive_if_any`.

| Token | Source | Description |
|---|---|---|
| `OZ_REENTRANCY_GUARD` | bytecode fingerprint | OpenZeppelin ReentrancyGuard: `_status` slot toggles 1↔2 around external call |
| `INITIALIZABLE` | bytecode fingerprint | OpenZeppelin Initializable: `_initialized` slot + initializer modifier |
| `OZ_OWNABLE` | bytecode fingerprint | OpenZeppelin Ownable: `owner()` + `transferOwnership()` selectors |
| `OZ_OWNABLE2STEP` | bytecode fingerprint | OpenZeppelin Ownable2Step: `pendingOwner()` + `acceptOwnership()` selectors |
| `OZ_ACCESS_CONTROL` | bytecode fingerprint | OpenZeppelin AccessControl: `hasRole` + `grantRole` + `DEFAULT_ADMIN_ROLE` pattern |
| `OZ_PAUSABLE` | bytecode fingerprint | OpenZeppelin Pausable: `paused()` + `pause()`/`unpause()` selectors |
| `OZ_TIMELOCK_CONTROLLER` | bytecode fingerprint | OpenZeppelin TimelockController: `getMinDelay()` + `schedule()`/`execute()` |
| `SAFE_ERC20_USAGE` | bytecode fingerprint | SafeERC20: CALL→RETURNDATASIZE→ISZERO wrapper pattern |
| `ERC1967_PROXY` | bytecode fingerprint | EIP-1967 proxy: implementation slot `0x360894...` |
| `ERC1167_CLONE` | bytecode fingerprint | EIP-1167 minimal proxy: ≤45-byte runtime with fixed clone target |
| `UUPS_PROXY` | bytecode fingerprint | EIP-1822 UUPS: `proxiableUUID()` selector present |
| `DIAMOND_PROXY` | bytecode fingerprint | EIP-2535 Diamond: `facets()` + `facetAddresses()` selectors |
| `GNOSIS_SAFE` | bytecode fingerprint | Gnosis Safe: `execTransaction` + multi-sig guard pattern |

### Behavioral Guard Tokens

Emitted from `function.behavior_tags` or `state_model.guard_catalog` entries during analysis.

| Token | Description |
|---|---|
| `reentrancy_guard` | Any reentrancy mutex detected (CEI or storage mutex) |
| `OZ_REENTRANCY_GUARD` | Specifically the OZ nonReentrant mutex |
| `cei_pattern_guard` | Checks-Effects-Interactions ordering confirmed |
| `KNOWN_SAFE_PROXY_PATTERN` | Delegatecall target is a known safe proxy pattern |
| `two_step_acceptance_by_new_admin` | Owner change requires pending owner to accept |
| `role_admin_guard` | Role-based access control guards the sensitive path |
| `timelock_or_governance_guard` | Timelocked or governance-controlled path |
| `safeTransfer` | SafeERC20 `safeTransfer` or `safeTransferFrom` used |
| `initializer_single_use_guard` | Initializer enforces one-time call invariant |
| `factory_only_initializer` | Initializer restricted to deployer/factory caller |
| `signature_authorization_with_nonce` | Signature guard with nonce consumption |

### Detector-Specific Suppression Tokens

Tokens declared in individual detector `counter_evidence` blocks.

#### Access / Auth Detectors

| Token | Suppresses | Notes |
|---|---|---|
| `OZ_OWNABLE2STEP` | `access.public_privileged_slot_poisoning`, `auth.authorization_predicate_poisoning`, `init.public_initializer_takeover`, `proxy.unprotected_implementation_upgrade`, `control.unguarded_selfdestruct` | Two-step acceptance eliminates single-tx takeover |
| `OZ_ACCESS_CONTROL` | `access.public_privileged_slot_poisoning`, `auth.authorization_predicate_poisoning`, `call.unvalidated_calldataload_target_injection` | Role-based guard eliminates caller-poisoning surface |
| `OZ_TIMELOCK_CONTROLLER` | `access.public_privileged_slot_poisoning`, `proxy.unprotected_implementation_upgrade`, `control.unguarded_selfdestruct`, `init.public_initializer_takeover` | Timelock delay eliminates single-block admin attack |
| `OZ_OWNABLE` | downgrade in access/auth/proxy detectors | Two-step not present but Ownable guard reduces unguarded risk |
| `eip712_domain_separator_guard` | `auth.eip712_domain_separator_missing` | EIP-712 structured data hash with stored domain separator |
| `permit_companion_guard` | `token.erc20_approve_race` | EIP-2612 permit or Permit2 integration present |
| `increaseAllowance_companion` | `token.erc20_approve_race` | OZ increaseAllowance/decreaseAllowance present |

#### Reentrancy Detectors

| Token | Suppresses | Notes |
|---|---|---|
| `OZ_REENTRANCY_GUARD` | `reentrancy.classic_mutex_absent`, `reentrancy.state_after_external_call`, `reentrancy.read_only_exposure` | nonReentrant modifier detected |
| `REENTRANCY_GUARD` | Same as above | Generic reentrancy guard token |
| `cei_pattern_guard` | `reentrancy.state_after_external_call` | Checks-Effects-Interactions ordering confirmed |

#### Token Security Detectors

| Token | Suppresses | Notes |
|---|---|---|
| `SAFE_ERC20_USAGE` | `token.unsafe_erc20_assumption`, `call.unchecked_return_value` | SafeERC20 wrapper handles return values |
| `safeTransfer` | `token.unsafe_erc20_assumption` | Specific safeTransfer call pattern |
| `eip2612_permit` | `token.erc20_approve_race` | EIP-2612 permit signature approval |
| `PERMIT2_INTEGRATION` | `token.erc20_approve_race` | Uniswap Permit2 integration |

#### DeFi Logic Detectors

| Token | Suppresses | Notes |
|---|---|---|
| `slippage_check_guard` | `defi.swap.missing_slippage_or_deadline` | `amountOut >= minAmountOut` comparison detected |
| `deadline_check_guard` | `defi.swap.missing_slippage_or_deadline` | `block.timestamp <= deadline` comparison detected |
| `amountOut_ge_minOut_revert` | `defi.swap.missing_slippage_or_deadline` | Output amount check with revert path |
| `block_timestamp_le_deadline_revert` | `defi.swap.missing_slippage_or_deadline` | Deadline check with revert path |
| `virtual_shares_offset_guard` | `defi.erc4626.first_depositor_inflation` | Virtual shares constant prevents rounding to zero |
| `dead_shares_mint_guard` | `defi.erc4626.first_depositor_inflation` | Dead shares minted at initialization |
| `oz_erc4626_virtual_shares` | `defi.erc4626.first_depositor_inflation` | OZ ERC4626 v5 virtual shares pattern |

#### Oracle Detectors

| Token | Suppresses | Notes |
|---|---|---|
| `chainlink_staleness_check` | `oracle.chainlink_staleness_unchecked` | `updatedAt` from `latestRoundData()` compared against `block.timestamp` |
| `DOMAIN_SEPARATOR_SLOT_READ` | `auth.eip712_domain_separator_missing` | Domain separator read from storage before ecrecover |

#### Call / Target Detectors

| Token | Suppresses | Notes |
|---|---|---|
| `allowlist_guard` | `call.user_controlled_external_target` | Target validated against an allowlist before call |
| `address_validation` | `call.user_controlled_external_target` | Call target validated against a stored address |
| `KNOWN_SAFE_PROXY_PATTERN` | `reentrancy.read_only_exposure` | Known safe proxy pattern detected |

#### Randomness Detectors

| Token | Suppresses | Notes |
|---|---|---|
| `chainlink_vrf_guard` | `randomness.timestamp_or_blockhash_value_gating` | Chainlink VRF used as randomness source |
| `commit_reveal_guard` | `randomness.timestamp_or_blockhash_value_gating` | Commit-reveal scheme prevents miner manipulation |
| `view_only_gating_guard` | downgrade in `randomness.timestamp_or_blockhash_value_gating` | Timestamp/blockhash gates a view, not a state change |

#### Signature Replay Detectors

| Token | Suppresses | Notes |
|---|---|---|
| `nonce_slot_increment_guard` | `auth.signature_replay_missing_nonce` | SLOAD → ADD(1) → SSTORE pattern on nonce slot |
| `eip2612_permit` | `auth.signature_replay_missing_nonce` | EIP-2612 permit with nonce |

---

## Counter-Evidence Pipeline

Tokens are collected from three sources before each rule evaluation:

1. `state_model.guard_catalog[*].id` — structural guards detected by the state model
2. `state_model.library_fingerprints[*].id` — fingerprinted OZ/proxy libraries (≥0.82 confidence)
3. `state_model.proxy_index[*].proxy_standard` and `[*].slot_kind` — proxy patterns
4. `function.behavior_tags[*]` — per-function behavioral tags from bytecode analysis

The union of all tokens is tested against each detector's `counter_evidence` block.
Suppression tokens prevent the finding from being emitted at all.
Downgrade tokens reduce the emitted severity by one level.
Inconclusive tokens set `status: analysis_inconclusive` and `witness_status: analysis_inconclusive`.
Manual-review tokens add `requires_manual_review: true` without changing status.
