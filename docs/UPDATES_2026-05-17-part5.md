# Updates — 2026-05-17 (part 5): rescue-prove@2 (coverage expansion)

> Honest answer to "is the auto-rescue advanced enough for different case scenarios and edge cases?": **v1 was a foundation — this update closes the four biggest gaps. There are still classes of bugs it won't auto-rescue (documented below) but the everyday "deployer authorises us" workflow is now fully wired.**

## Why this update

v1 of `rescue-prove` (shipped in part 4) only covered ~20-30% of real exploit shapes. It worked great on the canonical "Symbiosis-style `exec(target, data)` arbitrary-call forwarder" pattern and on plain `selfdestruct(address)` functions — and refused to attempt the rest. Anything else returned `no_rescue_possible`.

The gaps this update closes:

| Gap | v1 | v2 |
|---|---|---|
| **A. Owner-only exploits** | Drained from attacker EOA → reverted → no_rescue_possible | `anvil_impersonateAccount` the owner (when `RESCUE_IMPERSONATE_OWNER=true`); broadcaster knows to require `RESCUE_OWNER_PRIVATE_KEY` for live broadcast of owner-executor steps |
| **C. Wrapped-native holdings (WETH/WBNB/…)** | Drained as ERC-20 only (left as wrapped) | Prepends `WETH.withdraw(balance)` via the same forwarder so subsequent native-drain steps see the new native balance. Per-chain canonical wrapped-native table |
| **D+G. Forwarder shape edge cases** | Single uintFiller (balance), no transferFrom fallback, single addrPos for selfdestruct | Multi-variant fanout: `uintFiller ∈ {balance, max, half, 0}`, `transferFrom(self, escrow, bal)` template alongside `transfer`, multi-position selfdestruct search (positions 0..3) |
| **H. No witnessed forwarder attempt** | Returned no_rescue_possible immediately | Scans contract bytecode for ~16 curated admin-named function selectors (`withdraw`/`rescue`/`sweep`/`emergency`/…), builds canonical drain calldata for each that's present, marks them as owner-executor |

## Engine bump: `rescue-prove@1` → `rescue-prove@2`

Old PoEs remain in the DB as historical records (they're proofs of what happened at a point in time — not a cache). New PoEs are tagged `engineVersion="2"` and carry two new fields:

- `executorOwner: string | null` — owner address impersonated on the fork (if any)
- `drainPlan[i].executor: "attacker" | "owner"` — which signing key the step needs
- `drainPlan[i].from: string` — the actual sender address on the fork
- `drainPlan[i].strategy: string` — short tag describing the strategy that produced this step (`witnessed-arbitrary-call sel=…`, `weth-unwrap addr=…`, `admin-heuristic:rescueERC20(…)`, …)

## Broadcaster updates (`panel/src/server/rescue/broadcaster.ts`)

- **owner-executor guard**: live mode refuses to broadcast if any drain step has `executor === "owner"` AND `RESCUE_OWNER_PRIVATE_KEY` isn't configured. The error message names the exact owner address from the PoE so the operator knows whose key to request.
- **dual-wallet broadcast**: when both `RESCUER_PRIVATE_KEY` and `RESCUE_OWNER_PRIVATE_KEY` are set, attacker-executor steps go via the rescuer EOA and owner-executor steps via the owner EOA. Independent nonce counters. Mismatch between PoE's `executorOwner` and the configured owner key is logged into the rescue-actions timeline as a warning (not a hard fail — operators may rotate keys).

## UI surface (`panel/src/components/FindingDetail.tsx`)

`ProofOfExploitPanel` now shows:
- **Purple `owner-required` badge** in the header when any step needs the owner's key, with tooltip explaining the broadcaster behavior
- **`owner: 0xABCD…1234`** chip in the meta row showing the impersonated owner address

## New env knobs

```bash
# Default true. When set to false, owner-only findings produce
# no_rescue_possible even if the owner key is known.
RESCUE_IMPERSONATE_OWNER=true

# Required for live broadcast of any drain step tagged executor="owner".
# When unset, the broadcaster refuses live mode for owner-required PoEs.
RESCUE_OWNER_PRIVATE_KEY=0x...
```

## Honest coverage matrix (what v2 still won't do)

Stuff that still returns `no_rescue_possible` and probably should — earmarked for v3:

- **B. Approval-surface drain** (transferFrom victims who approved the contract) — needs per-victim off-chain consent, big policy question
- **F-1. Initializer takeover two-phase** (init then admin drain) — needs proxy-aware logic
- **F-3. Flash-loan rescue for economic.* findings** — needs per-chain Aave/Balancer config + a custom flash-loan receiver contract
- **Token quirks**: fee-on-transfer (partial rescue with delta-mismatch), paused/blacklisted tokens (revert on `transfer`), rebasing tokens (stale balance snapshot)
- **Multi-arg forwarders** where ALL address slots need to be set (v2 only substitutes one)
- **Sub-call calldata in non-raw envelopes** (EIP-712 wrappers, multicall, etc.)

These are all known and deliberate. The v2 changes catch the classes we hit most often in real auditor runs — particularly owner-only contracts where the deployer can authorise rescue, and contracts that hold wrapped-native.

## Files changed

```
panel/src/server/sim/rescue-prove.ts       (+~400 LoC, engine bump to @2)
panel/src/server/sim/poe-store.ts          (PoeDrainStep/PoeArtifact schema additions)
panel/src/server/rescue/broadcaster.ts     (owner-executor guard + dual-wallet)
panel/src/components/FindingDetail.tsx     (owner-required badge + owner address chip)
docs/UPDATES_2026-05-17-part5.md           (this file)
```

## Verification

```
$ pnpm run sim:corpus
[corpus] pass=24  fail=0  error=0  total=24  elapsed=14.2s
```

Corpus regression suite still 24/24 green — all v1 behavior preserved, v2 paths are additive.
