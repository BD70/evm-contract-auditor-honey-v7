# 2026-05-17 — part 8 — rescue-prove@5: attacker-side-only

## What changed and why

User feedback on part 7: **"the rescue should not be owner-side. It always
should be attacker side it doesn't make sense."**

That's the correct mental model. The whole purpose of the rescue pipeline is
"an attacker can drain this contract right now; let's frontrun them and
deliver the funds to escrow." If only the contract owner can drain, an
attacker can't — so there is nothing for the auto-rescue to do. The
funds depend on the owner's key custody, which is out of scope.

v2-v4 had wired an owner-impersonation drain path on top of that core
loop. It was a category error: "owner withdrawing funds" is not a
rescue, it's just the owner doing what they were always able to do.
Worse, live-broadcasting an owner-side rescue would have required
holding the deployer's private key (RESCUE_OWNER_PRIVATE_KEY), which
defeats the threat model and adds custodial risk for zero benefit.

v5 gets rid of all of it.

## Behavioural changes

### Owner-only findings: short-circuit no_rescue_possible
- `rescueProve()` now exits before forking when
  `evidence.attackerKind === "owner"`. Verdict is `no_rescue_possible`
  with a clear note: "owner-only exploit: vulnerable function is gated to
  the contract owner. An attacker cannot drain, so there is nothing for
  the auto-rescue pipeline to do."
- Saves a fork allocation and a full drain-plan build for every
  owner-only finding the worker hits.

### Drain plan is always attacker-side
- Removed the `executor: "attacker" | "owner"` discriminator from
  `DrainStep` and `PoeDrainStep`. Every step is sent from
  `ATTACKER_ADDRESS` on the fork and from `RESCUER_PRIVATE_KEY` in live mode.
- Removed `anvil_impersonateAccount` wiring, owner-step dispatch,
  `sendFromImpersonated` helper, and the `ownerAddressFromEvidence` resolver.
- Init-takeover phase-2 still works: the attacker calls
  `initialize(escrow=attackerEOA)` in phase 1 and **becomes** the
  owner, so admin-name heuristic in phase 2 succeeds when run from the
  same attacker EOA — no impersonation needed.

### Safe-multisig handling removed
- Removed the `requires_safe_signing` verdict from `PoeVerdict`.
- Removed the `safeRequirement` field from `PoeArtifact`.
- Deleted `panel/src/server/sim/rescue/safe-tx.ts` (Safe deeplink
  generator / chain table / instruction builder).
- Removed the broadcaster's `requires_safe_signing` gate.
- Removed the UI's teal Safe panel and "Open in Safe app" button.
- Why: this whole path was tied to owner-side rescue. With owner-side
  gone, Safe-owned contracts that have an owner-only exploit just
  produce `no_rescue_possible` like any other owner-only finding.
  (A Safe-owned contract that has an **any-caller** exploit still
  gets fully rescued attacker-side — the Safe doesn't matter.)

### Broadcaster simplification
- Removed dual-wallet logic (rescuer EOA + owner EOA).
- Removed `RESCUE_OWNER_PRIVATE_KEY` parsing and the owner-required
  live-mode gate.
- Removed the `executorOwner` mismatch warning.
- `liveBroadcast()` is now a single nonce stream, single wallet.

### UI cleanup
- Removed the "owner-required" badge from the PoE panel header.
- Removed the "owner: 0x…" chip from the metadata strip.
- Removed the entire Safe-multisig panel (deeplink + threshold badge).
- Verdict colour map no longer has `requires_safe_signing` (teal).

## Engine bump

- `rescue-prove` engine: **5** (was 4).
- Existing PoE rows in the DB are preserved bit-for-bit and remain
  loadable — the dropped fields are still tolerated by the JSON parse
  but no longer surfaced in the UI.

## Env knob changes (cleaned in `.env` and `.env.example`)

**Removed (no longer read by any code path):**
- `RESCUE_IMPERSONATE_OWNER` — owner impersonation gate
- `RESCUE_OWNER_PRIVATE_KEY` — owner signing key for live broadcast
- `RESCUE_SAFE_TX_SERVICE_URL` — Safe Transaction Service override

**Kept (still active in v5):**
- `RESCUE_ESCROW_ADDR`, `RESCUER_PRIVATE_KEY`, `RESCUE_AUTH_TOKEN`,
  `RESCUE_BROADCAST_ENABLED` — core rescue execution
- `TG_BOT_TOKEN`, `TG_CHAT_ID`, `TG_ALLOWED_CHAT_IDS` — Telegram bot
- `RESCUE_APPROVAL_CONSENT_MODE`, `RESCUE_APPROVAL_CONSENT_VICTIMS`,
  `RESCUE_APPROVAL_LOOKBACK`, `RESCUE_APPROVAL_MAX_VICTIMS` — v3-A
  approval-surface scan
- `RESCUE_FLASHLOAN_ENABLED`, `RESCUE_FLASHLOAN_GRANT_ETH`,
  `RESCUE_FLASHLOAN_RECEIVER` — v3/v4-FL flash-loan helper
- `RESCUE_EXTRA_ADMIN_SLOTS` — v4 bespoke-proxy slot probe (diagnostic
  only)

## Regression

- `pnpm exec tsc --noEmit`: clean
- `pnpm run sim:corpus`: 24/24 pass, 0 fail, 0 error, 14.8s

No corpus regressions. The economic-attack tax-token suppressor from
part 6 is still effective; the new `econ-eth-tax-token-pair-direct-479f9583-tn`
anchor continues to pass.
