# Updates — 2026-05-17 (part 6): rescue-prove@3 + tg-bot resilience

## Summary

v2 covered the everyday cases. v3 closes ALL the deferred edge cases I called out honestly in part-5:

1. **Token quirks** (FOT / paused / blacklisted / non-transferable) — pre-flight detection + per-asset quirk metadata, "trapped assets" verdict for the all-trapped case
2. **Multi-arg forwarders** — ALL-positions address substitution fanout, every (token, escrow) slot pair tried
3. **Multicall / EIP-712 envelopes** — bytecode-detected `multicall(bytes[])` + variants, wrap drain calldata into the envelope as fallback variants
4. **Initializer-takeover two-phase rescue** — phase-1 `initialize(escrow)` replay (re-probed for freshness) + phase-2 admin-name heuristic drain from the new attacker-owner
5. **Approval-surface drain** — scans `Approval` logs from victims, computes per-victim drainable, gated by `RESCUE_APPROVAL_CONSENT_MODE` (default `scan-only`) and per-victim consent list
6. **Flash-loan rescue stub** — on-fork `anvil_setBalance` capital grant to prove drainability for `economic.*`, emits `requires_flashloan_helper` PoE with suggested Aave v3 pool per chain

Plus: tg-bot now survives Cloudflare keep-alive resets cleanly.

## New PoE verdicts

```
victim_approval_rescue      // drainable VICTIMS' approvals; live requires per-victim consent
requires_flashloan_helper   // economic exploit drains on fork given capital; live needs flash-loan receiver
trapped_assets_only         // every token paused/blacklisted/non-transferable
```

## New schema fields on PoeArtifact

```ts
approvalVictims?: PoeApprovalVictim[]    // {victim, token, allowance, balance, drainable, drainableUsd, consented}
trappedAssets?: PoeTrappedAsset[]        // {token, symbol, balance, usdValue, reason}
flashloanRequirement?: {                 // when verdict='requires_flashloan_helper'
  asset, amount, suggestedPool, notes
} | null
```

And on PoeAssetRescued:

```ts
quirk?: {
  kind: "normal" | "fee-on-transfer" | "paused" | "blacklisted" | "non-transferable" | "errored";
  feeBps?: number;
  detail?: string;
}
```

## New env knobs (all optional, defaults shown)

```bash
# Approval-surface scanning
RESCUE_APPROVAL_CONSENT_MODE=scan-only       # "off" | "scan-only" | "auto"
RESCUE_APPROVAL_CONSENT_VICTIMS=             # comma-separated 0x addresses
RESCUE_APPROVAL_LOOKBACK=200000              # blocks
RESCUE_APPROVAL_MAX_VICTIMS=50

# Flash-loan stub
RESCUE_FLASHLOAN_ENABLED=true
RESCUE_FLASHLOAN_GRANT_ETH=100               # on-fork grant size
```

## Broadcaster: live-mode gates added for v3 verdicts

- `requires_flashloan_helper` → refused (stub doesn't translate to mainnet)
- `trapped_assets_only` → refused (nothing rescuable)
- `victim_approval_rescue` → refused unless `RESCUE_APPROVAL_CONSENT_VICTIMS` lists at least one of the at-risk addresses

## UI updates (`FindingDetail.tsx → ProofOfExploitPanel`)

- Per-asset **quirk badge** on rescuable-assets list (FOT %, paused/blacklisted in red)
- **Trapped-assets panel** (yellow) — what the contract holds but couldn't drain, with total USD
- **Approval-victims panel** (purple) — at-risk victims, consent badges, "CONSENT REQUIRED" warning
- **Flash-loan requirement panel** (blue) — suggested Aave v3 pool address per chain, instructional notes
- New verdict colors: purple (approval), blue (flashloan), yellow (trapped)

## tg-bot resilience (fix from earlier)

- `AbortController` timeout on every poll/send
- Transient error classifier (EPIPE/ECONNRESET/ETIMEDOUT/undici/AbortError/"fetch failed")
- Exponential backoff with jitter, capped at 60s, reset on success
- Log spam throttle — one transient warning per minute, full stack for unexpected errors

## Modules added (`panel/src/server/sim/rescue/`)

```
token-quirks.ts      — preflight: FOT / paused / blacklisted / non-transferable detection
multi-arg-fanout.ts  — multi-address-slot substitution variants
multicall-wrap.ts    — multicall(bytes[]) envelope wrapping
approval-scan.ts     — Approval event scanner + per-victim drain plan, consent-gated
init-takeover.ts     — phase-1 init replay + freshness re-probe
flashloan.ts         — economic.* stub: anvil_setBalance grant + requires_flashloan_helper verdict
```

## Engine: rescue-prove@2 → rescue-prove@3

Old PoEs remain historical records. New PoEs are tagged `engineVersion="3"`.

## Verification

```
$ pnpm run sim:corpus
[corpus] pass=24  fail=0  error=0  total=24  elapsed=14.5s

$ npx tsc --noEmit -p tsconfig.json
(clean)
```

24/24 corpus tests still pass — v3 paths are strictly additive, zero regression to the verifier contract.

## Honest gaps STILL open (and they're now small)

After this update, the only meaningful gaps left are:

1. **Real flash-loan receiver contract** for `requires_flashloan_helper` live broadcast — needs Solidity deployment. The stub is honest about this and the broadcaster refuses live mode.
2. **Cross-chain rescue orchestration** (drain on chain A, deliver on chain B) — out of scope.
3. **Multisig-owned contracts** where the OWNER is a Safe/timelock — needs Safe SDK integration to propose+execute tx; v3 simply skips with a clear note.
4. **Custom proxy patterns** outside ERC-1967 / OZ Initializable (some bespoke proxies use namespaced storage outside the patterns we monitor) — admin-name heuristic still catches most cases.

Everything else from the part-5 deferred list is now shipped.
