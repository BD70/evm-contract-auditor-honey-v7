# Updates — 2026-05-17 (part 7): rescue-prove@4 — Safe multisig, bespoke proxy slots, flash-loan receiver

## Summary

Closes the three remaining honest gaps from part-6:

1. **Safe / timelock multisig integration** — when the contract owner is a Safe, rescue-prove no longer claims success; it emits `requires_safe_signing` verdict with a working deeplink to the Safe app's Transaction Builder. Broadcaster refuses live mode with actionable instructions.
2. **Bespoke proxy storage layouts** — `RESCUE_EXTRA_ADMIN_SLOTS` env var lets operators list custom storage slots; rescue-prove reads each on the fork and surfaces probable owner addresses in PoE notes.
3. **Flash-loan receiver wiring** — when `RESCUE_FLASHLOAN_RECEIVER=chainId:0xaddr,...` is configured, the broadcaster can route `requires_flashloan_helper` PoEs through the deployed receiver's `executeRescue(...)`. Ships a reference Solidity contract `contracts/rescue/FlashLoanRescue.sol` operators can deploy themselves.

## What's new

### New PoE verdict

```
requires_safe_signing  // owner is a Safe; rescue must be proposed through the Safe app
```

### New PoE field

```ts
safeRequirement?: {
  safeAddress: string;
  chainShortName: string | null;
  threshold: number | null;
  ownerCount: number | null;
  appDeeplink: string | null;     // ready-to-click Safe app URL
  txServiceEndpoint: string | null; // for programmatic proposal in v5
  instructions: string[];
} | null
```

### New modules (`panel/src/server/sim/rescue/`)

```
safe-tx.ts            — Safe detection + per-chain Transaction Service endpoints +
                        Transaction Builder deeplink generator
extra-admin-slots.ts  — env-driven bespoke proxy storage slot reader
flashloan-receiver.ts — registry parser for RESCUE_FLASHLOAN_RECEIVER env
```

### Reference Solidity (`contracts/rescue/FlashLoanRescue.sol`)

Minimal Aave v3 simple-flash-loan receiver. ~140 LoC. Deploy per chain, then register the address. No external deps. Operators own the deployment lifecycle (we don't ship a `forge create` automation in v4 — keeps the panel deploy-free).

### Broadcaster updates

- **`requires_safe_signing`** → refuses live with deeplink + multisig metadata
- **`requires_flashloan_helper`** → refuses live unless `RESCUE_FLASHLOAN_RECEIVER` is set for the chain. When configured, routes the entire drain plan through a single `executeRescue(address,uint256,address[],bytes[],uint256[],address)` call (selector `0xfe5d0181`)
- New `liveFlashloanBroadcast()` function handles the receiver-routed path

### UI (FindingDetail.tsx → ProofOfExploitPanel)

- New teal verdict color for `requires_safe_signing`
- New **Safe multisig panel** with threshold badge, Safe address, and an **"Open in Safe app"** button that links straight to the Transaction Builder for the right chain

### env knobs (added to `.env.example` and live `.env`)

```bash
# v4: real flash-loan receiver contracts (one per chain you've deployed to)
RESCUE_FLASHLOAN_RECEIVER=1:0xreceiver1,8453:0xreceiver2
# v4: extra storage slots to probe for owner on bespoke proxy layouts
RESCUE_EXTRA_ADMIN_SLOTS=0x...,0x...
# v4: override the default Safe Transaction Service base URL
RESCUE_SAFE_TX_SERVICE_URL=
```

## Engine: rescue-prove@3 → rescue-prove@4

## Verification

```
$ pnpm run sim:corpus
[corpus] pass=24  fail=0  error=0  total=24  elapsed=13.5s

$ npx tsc --noEmit
(clean)
```

## What's still open (honest)

- **Programmatic Safe proposal POST** — currently we generate the deeplink; v5 could sign + POST to the tx-service with a proposer key
- **Flash-loan receiver deployment automation** — operator deploys with `forge create` (we ship the .sol)
- **Cross-chain rescue** — still out of scope; rescue is single-chain
- **Receiver borrow-asset hardcoding** — `liveFlashloanBroadcast` currently passes zero-address as the borrow asset, expecting the deployed receiver to default to WETH. v5 will plumb per-chain WETH addresses through the encoded args.
