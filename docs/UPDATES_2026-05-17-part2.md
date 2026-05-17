# EVM Contract Auditor — Update Log 2026-05-17 (Part 2)

> Patch on top of `12197ab feat(sim): economic-attack verifier + sidecar
> pipeline + regression corpus`. Same day, addresses a high-rate
> false-positive class observed in production immediately after the v2
> ship.

---

## TL;DR

The router+swap **static-evidence** path of the economic-attack verifier
was over-firing on the entire long tail of UniV2 fee-on-transfer "tax
tokens" (Pinksale / ttken template family). The dynamic verifier
correctly observed zero AMM hits across all candidates in those
contracts — the router-swap selector is hardcoded in the bytecode but
the call lives inside `_transfer()` and is only reachable from internal
ERC20 paths, not from any attacker-callable surface.

**Effect of the over-firing in the user's DB at the time of the patch:**
21 of 24 sidecar findings (~88%) were tax-token FPs.

This patch ships **`anvil-fork-economic@3`** with a tax-token-shape
suppressor, retires the stale FPs in the user's DB, and adds two new TN
anchors to the regression corpus to prevent recurrence.

---

## What changed

### 1. `anvil-fork-economic@3` — tax-token shape suppressor

`panel/src/server/sim/exploits/economic-attack.ts`. New constant
`TAX_TOKEN_NAME_SIGNATURES` enumerates ~70 distinctive UniV2 tax-token
template names across these categories:

| Category | Examples |
|---|---|
| Tax / threshold getters | `_maxTaxSwap`, `_taxSwapThreshold`, `_maxTxAmount`, `_maxWalletSize`, `_buyTax`, `_sellTax`, `_reduceBuyTaxAt`, `_initialBuyTax`, `_finalSellTax` |
| Trading toggles | `openTrading`, `enableTrading`, `startTrading`, `startUnitrade`, `setLaunched`, `launch`, `tradingActive`, `tradingOpen` |
| Limit removers | `removeLimits`, `removeAllLimits`, `removeTransferTax`, `removeAllTransferTax`, `transferDelayEnabled` |
| Manual helpers | `manualSwap`, `manualSend` |
| Bot management | `delBots`, `delBot2`, `addBots`, `addBot2`, `isBot`, `isaBot`, `addbBot`, `blackList`, `removeBlackList`, `manageList`, `exileW_Restriction` |
| Stuck-funds rescues | `clearStuckEth`, `freeStuckEth`, `rescueETH`, `rescueToken`, `claimStuckTokens`, `withdrawStuckEthBalance` |
| Misc tax-token | `reduceFee`, `setFee`, `setTax`, `createPair`, `marketPair`, `uniswapV2Pair`, `uniswapV2Router` |
| Late-2025 CA-throttle meta | `caCount`, `caLimit`, `caBlockLimit`, `caToggle`, `noTokenLimit` |

Gate: if **≥ 2** of these names appear in the resolved candidate set
AND `signatureKind === "router+swap"`, the verifier returns
`not_exploitable` with a verdict explaining that the tax-token swap
lives in `_transfer()` and is not externally exploitable.

`signatureKind === "pair-direct"` is **unaffected** — tax tokens don't
call `pair.sync()` / `skim()` / `burn(addr)` / `mint(addr)`. Pair-direct
remains high-precision and continues to catch the Movie Token / KP3R
deflationary-burn family.

Engine bump: `2 → 3`. Cache entries from `@2` were invalidated.

### 2. Discriminator validation against the corpus

| Contract | Type | Candidate name pattern | New verdict |
|---|---|---|---|
| `0x91334d03…aeb1` (GPC/MSC, BSC) | **TP** (real exploit) | `getReferral`, `joinTime`, `unstakeTime`, `getUserVip`, `releaseReward`, `V3`, `V4`, `LEVEL_1` — staking / game shape, **0 tax-template hits** | `verified` (unchanged) ✓ |
| `0xb32979f3…4c18` (MT, BSC) | **TP** (real exploit, pair-direct) | `mtManagerAddr`, `includeMultipleAccountsInFee`, `feeProcessingThreshold`, `disableTrading` — DeFi mining shape, fires via pair-direct not router+swap | `verified` (unchanged) ✓ |
| `0xf9e2cd82…6512` (user-reported FP, ETH) | **TN** (tax token) | `_maxTaxSwap`, `startunitrade`, `clearstucketh`, `_maxTxAmount`, `_maxWalletSize`, `_taxSwapThreshold`, `notokenlimit`, `transferDelayEnabled` — **7 tax-template hits ≥ 2** | `not_exploitable` (was `verified` under @2) ✓ |

### 3. Two new TN anchors in the corpus

`panel/src/server/sim/__corpus__/cases.json`:

| ID | Address | What it asserts |
|---|---|---|
| `econ-eth-tax-token-f9e2cd82-tn` | `0xf9e2cd82…6512` | `not_exploitable` + `verdictContains: "tax-token shape"`. Template hits: `_maxTaxSwap, startunitrade, clearstucketh, _maxTxAmount, _maxWalletSize, _taxSwapThreshold, notokenlimit, transferDelayEnabled`. |
| `econ-eth-tax-token-1983ceca-tn` | `0x1983ceca…2f5a` | `not_exploitable` + `verdictContains: "tax-token shape"`. Different template variant: `_maxTaxSwap, isaBot, addbBot, manualSwap, _maxTxAmount, resERC20, openTrading, removeAllTransferTax`. |

Corpus now runs **23/23 PASS** in both default and
`SIM_FEATURE_STATEDIFF=true` modes (~19s).

### 4. DB cleanup (one-off, applied in the user's panel)

Not part of this commit, but worth recording for tracking:

```sql
-- Demote the 25 retired tax-token FPs to info/not_exploitable so the
-- UI stops shouting "critical". Severity, status, simulation_status,
-- title, simulation_engine all updated; simulation_verdict appended
-- with a [SUPERSEDED] tag for audit trail.
UPDATE findings
SET severity = 'info',
    status = 'not_a_vulnerability',
    simulation_status = 'not_exploitable',
    simulation_engine = 'anvil-fork-economic@2->3-retired',
    simulation_verdict = simulation_verdict || ' [SUPERSEDED by ' ||
      'anvil-fork-economic@3: tax-token shape suppressor — see ' ||
      'TAX_TOKEN_NAME_SIGNATURES]',
    title = 'Suppressed: tax-token (UniV2 fee-on-transfer) — not ' ||
            'exploitable [anvil-fork-economic@3]'
WHERE source = 'sidecar-economic-attack'
  AND simulation_evidence_json LIKE '%"staticSignatureKind":"router+swap"%'
  AND simulation_status = 'verified';
-- 25 rows demoted

DELETE FROM simulation_cache
WHERE engine = 'anvil-fork-economic' AND engine_version = '2';
-- 44 rows invalidated; next sweep will rerun under @3
```

After cleanup: 25 retired findings (severity=info, sim=not_exploitable);
3 legitimate verified TPs remain (GPC/MSC + 2 pair-direct).

---

## Why not just lower confidence on static evidence

Considered and rejected. The 88% FP rate isn't a confidence problem —
it's a wrong-class problem. Tax tokens are fundamentally NOT exploitable
via the GPC/MSC bug class, so the right verdict is `not_exploitable`,
not "low-confidence verified". Lowering confidence would still leave
them surfaced as findings, still scoring against the bytecode-similarity
clusters used by the UI, and still costing operator review time.

The name-based suppressor is what discriminates the class, and the GPC/MSC
TP proves the discriminator: that contract has 23 of 24 candidates
clean-executing without reaching the swap (same numeric shape as a tax
token) but **zero** tax-template name hits. Names ARE the signal.

---

## Tuning knobs

| Constant | File | Default | Purpose |
|---|---|---|---|
| `TAX_TOKEN_NAME_SIGNATURES` | `economic-attack.ts` | ~70 names | The suppressor's vocabulary. Extend as new tax-token template variants emerge. |
| `TAX_TOKEN_HIT_THRESHOLD` | `economic-attack.ts` | `2` | How many distinct template names must match. Set higher to be more permissive (more FPs surface). |

---

## Anchor commit

This update: see git log of `main` after this push. The previous update
log lives at `docs/UPDATES_2026-05-17.md`.
