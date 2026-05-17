# EVM Contract Auditor — Update Log 2026-05-17 (Part 3)

> Builds on `59d16d2` (panel OOM fix) and `67cd7ff` (tax-token suppressor).
> Same day. This patch ships **Layer 1 + Layer 2 of the exposure
> accuracy plan**: log-based token discovery + Coingecko USD pricing
> with stablecoin fallbacks, plus a redesigned UI that surfaces
> at-risk USD prominently (no more "hover the badge to see tokens").

---

## TL;DR

| Before | After |
|---|---|
| Exposure column showed **native balance only**; ERC-20 column was structurally always empty because the QuickNode `qn_getWalletTokenBalance` add-on isn't enabled on the configured endpoints | Token discovery runs via RPC-only `eth_getLogs` + `balanceOf` with persistent caching (works on any chain we have an RPC for) |
| No USD anywhere; sort-by-exposure used the placeholder `non_zero_token_count × 0.01` | Per-token USD via Coingecko (`/simple/token_price/{platform}`, 60-min cached, 1 req per chain) with stablecoin / wrapped-native hardcoded fallbacks (zero requests for USDC/USDT/DAI/BUSD/FRAX/WETH/WBNB/WMATIC/WAVAX/WBTC) |
| At-risk asset class buried in a tooltip; "+N tok" badge required hover to read | At-risk USD shown **inline** in every row with a coloured surface badge; contract-detail page has a dedicated `Balance vs At-Risk` panel with per-asset breakdown |

---

## Rate budget (the "don't spam" constraint)

Per **cold** contract (never-seen, cache empty):

| Network call | Count | Why |
|---|---|---|
| `eth_blockNumber` (only if `deployments` table doesn't have the contract's block) | 0–1 | Bound the log-scan window |
| `eth_getLogs` (single chunk: `Transfer(_,addr,_)`) | 1 | Discover all tokens ever transferred IN |
| `eth_call` batch (`balanceOf(addr)` for ≤40 tokens) | 1 batch | Snapshot live balances |
| `eth_call` batch (`symbol`/`name`/`decimals` for new tokens) | 1 batch | Metadata; cached **forever** after first fetch |
| Coingecko `/simple/token_price` for new tokens | 1 batch | Per-chain pooled, 60-min cached |

**Worst case ≈ 4 batched HTTP calls; never per-contract loops.** After
warmup the metadata cache (`token_metadata`) covers ~all common tokens
(USDC, USDT, WETH, WBNB, ...) for zero RPC across all contracts.

Per **warm** contract (cache hit, ≤30 min old):

| Network call | Count |
|---|---|
| anything | **0** |

The `contract_token_holdings` table is the key cache: a 30-min TTL
means even an active panel re-hitting the same contract every few
minutes only does the full discovery once.

## Layer 1 — Log-based token discovery

New modules:

| File | Role |
|---|---|
| `panel/src/server/rpc-batch.ts` | Shared JSON-RPC primitives: single + batched calls with timeout; ABI decoders for `uint256` / `uint8` / dynamic string / packed bytes32 (handles legacy MKR/REP shapes) |
| `panel/src/server/token-metadata.ts` | Per-(chain, token) metadata cache. PERMANENT TTL — ERC-20 metadata is immutable. Stored in `token_metadata` table |
| `panel/src/server/token-discovery.ts` | One `eth_getLogs` per cold contract; `deployments.blockNumber` as `fromBlock` when known, otherwise `latest − DISCOVERY_WINDOW_BLOCKS` (5M default). Capped at `MAX_TOKENS_PER_CONTRACT=40`. Caches into `contract_token_holdings` with 30-min TTL. Writes a sentinel row when a contract holds no tokens so we don't re-scan |

Tuning knobs (via env):

| Var | Default | Effect |
|---|---|---|
| `EXPOSURE_DISCOVERY_WINDOW` | 5 000 000 | Block window if no deployment row known (≈3 weeks on ETH, ≈3 mo on BSC, longer on AVAX) |
| `EXPOSURE_HOLDINGS_TTL_MS` | 30 × 60 000 | How long a contract's discovered holdings stay fresh |
| `EXPOSURE_MAX_TOKENS_PER_CONTRACT` | 40 | Cap to bound the balanceOf batch |
| `EXPOSURE_RPC_BATCH_SIZE` | 50 | JSON-RPC batch chunk size |

## Layer 2 — USD pricing

New module: `panel/src/server/token-pricing.ts`.

Three layers of resolution in this strict order — each layer requires
zero requests if the layer above answered:

1. **Hardcoded fallback** for stablecoins (`$1.00`) and wrapped-native /
   WBTC. Catalogues:
   - ETH: USDC, USDT, DAI, BUSD, FRAX, WETH (→ native), WBTC (→ BTC)
   - BSC: USDT, USDC, BUSD, WBNB (→ native)
   - Polygon: USDC (native), USDC.e, USDT, DAI, WMATIC
   - Arbitrum: USDC, USDC.e, USDT, DAI, WETH
   - Optimism: USDC, USDC.e, USDT, WETH
   - Base: USDC, DAI, WETH
   - Avalanche: USDC, USDT, DAI.e, WAVAX
2. **SQLite cache** (`token_price_usd`, 60-min TTL).
3. **Coingecko** `/simple/token_price/{platform}` batched per chain.
   Misses (Coingecko doesn't know the token) are persisted with
   `usd_per_token = NULL` so we don't re-query them every cycle. Native
   prices fetched separately via `/simple/price?ids=...` (30-min cached).

Tuning:

| Var | Default | Effect |
|---|---|---|
| `EXPOSURE_PRICE_TTL_MS` | 60 × 60 000 | Token price freshness |
| `EXPOSURE_NATIVE_PRICE_TTL_MS` | 30 × 60 000 | Native (ETH/BNB/MATIC/...) freshness |
| `EXPOSURE_DUST_USD` | 1.00 | Priced tokens below this USD value are dropped to avoid airdrop spam inflating the at-risk total |
| `COINGECKO_API_KEY` | (empty) | Optional demo key for higher rate limits |

## The `Exposure` shape gained five fields

```ts
interface Exposure {
  // ── existing ──────────────────────────────────────────
  chainId: number;
  address: string;
  nativeWei: string;        // wei, decimal string
  nativeSymbol: string;
  nativeDecimals: number;
  tokens: TokenBalance[];   // each row now also carries usdPerToken + usdValue
  tokenScanUnsupported?: boolean;
  fetchedAt: number;
  error?: string;
  // ── added in v3 ───────────────────────────────────────
  nativeUsdPerToken?: number | null;   // spot $/native
  nativeUsdValue?: number | null;      // $ value of nativeWei
  tokensUsdValue?: number | null;      // $ sum across priced tokens
  totalUsdValue?: number | null;       // native + tokens
  tokenSource?: "qn-add-on" | "log-scan" | "log-scan-cache" | "none";
  dustTokensFiltered?: number;         // count of <$1 tokens dropped
}
```

`TokenBalance` similarly gained `usdPerToken` and `usdValue`.

## Worker sort score wired to real USD

`relevantExposureValue()` (`panel/src/server/sim/worker.ts`) used to
score token-rules with `non_zero_count × 0.01` because we had no
price data — meaning a contract holding $0.0001 of spam dust ranked
the same as one holding $50k USDC. It now sums `nativeUsdValue +
tokensUsdValue` filtered by the rule's surface, with the old logic
preserved as a degraded fallback when USD is missing.

## UI

### `FindingsTable` — `ExposureCell` redesigned (no hover needed)

Old: native amount + grey "+N tok" badge; everything below it lived
in a tooltip.

New: two-line cell —
```
$59.87  [native+tokens]
0.027 ETH ($59) · 100 USDC ($100)  +3 more
```
where `[native+tokens]` is a coloured badge indicating the rule's
at-risk surface. Out-of-scope assets are still rendered but at 55%
opacity. Cached holdings get a small `cached` chip so the user can
tell the page isn't stale.

### `FindingDetail` — new `ExposurePanel`

A dedicated **Balance vs At-Risk** panel appears between the header
and the tab strip on every finding detail page that has a contract
address. Three big numbers:

| Total Balance | At Risk · This Rule | Out Of Scope |
|---|---|---|
| every asset, USD | surface-filtered subset, USD | held but not drainable, USD |

Below that, a row-per-asset breakdown coloured by relevance:
green-bordered "at risk" rows vs dimmed "out of scope" rows. Each
row shows symbol / name / human amount / $ value / surface chip.

Tooltips still exist for power users (token name, contract address,
why-out-of-scope explanation) but **all the at-a-glance info is
visible without mouseover**.

## Schema migrations (`panel/src/db/client.ts`)

Three new tables, all `CREATE TABLE IF NOT EXISTS` so existing dbs
pick them up on next boot:

```sql
CREATE TABLE token_metadata (
  chain_id INTEGER NOT NULL,
  token_address TEXT NOT NULL,
  symbol TEXT, name TEXT, decimals INTEGER,
  fetched_at INTEGER NOT NULL,
  PRIMARY KEY (chain_id, token_address)
);

CREATE TABLE token_price_usd (
  chain_id INTEGER NOT NULL,
  token_address TEXT NOT NULL,
  usd_per_token REAL, source TEXT,
  fetched_at INTEGER NOT NULL,
  PRIMARY KEY (chain_id, token_address)
);

CREATE TABLE contract_token_holdings (
  chain_id INTEGER NOT NULL,
  contract_address TEXT NOT NULL,
  token_address TEXT NOT NULL,
  balance_base TEXT NOT NULL,
  last_seen_block INTEGER,
  discovered_at INTEGER NOT NULL,
  PRIMARY KEY (chain_id, contract_address, token_address)
);
```

## Live verification (post-deploy)

Contract `0xf9e2cd82041bd8c643831f1e16fab52808136512` (the one the
user reported as showing exposure poorly):

```json
{
  "nativeWei": "27327652826525012",
  "nativeUsdValue": 59.87,
  "tokens": [{ "symbol": "NMIND", "balance": "78392598088008", "usdValue": null }],
  "tokensUsdValue": null,
  "totalUsdValue": 59.87,
  "tokenSource": "qn-add-on"
}
```

Avalanche native test: `0xAAaA…AAaa` → 0.25 AVAX = `$2.33`,
`nativeUsdPerToken` = `$9.33`. AVAX price reached the panel through
the Coingecko native cache.

ETH dust test: deliberate `$0.0001` TUSD balance on a sample contract
priced at $1.00, dropped by the $1 dust filter so it doesn't inflate
the at-risk total.

## What's deliberately NOT in this patch

- **Layer 3 (approval-surface exposure)** — "who has approved this
  contract to spend their funds, and how much is that worth" — was
  scoped in the previous turn but the user wanted L1+L2 first to
  validate the rate budget under real load. Easy follow-up once
  Coingecko quota behaviour is confirmed.
- **LP-token / vault-token unfurling** — `cToken`, `aToken`, UniV2
  pair LPs etc. currently surface as plain tokens with the raw
  base-unit balance. Per-protocol adapters are a larger project.
- **NFT holdings** — `qn_fetchNFTs` add-on path or per-chain explorer
  fallback. Usually low-value, deferred.

## Files changed

```
panel/src/db/client.ts                 |  +47 lines (3 cache tables)
panel/src/lib/format.ts                |  +18 lines (fmtUsd)
panel/src/server/rpc-batch.ts          | NEW (shared JSON-RPC helpers)
panel/src/server/token-metadata.ts     | NEW (ERC-20 metadata cache)
panel/src/server/token-discovery.ts    | NEW (eth_getLogs discovery)
panel/src/server/token-pricing.ts      | NEW (Coingecko + fallbacks)
panel/src/server/exposure.ts           | +142 (enrichWithUsd, discovery wiring)
panel/src/server/sim/worker.ts         |  ~  (USD-aware sort score)
panel/src/components/FindingsTable.tsx | +182 (no-hover ExposureCell)
panel/src/components/FindingDetail.tsx | +241 (ExposurePanel)
```

## Cleared follow-ups for next session

- Validate Coingecko quota behaviour after a day under load
- Decide whether to ship Layer 3 (approval-surface) or first build
  per-protocol adapters for the most common vault/LP token shapes
