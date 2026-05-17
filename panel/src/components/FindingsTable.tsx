"use client";

import {
  Badge,
  Box,
  Button,
  HStack,
  Heading,
  Input,
  NativeSelect,
  Stack,
  Table,
  Text,
} from "@chakra-ui/react";
import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { fmtAge, fmtNativeAmount, fmtTokenAmount, fmtUsd, shortHash, SEVERITY_COLORS } from "@/src/lib/format";
import { CHAINS, chainName } from "@/src/lib/chains";
import { explorerAddressUrl } from "@/src/lib/chain-meta";

interface TokenBalance {
  address: string;
  symbol: string;
  name: string;
  decimals: number;
  balance: string;
  usdPerToken?: number | null;
  usdValue?: number | null;
}

interface Exposure {
  chainId: number;
  address: string;
  nativeWei: string;
  nativeSymbol: string;
  nativeDecimals: number;
  tokens: TokenBalance[];
  tokenScanUnsupported?: boolean;
  error?: string;
  nativeUsdPerToken?: number | null;
  nativeUsdValue?: number | null;
  tokensUsdValue?: number | null;
  totalUsdValue?: number | null;
  tokenSource?: "qn-add-on" | "log-scan" | "log-scan-cache" | "none";
  dustTokensFiltered?: number;
}

function exposureKey(chainId: number | null | undefined, address: string | null | undefined): string | null {
  if (chainId == null || !address) return null;
  return `${chainId}:${address.toLowerCase()}`;
}

/** Sum the USD value at risk given the rule's surface. Surface-aware:
 *   native → nativeUsdValue
 *   token  → tokensUsdValue
 *   both   → both
 *   none   → 0 */
function usdAtRiskForSurface(exp: Exposure, surface: "native" | "token" | "both" | "none"): number | null {
  if (surface === "none") return 0;
  let v = 0;
  let any = false;
  if (surface === "native" || surface === "both") {
    if (exp.nativeUsdValue != null) { v += exp.nativeUsdValue; any = true; }
  }
  if (surface === "token" || surface === "both") {
    if (exp.tokensUsdValue != null) { v += exp.tokensUsdValue; any = true; }
  }
  return any ? v : null;
}

/**
 * ExposureCell — surface-aware, $-denominated, no-hover-required.
 *
 * Layout per row:
 *   ┌──────────────────────────────────────────────────────────────────────┐
 *   │ AT-RISK $X · [native|token|both badge]                               │
 *   │ ◦ 0.12 ETH ≈ $260   ◦ 1,200 USDC ≈ $1,200   +3 more                  │
 *   └──────────────────────────────────────────────────────────────────────┘
 *
 * For a `selfdestruct.unguarded` finding the ERC-20s are shown but the
 * "AT-RISK" total only counts the native portion, and irrelevant rows
 * are visually de-emphasised — preserving the at-a-glance honesty the
 * previous tooltip-only design lacked.
 */
function ExposureCell({
  exp,
  loading,
  surface,
}: {
  exp: Exposure | undefined;
  loading: boolean;
  surface: "native" | "token" | "both" | "none";
}) {
  if (loading && !exp) {
    return <Text fontSize="xs" color="fg.muted">…</Text>;
  }
  if (!exp) {
    return <Text fontSize="xs" color="fg.muted">—</Text>;
  }
  if (exp.error) {
    return <Text fontSize="xs" color="fg.muted" title={exp.error}>n/a</Text>;
  }

  const nativeRelevant = surface === "native" || surface === "both";
  const tokenRelevant = surface === "token" || surface === "both";
  const atRisk = usdAtRiskForSurface(exp, surface);
  const hasNative = exp.nativeWei && exp.nativeWei !== "0";
  const tokens = exp.tokens ?? [];
  const top = tokens.slice(0, 2);
  const more = Math.max(0, tokens.length - top.length);

  // Surface label badge: makes the rule's at-risk asset class IMPOSSIBLE to miss.
  const surfaceLabel =
    surface === "native" ? "native" :
    surface === "token"  ? "tokens" :
    surface === "both"   ? "native+tokens" :
    "none";
  const surfaceColor =
    surface === "none" ? "gray" :
    surface === "native" ? "blue" :
    surface === "token" ? "purple" :
    "orange";

  return (
    <Stack gap="0.5" minW="180px">
      <HStack gap="2" align="center">
        <Text fontSize="sm" fontFamily="mono" fontWeight="semibold" whiteSpace="nowrap">
          {atRisk == null ? "—" : fmtUsd(atRisk)}
        </Text>
        <Badge size="xs" variant="subtle" colorPalette={surfaceColor} title={`Rule surface: ${surfaceLabel}`}>
          {surfaceLabel}
        </Badge>
        {exp.tokenSource === "log-scan-cache" && (
          <Badge size="xs" variant="outline" colorPalette="gray" title="Holdings served from the 30-min cache">cached</Badge>
        )}
      </HStack>
      <HStack gap="2" align="center" flexWrap="wrap" rowGap="0.5">
        {hasNative && (
          <Text
            fontSize="2xs"
            fontFamily="mono"
            color={nativeRelevant ? "fg" : "fg.muted"}
            opacity={nativeRelevant ? 1 : 0.55}
            whiteSpace="nowrap"
            title={nativeRelevant ? `Native ${exp.nativeSymbol} at risk` : `Native ${exp.nativeSymbol} — informational only for this rule`}
          >
            {fmtNativeAmount(exp.nativeWei, exp.nativeSymbol, exp.nativeDecimals)}
            {exp.nativeUsdValue != null && (
              <Text as="span" color="fg.muted" ml="1">({fmtUsd(exp.nativeUsdValue)})</Text>
            )}
          </Text>
        )}
        {top.map((t) => (
          <Text
            key={t.address}
            fontSize="2xs"
            fontFamily="mono"
            color={tokenRelevant ? "fg" : "fg.muted"}
            opacity={tokenRelevant ? 1 : 0.55}
            whiteSpace="nowrap"
            title={`${t.name} (${t.address})${t.usdValue != null ? ` — ${fmtUsd(t.usdValue)}` : ""}`}
          >
            {fmtTokenAmount(t.balance, t.decimals)} {t.symbol}
            {t.usdValue != null && (
              <Text as="span" color="fg.muted" ml="1">({fmtUsd(t.usdValue)})</Text>
            )}
          </Text>
        ))}
        {more > 0 && (
          <Badge size="xs" variant="outline" colorPalette={tokenRelevant ? "purple" : "gray"}
            title={tokens.slice(2, 12).map((t) => `${fmtTokenAmount(t.balance, t.decimals)} ${t.symbol}${t.usdValue != null ? ` (${fmtUsd(t.usdValue)})` : " (unpriced)"}`).join("\n")}>
            +{more} more
          </Badge>
        )}
        {tokens.length === 0 && !hasNative && (
          <Text fontSize="2xs" color="fg.muted">no balance</Text>
        )}
      </HStack>
      {exp.dustTokensFiltered && exp.dustTokensFiltered > 0 ? (
        <Text fontSize="2xs" color="fg.muted" title={`${exp.dustTokensFiltered} priced token(s) below the dust threshold were filtered`}>
          {exp.dustTokensFiltered} dust filtered
        </Text>
      ) : null}
    </Stack>
  );
}

interface Row {
  id: string;
  runId: string | null;
  ruleId: string;
  severity: string;
  status: string | null;
  title: string | null;
  contractAddress: string | null;
  chainId: number | null;
  blockNumber: number | null;
  discoveredAt: number;
  source: string;
  judgeVerdict: string | null;
  simulationStatus: string | null;
  simulationVerdict: string | null;
  simulationEngine: string | null;
  simulatedAt: number | null;
  /** "any" (anyone can call) | "owner" (only owner can) | null */
  simulationAttackerKind: "any" | "owner" | null;
  /** which value-types this rule puts at risk: native, token, both, none */
  ruleExposureSurface: "native" | "token" | "both" | "none";
  /** True if owner can call an INTENDED admin function (rescueFunds, withdrawETH, ...);
   *  this is centralisation risk, not an exploit. */
  simulationCentralizationRisk?: boolean;
}

const SIM_COLORS: Record<string, string> = {
  verified: "red",
  not_exploitable: "green",
  inconclusive: "yellow",
  skipped: "gray",
  error: "orange",
};

const SIM_LABEL: Record<string, string> = {
  verified: "exploitable",
  not_exploitable: "FP",
  inconclusive: "?",
  skipped: "n/a",
  error: "err",
};

/**
 * ContractAddressCell — renders the contract's short hash with a one-click
 * deep-link to the chain's canonical block explorer (Etherscan / BscScan /
 * PolygonScan / etc). The whole cell is clickable; the external-link arrow
 * makes the affordance obvious without taking more horizontal space.
 *
 * When the chain has no configured explorer (or the address is missing),
 * we degrade to the plain mono short hash so the column stays consistent.
 */
function ContractAddressCell({
  chainId,
  address,
}: {
  chainId: number | null;
  address: string | null;
}) {
  const url = explorerAddressUrl(chainId, address);
  if (!url || !address) {
    return (
      <Text fontSize="xs" fontFamily="mono">
        {shortHash(address)}
      </Text>
    );
  }
  return (
    <Text
      fontSize="xs"
      fontFamily="mono"
      color="blue.fg"
      _hover={{ textDecoration: "underline", color: "blue.solid" }}
      title={`Open ${address} on block explorer (new tab)`}
    >
      <a
        href={url}
        target="_blank"
        rel="noopener noreferrer"
        onClick={(e) => e.stopPropagation()}
      >
        {shortHash(address)} ↗
      </a>
    </Text>
  );
}

function SimCell({ row }: { row: Row }) {
  const s = row.simulationStatus;
  if (!s) {
    return (
      <Text fontSize="2xs" color="fg.muted">
        queued
      </Text>
    );
  }
  // OWNER-ONLY: treat as its own visual badge — it's still verified-exploitable
  // but only by the owner, so we colour it orange to distinguish from
  // "anyone can drain this" (solid red) and "false positive" (green).
  // This is the difference between "the owner can rug" and "anybody can rug".
  if (s === "verified" && row.simulationAttackerKind === "owner") {
    const title = [row.simulationVerdict, row.simulationEngine].filter(Boolean).join(" — ");
    return (
      <Badge size="xs" variant="solid" colorPalette="orange" title={title}>
        owner-only
      </Badge>
    );
  }
  const color = SIM_COLORS[s] ?? "gray";
  const label = SIM_LABEL[s] ?? s;
  const title = [row.simulationVerdict, row.simulationEngine].filter(Boolean).join(" — ");
  return (
    <Badge size="xs" variant={s === "verified" ? "solid" : "subtle"} colorPalette={color} title={title}>
      {label}
    </Badge>
  );
}

const SEVERITIES = ["critical", "high", "medium", "low", "info"];

export function FindingsTable() {
  const [rows, setRows] = useState<Row[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const limit = 50;
  const [search, setSearch] = useState("");
  const [sevFilter, setSevFilter] = useState<string[]>([]);
  const [source, setSource] = useState<string>("");
  const [chainId, setChainId] = useState<string>("");
  const [simFilter, setSimFilter] = useState<string[]>([]);

  const query = useMemo(() => {
    const p = new URLSearchParams();
    p.set("limit", String(limit));
    p.set("offset", String(offset));
    if (search) p.set("q", search);
    if (sevFilter.length) p.set("severity", sevFilter.join(","));
    if (source) p.set("source", source);
    if (chainId) p.set("chainId", chainId);
    if (simFilter.length) p.set("simStatus", simFilter.join(","));
    return p.toString();
  }, [search, sevFilter, source, chainId, simFilter, offset]);

  const [exposures, setExposures] = useState<Record<string, Exposure>>({});
  const [exposureLoading, setExposureLoading] = useState(false);

  useEffect(() => {
    let alive = true;
    fetch(`/api/findings?${query}`)
      .then((r) => r.json())
      .then((j) => {
        if (!alive) return;
        setRows(j.rows ?? []);
        setTotal(j.total ?? 0);
      });
    return () => {
      alive = false;
    };
  }, [query]);

  // After rows load, batch-fetch exposure (native + ERC-20 balances via
  // QuickNode's qn_getWalletTokenBalance) for every unique (chainId, address).
  // The server-side endpoint caches for 5 minutes so this is cheap on reload.
  useEffect(() => {
    if (rows.length === 0) return;
    const seen = new Set<string>();
    const items: { chainId: number; address: string }[] = [];
    for (const r of rows) {
      if (r.chainId == null || !r.contractAddress) continue;
      const k = `${r.chainId}:${r.contractAddress.toLowerCase()}`;
      if (seen.has(k)) continue;
      seen.add(k);
      items.push({ chainId: r.chainId, address: r.contractAddress });
    }
    if (items.length === 0) return;
    let alive = true;
    setExposureLoading(true);
    fetch("/api/exposure", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ items }),
    })
      .then((r) => (r.ok ? r.json() : { exposures: {} }))
      .then((j) => {
        if (!alive) return;
        setExposures((prev) => ({ ...prev, ...(j.exposures ?? {}) }));
      })
      .catch(() => {})
      .finally(() => {
        if (alive) setExposureLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [rows]);

  useEffect(() => {
    const es = new EventSource("/api/findings/stream");
    es.addEventListener("finding", () => {
      if (offset === 0) {
        fetch(`/api/findings?${query}`)
          .then((r) => r.json())
          .then((j) => {
            setRows(j.rows ?? []);
            setTotal(j.total ?? 0);
          });
      }
    });
    return () => es.close();
  }, [query, offset]);

  return (
    <Stack gap="4">
      <Heading size="lg">Findings</Heading>
      <HStack gap="2" wrap="wrap">
        <Input
          placeholder="search title / rule / address / hash"
          size="sm"
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setOffset(0);
          }}
          maxW="320px"
        />
        <HStack gap="1">
          {SEVERITIES.map((s) => (
            <Button
              key={s}
              size="xs"
              variant={sevFilter.includes(s) ? "solid" : "subtle"}
              colorPalette={SEVERITY_COLORS[s]}
              onClick={() => {
                setSevFilter((cur) =>
                  cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s],
                );
                setOffset(0);
              }}
            >
              {s}
            </Button>
          ))}
        </HStack>
        <HStack gap="1">
          {["", "runner", "manual"].map((src) => (
            <Button
              key={src || "any"}
              size="xs"
              variant={source === src ? "solid" : "subtle"}
              onClick={() => {
                setSource(src);
                setOffset(0);
              }}
            >
              {src || "any source"}
            </Button>
          ))}
        </HStack>
        <HStack gap="1">
          {[
            { key: "verified", label: "exploitable", color: "red" },
            { key: "not_exploitable", label: "FP", color: "green" },
            { key: "inconclusive", label: "?", color: "yellow" },
            { key: "unverified", label: "queued", color: "gray" },
          ].map((opt) => (
            <Button
              key={opt.key}
              size="xs"
              variant={simFilter.includes(opt.key) ? "solid" : "subtle"}
              colorPalette={opt.color}
              onClick={() => {
                setSimFilter((cur) =>
                  cur.includes(opt.key) ? cur.filter((x) => x !== opt.key) : [...cur, opt.key],
                );
                setOffset(0);
              }}
            >
              {opt.label}
            </Button>
          ))}
        </HStack>
        <NativeSelect.Root size="sm" w="200px">
          <NativeSelect.Field
            value={chainId}
            onChange={(e) => {
              setChainId(e.target.value);
              setOffset(0);
            }}
          >
            <option value="">any chain</option>
            {CHAINS.map((c) => (
              <option key={c.id} value={String(c.id)}>
                {c.name}
              </option>
            ))}
          </NativeSelect.Field>
          <NativeSelect.Indicator />
        </NativeSelect.Root>
        <Text fontSize="xs" color="fg.muted" ml="auto">
          {total} findings
        </Text>
      </HStack>

      <Box bg="bg.panel" rounded="lg" border="1px solid" borderColor="border" overflowX="auto">
        <Table.Root size="sm">
          <Table.Header>
            <Table.Row>
              <Table.ColumnHeader>Severity</Table.ColumnHeader>
              <Table.ColumnHeader>Title</Table.ColumnHeader>
              <Table.ColumnHeader>Rule</Table.ColumnHeader>
              <Table.ColumnHeader>Contract</Table.ColumnHeader>
              <Table.ColumnHeader>Verify</Table.ColumnHeader>
              <Table.ColumnHeader>Exposure</Table.ColumnHeader>
              <Table.ColumnHeader>Chain</Table.ColumnHeader>
              <Table.ColumnHeader>Block</Table.ColumnHeader>
              <Table.ColumnHeader>When</Table.ColumnHeader>
              <Table.ColumnHeader>Source</Table.ColumnHeader>
              <Table.ColumnHeader>Judge</Table.ColumnHeader>
            </Table.Row>
          </Table.Header>
          <Table.Body>
            {rows.map((r) => (
              <Table.Row
                key={r.id}
                cursor="pointer"
                _hover={{ bg: "bg.muted" }}
                onClick={() => (window.location.href = `/findings/${r.id}`)}
              >
                <Table.Cell>
                  <Badge colorPalette={SEVERITY_COLORS[r.severity] ?? "gray"} variant="subtle" size="sm">
                    {r.severity}
                  </Badge>
                </Table.Cell>
                <Table.Cell maxW="320px">
                  <Text fontSize="sm" lineClamp={1}>
                    {r.title ?? r.ruleId}
                  </Text>
                </Table.Cell>
                <Table.Cell>
                  <Text fontSize="xs" fontFamily="mono">
                    {r.ruleId}
                  </Text>
                </Table.Cell>
                <Table.Cell>
                  <ContractAddressCell chainId={r.chainId} address={r.contractAddress} />
                </Table.Cell>
                <Table.Cell>
                  <SimCell row={r} />
                </Table.Cell>
                <Table.Cell>
                  <ExposureCell
                    exp={
                      exposureKey(r.chainId, r.contractAddress)
                        ? exposures[exposureKey(r.chainId, r.contractAddress)!]
                        : undefined
                    }
                    loading={exposureLoading}
                    surface={r.ruleExposureSurface ?? "both"}
                  />
                </Table.Cell>
                <Table.Cell>
                  <Text fontSize="xs">{chainName(r.chainId)}</Text>
                </Table.Cell>
                <Table.Cell>
                  <Text fontSize="xs">{r.blockNumber ?? "—"}</Text>
                </Table.Cell>
                <Table.Cell>
                  <Text fontSize="xs" color="fg.muted">
                    {fmtAge(r.discoveredAt)}
                  </Text>
                </Table.Cell>
                <Table.Cell>
                  <Badge variant="subtle" size="xs">
                    {r.source}
                  </Badge>
                </Table.Cell>
                <Table.Cell>
                  {r.judgeVerdict ? (
                    <Badge size="xs" variant="outline">
                      {r.judgeVerdict}
                    </Badge>
                  ) : (
                    <Text fontSize="xs" color="fg.muted">
                      —
                    </Text>
                  )}
                </Table.Cell>
              </Table.Row>
            ))}
            {rows.length === 0 && (
              <Table.Row>
                <Table.Cell colSpan={11}>
                  <Text fontSize="sm" color="fg.muted" textAlign="center" py="6">
                    no findings match
                  </Text>
                </Table.Cell>
              </Table.Row>
            )}
          </Table.Body>
        </Table.Root>
      </Box>
      <HStack justify="space-between">
        <Button
          size="sm"
          variant="subtle"
          disabled={offset === 0}
          onClick={() => setOffset(Math.max(0, offset - limit))}
        >
          ← prev
        </Button>
        <Text fontSize="xs" color="fg.muted">
          rows {offset + 1}-{Math.min(total, offset + rows.length)} of {total}
        </Text>
        <Button
          size="sm"
          variant="subtle"
          disabled={offset + rows.length >= total}
          onClick={() => setOffset(offset + limit)}
        >
          next →
        </Button>
      </HStack>
    </Stack>
  );
}
