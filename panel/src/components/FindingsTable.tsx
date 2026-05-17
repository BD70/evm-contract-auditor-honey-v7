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
import { fmtAge, fmtNativeAmount, fmtTokenAmount, shortHash, SEVERITY_COLORS } from "@/src/lib/format";
import { CHAINS, chainName } from "@/src/lib/chains";

interface TokenBalance {
  address: string;
  symbol: string;
  name: string;
  decimals: number;
  balance: string;
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
}

function exposureKey(chainId: number | null | undefined, address: string | null | undefined): string | null {
  if (chainId == null || !address) return null;
  return `${chainId}:${address.toLowerCase()}`;
}

/**
 * ExposureCell renders only the AT-RISK exposure for the rule's surface.
 *
 * For a `selfdestruct.unguarded` finding the contract's ERC-20 holdings
 * are irrelevant — showing them as "exposure" would mislead the user
 * into thinking those tokens are at risk. We render irrelevant balances
 * de-emphasised (greyed-out with a tooltip explaining why) so the user
 * still gets the full picture but knows what's covered by this rule vs.
 * what's collateral information.
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
    return (
      <Text fontSize="xs" color="fg.muted">
        …
      </Text>
    );
  }
  if (!exp) {
    return (
      <Text fontSize="xs" color="fg.muted">
        —
      </Text>
    );
  }
  if (exp.error) {
    return (
      <Text fontSize="xs" color="fg.muted" title={exp.error}>
        n/a
      </Text>
    );
  }
  const native = fmtNativeAmount(exp.nativeWei, exp.nativeSymbol, exp.nativeDecimals);
  const tokens = exp.tokens ?? [];
  const tokenTip = tokens.length
    ? tokens
        .slice(0, 10)
        .map((t) => `${fmtTokenAmount(t.balance, t.decimals)} ${t.symbol}`)
        .join("\n") + (tokens.length > 10 ? `\n+${tokens.length - 10} more…` : "")
    : exp.tokenScanUnsupported
      ? "Token scan unavailable on this chain's RPC (qn_getWalletTokenBalance add-on not enabled)"
      : "No ERC-20 tokens with non-zero balance";
  const nativeRelevant = surface === "native" || surface === "both";
  const tokenRelevant = surface === "token" || surface === "both";
  const irrelevantNote = "This rule cannot drain this asset class — informational only";
  return (
    <HStack gap="1.5" align="baseline">
      <Text
        fontSize="xs"
        fontFamily="mono"
        whiteSpace="nowrap"
        color={nativeRelevant ? undefined : "fg.muted"}
        opacity={nativeRelevant ? 1 : 0.55}
        title={
          nativeRelevant
            ? `Native ${exp.nativeSymbol} at risk for this rule`
            : `Native ${exp.nativeSymbol} — ${irrelevantNote}`
        }
      >
        {native}
        {!nativeRelevant && (
          <Text as="span" fontSize="2xs" color="fg.muted" ml="0.5">
            (n/a)
          </Text>
        )}
      </Text>
      {tokens.length > 0 ? (
        <Badge
          size="xs"
          variant="subtle"
          colorPalette={tokenRelevant ? "purple" : "gray"}
          title={tokenRelevant ? tokenTip : `${tokenTip}\n\n${irrelevantNote}`}
          opacity={tokenRelevant ? 1 : 0.55}
        >
          +{tokens.length} tok{!tokenRelevant && " (n/a)"}
        </Badge>
      ) : exp.tokenScanUnsupported ? (
        <Text fontSize="2xs" color="fg.muted" title={tokenTip}>
          —
        </Text>
      ) : null}
    </HStack>
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
                  <Text fontSize="xs" fontFamily="mono">
                    {shortHash(r.contractAddress)}
                  </Text>
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
