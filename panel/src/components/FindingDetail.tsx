"use client";

import {
  Badge,
  Box,
  Button,
  HStack,
  Heading,
  Stack,
  Tabs,
  Text,
} from "@chakra-ui/react";
import { useEffect, useState } from "react";
import { fmtTs, fmtNativeAmount, fmtTokenAmount, fmtUsd, SEVERITY_COLORS, shortHash } from "@/src/lib/format";
import { chainName } from "@/src/lib/chains";
import { explorerAddressUrl } from "@/src/lib/chain-meta";
import { EvidenceRenderer, CounterEvidenceRenderer } from "./EvidenceRenderer";
import { JsonView } from "./JsonView";

type ExposureSurface = "native" | "token" | "both" | "none";
const RULE_SURFACE_HINT: Record<string, ExposureSurface> = {
  "selfdestruct.unguarded": "native",
  "control.unguarded_selfdestruct": "native",
  "control.selfdestruct_user_controlled_recipient": "native",
  "oracle.spot_price_manipulation": "token",
};
function surfaceForRule(ruleId: string | null | undefined): ExposureSurface {
  if (!ruleId) return "both";
  return RULE_SURFACE_HINT[ruleId] ?? "both";
}
const SURFACE_LABEL: Record<ExposureSurface, string> = {
  native: "Native only",
  token: "ERC-20 tokens only",
  both: "Native + ERC-20 tokens",
  none: "No on-chain assets at risk",
};
const SURFACE_COLOR: Record<ExposureSurface, string> = {
  native: "blue",
  token: "purple",
  both: "orange",
  none: "gray",
};

interface Finding {
  id: string;
  rule_id: string;
  internal_name: string | null;
  severity: string;
  status: string | null;
  confidence: string | null;
  title: string | null;
  bytecode_hash: string | null;
  contract_address: string | null;
  chain_id: number | null;
  block_number: number | null;
  tx_hash: string | null;
  discovered_at: number;
  source: string;
  judged_by: string | null;
  judge_verdict: string | null;
  judge_rationale: string | null;
  judge_confidence: string | null;
  simulation_status: string | null;
  simulation_verdict: string | null;
  simulation_evidence_json: string | null;
  simulation_engine: string | null;
  simulated_at: number | null;
  raw: any;
  affectedFunctions: any[];
}

const SIM_COLOR_MAP: Record<string, string> = {
  verified: "red",
  not_exploitable: "green",
  inconclusive: "yellow",
  skipped: "gray",
  error: "orange",
};

/** Extract attackerKind ("any" | "owner") from the evidence JSON; null if absent. */
function attackerKindOf(f: { simulation_evidence_json: string | null }): "any" | "owner" | null {
  if (!f.simulation_evidence_json) return null;
  try {
    const ev = JSON.parse(f.simulation_evidence_json);
    if (ev?.attackerKind === "any" || ev?.attackerKind === "owner") return ev.attackerKind;
  } catch {
    /* ignore */
  }
  return null;
}

export function FindingDetail({ id }: { id: string }) {
  const [f, setF] = useState<Finding | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [reauditing, setReauditing] = useState(false);
  const [simulating, setSimulating] = useState(false);
  const [inspecting, setInspecting] = useState(false);
  const [inspectResult, setInspectResult] = useState<any | null>(null);

  useEffect(() => {
    fetch(`/api/findings/${id}`)
      .then((r) => (r.ok ? r.json() : r.json().then((j) => Promise.reject(j))))
      .then(setF)
      .catch((e) => setErr(e?.error ?? "load failed"));
  }, [id]);

  if (err) return <Text color="red.500">{err}</Text>;
  if (!f) return <Text color="fg.muted">loading…</Text>;

  const raw = f.raw ?? {};
  const reporting = raw.reporting ?? {};

  const handleSimulate = async () => {
    if (!f) return;
    setSimulating(true);
    try {
      const r = await fetch(`/api/simulation`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ findingId: f.id }),
      });
      const j = await r.json();
      setF((prev) => prev
        ? {
            ...prev,
            simulation_status: j.status ?? prev.simulation_status,
            simulation_verdict: j.verdict ?? prev.simulation_verdict,
            simulation_evidence_json: j.evidence ? JSON.stringify(j.evidence) : prev.simulation_evidence_json,
            simulation_engine: j.engine && j.engineVersion ? `${j.engine}@${j.engineVersion}` : prev.simulation_engine,
            simulated_at: Date.now(),
          }
        : prev,
      );
    } finally {
      setSimulating(false);
    }
  };

  const handleInspect = async () => {
    if (!f) return;
    setInspecting(true);
    setInspectResult(null);
    try {
      const r = await fetch(`/api/simulation/inspect`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ findingId: f.id }),
      });
      const j = await r.json();
      setInspectResult(j);
    } finally {
      setInspecting(false);
    }
  };

  const handleReaudit = async (refresh: boolean) => {
    setReauditing(true);
    try {
      const r = await fetch(`/api/findings/${id}/reaudit`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ llmJudge: true, llmJudgeRefresh: refresh }),
      });
      const j = await r.json();
      if (j.runId) window.location.href = `/test?runId=${j.runId}`;
    } finally {
      setReauditing(false);
    }
  };

  return (
    <Stack gap="4">
      <Box>
        <HStack gap="2" mb="2">
          <Badge colorPalette={SEVERITY_COLORS[f.severity] ?? "gray"} variant="subtle">
            {f.severity}
          </Badge>
          {f.status && <Badge variant="outline">{f.status}</Badge>}
          {f.confidence && <Badge variant="outline">confidence: {f.confidence}</Badge>}
          {f.judge_verdict && (
            <Badge colorPalette="purple" variant="subtle">
              judge: {f.judge_verdict}
            </Badge>
          )}
          {f.simulation_status && (() => {
            const ak = attackerKindOf(f);
            const isOwnerOnly = f.simulation_status === "verified" && ak === "owner";
            const palette = isOwnerOnly ? "orange" : SIM_COLOR_MAP[f.simulation_status] ?? "gray";
            const label = isOwnerOnly
              ? "owner-only exploit"
              : f.simulation_status === "verified"
                ? "exploitable (any caller)"
                : f.simulation_status === "not_exploitable"
                  ? "FP"
                  : f.simulation_status;
            return (
              <Badge
                colorPalette={palette}
                variant={f.simulation_status === "verified" ? "solid" : "subtle"}
                title={isOwnerOnly ? "Only the contract owner can trigger this — risk depends on owner key safety" : undefined}
              >
                sim: {label}
              </Badge>
            );
          })()}
          <Badge variant="subtle">{f.source}</Badge>
        </HStack>
        <Heading size="md">{f.title ?? f.rule_id}</Heading>
        <HStack gap="3" mt="2" wrap="wrap">
          <Text fontSize="sm" color="fg.muted">
            {f.rule_id}
          </Text>
          {f.internal_name && (
            <Text fontSize="xs" color="fg.muted" fontFamily="mono">
              {f.internal_name}
            </Text>
          )}
        </HStack>
        <HStack gap="3" mt="2" wrap="wrap">
          <Text fontSize="xs" color="fg.muted">discovered {fmtTs(f.discovered_at)}</Text>
          {f.contract_address && (() => {
            const url = explorerAddressUrl(f.chain_id, f.contract_address);
            const label = `contract ${shortHash(f.contract_address, 10, 6)}`;
            return url ? (
              <Text fontSize="xs" fontFamily="mono">
                <a
                  href={url}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{ color: "var(--chakra-colors-blue-fg)", textDecoration: "underline" }}
                  title={`Open ${f.contract_address} on block explorer (new tab)`}
                >
                  {label} ↗
                </a>
              </Text>
            ) : (
              <Text fontSize="xs" color="fg.muted" fontFamily="mono">
                {label}
              </Text>
            );
          })()}
          <Text fontSize="xs" color="fg.muted">{chainName(f.chain_id)}</Text>
          {f.block_number != null && <Text fontSize="xs" color="fg.muted">block {f.block_number}</Text>}
          {f.bytecode_hash && (
            <Text fontSize="xs" color="fg.muted" fontFamily="mono">
              hash {shortHash(f.bytecode_hash)}
            </Text>
          )}
        </HStack>
        <HStack mt="3" gap="2">
          <Button size="xs" variant="subtle" loading={reauditing} onClick={() => handleReaudit(false)}>
            Re-audit
          </Button>
          <Button size="xs" variant="ghost" loading={reauditing} onClick={() => handleReaudit(true)}>
            Re-judge (refresh)
          </Button>
          <Button size="xs" variant="outline" colorPalette="red" loading={simulating} onClick={handleSimulate}>
            Run fork simulation
          </Button>
          <Button size="xs" variant="ghost" colorPalette="orange" loading={inspecting} onClick={handleInspect}>
            Verbose inspect
          </Button>
        </HStack>
      </Box>

      {f.contract_address && f.chain_id != null && (
        <ExposurePanel chainId={f.chain_id} address={f.contract_address} surface={surfaceForRule(f.rule_id)} />
      )}

      <ProofOfExploitPanel findingId={f.id} />

      <Tabs.Root defaultValue="summary" variant="line">
        <Tabs.List>
          <Tabs.Trigger value="summary">Summary</Tabs.Trigger>
          <Tabs.Trigger value="evidence">Evidence</Tabs.Trigger>
          <Tabs.Trigger value="counter">Counter-evidence</Tabs.Trigger>
          <Tabs.Trigger value="witness">Witness</Tabs.Trigger>
          <Tabs.Trigger value="judge">Judge</Tabs.Trigger>
          <Tabs.Trigger value="simulation">Simulation</Tabs.Trigger>
          <Tabs.Trigger value="raw">Raw JSON</Tabs.Trigger>
        </Tabs.List>

        <Tabs.Content value="summary">
          <SummaryView finding={f} />
        </Tabs.Content>

        <Tabs.Content value="evidence">
          <EvidenceRenderer raw={raw} />
        </Tabs.Content>

        <Tabs.Content value="counter">
          <CounterEvidenceRenderer raw={raw} />
        </Tabs.Content>

        <Tabs.Content value="witness">
          {raw.witness ? <EvidenceRenderer raw={{ evidence: { details: raw.witness } }} /> : (
            <Text fontSize="sm" color="fg.muted">no witness backend data on this finding.</Text>
          )}
        </Tabs.Content>

        <Tabs.Content value="simulation">
          <SimulationView finding={f} />
          {inspectResult && <InspectView data={inspectResult} />}
        </Tabs.Content>

        <Tabs.Content value="judge">
          {f.judged_by ? (
            <Stack gap="2">
              <HStack gap="2">
                <Badge variant="subtle" colorPalette="purple">judge: {f.judged_by}</Badge>
                {f.judge_verdict && <Badge variant="outline">{f.judge_verdict}</Badge>}
                {f.judge_confidence && <Badge variant="outline">conf: {f.judge_confidence}</Badge>}
              </HStack>
              {f.judge_rationale && (
                <Box bg="bg.subtle" p="3" rounded="md" border="1px solid" borderColor="border">
                  <Text fontSize="sm" whiteSpace="pre-wrap">{f.judge_rationale}</Text>
                </Box>
              )}
            </Stack>
          ) : (
            <Text fontSize="sm" color="fg.muted">no LLM judge result on this finding. Enable EVM_LLM_* and re-audit to invoke.</Text>
          )}
        </Tabs.Content>

        <Tabs.Content value="raw">
          <JsonView value={raw} maxHeight="70vh" />
        </Tabs.Content>
      </Tabs.Root>
    </Stack>
  );
}

function asArray(v: any): any[] {
  if (Array.isArray(v)) return v;
  if (v == null) return [];
  return [v];
}

interface ExposureToken {
  address: string; symbol: string; name: string; decimals: number;
  balance: string; usdPerToken?: number | null; usdValue?: number | null;
}
interface ExposureResp {
  chainId: number; address: string;
  nativeWei: string; nativeSymbol: string; nativeDecimals: number;
  tokens: ExposureToken[];
  nativeUsdPerToken?: number | null;
  nativeUsdValue?: number | null;
  tokensUsdValue?: number | null;
  totalUsdValue?: number | null;
  tokenSource?: "qn-add-on" | "log-scan" | "log-scan-cache" | "none";
  tokenScanUnsupported?: boolean;
  dustTokensFiltered?: number;
  error?: string;
}

/**
 * ExposurePanel — surface-aware "Balance vs True Exposure vs At Risk" panel.
 *
 * Renders three numbers prominently:
 *   - Total Balance      (everything the contract holds, ETH + ERC-20 USD)
 *   - At Risk For This Rule (subset filtered by the rule's surface)
 *   - Out-of-Scope       (the difference, shown dimmed for context)
 *
 * Then a row-per-asset breakdown with each row colored / opacity-coded by
 * whether it is in-scope for the rule. This is what replaces the hover-only
 * UX from earlier: no mouse-over needed to understand what's at risk.
 */
function ExposurePanel({ chainId, address, surface }: { chainId: number; address: string; surface: ExposureSurface }) {
  const [exp, setExp] = useState<ExposureResp | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    fetch("/api/exposure", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ items: [{ chainId, address }] }),
    })
      .then((r) => r.json())
      .then((j) => {
        if (cancelled) return;
        const key = `${chainId}:${address.toLowerCase()}`;
        setExp(j?.exposures?.[key] ?? null);
      })
      .catch((e) => { if (!cancelled) setErr(String(e?.message ?? e)); });
    return () => { cancelled = true; };
  }, [chainId, address]);

  if (err) {
    return (
      <Box bg="bg.subtle" p="3" rounded="md" border="1px solid" borderColor="border">
        <Text fontSize="xs" color="fg.muted">Exposure lookup failed: {err}</Text>
      </Box>
    );
  }
  if (!exp) {
    return (
      <Box bg="bg.subtle" p="3" rounded="md" border="1px solid" borderColor="border">
        <Text fontSize="xs" color="fg.muted">Loading exposure…</Text>
      </Box>
    );
  }

  const nativeRelevant = surface === "native" || surface === "both";
  const tokenRelevant = surface === "token" || surface === "both";
  const nativeUsd = exp.nativeUsdValue ?? null;
  const tokensUsd = exp.tokensUsdValue ?? null;
  const totalUsd = exp.totalUsdValue ?? null;

  const atRiskUsd = (() => {
    let v = 0; let any = false;
    if (nativeRelevant && nativeUsd != null) { v += nativeUsd; any = true; }
    if (tokenRelevant && tokensUsd != null) { v += tokensUsd; any = true; }
    return any ? v : null;
  })();
  const outOfScopeUsd = (() => {
    if (totalUsd == null || atRiskUsd == null) return null;
    return Math.max(0, totalUsd - atRiskUsd);
  })();

  const tokens = exp.tokens ?? [];
  const sourceLabel =
    exp.tokenSource === "qn-add-on" ? "QuickNode token API" :
    exp.tokenSource === "log-scan" ? "log scan (fresh)" :
    exp.tokenSource === "log-scan-cache" ? "log scan (cached, ≤30 min)" :
    "native only";

  return (
    <Box bg="bg.subtle" p="4" rounded="md" border="1px solid" borderColor="border">
      <HStack justify="space-between" align="start" mb="3" wrap="wrap" gap="2">
        <Stack gap="0">
          <Text fontSize="xs" color="fg.muted" textTransform="uppercase" letterSpacing="wide">On-chain exposure</Text>
          <Heading size="sm">Balance vs At-Risk for this rule</Heading>
        </Stack>
        <HStack gap="2">
          <Badge colorPalette={SURFACE_COLOR[surface]} variant="subtle" size="sm" title="What this rule can drain">
            {SURFACE_LABEL[surface]}
          </Badge>
          <Badge variant="outline" size="sm" title={`Source: ${sourceLabel}`}>{sourceLabel}</Badge>
        </HStack>
      </HStack>

      <HStack gap="6" align="start" wrap="wrap" mb="4">
        <Stack gap="0" minW="120px">
          <Text fontSize="xs" color="fg.muted">Total balance</Text>
          <Text fontSize="2xl" fontWeight="bold" fontFamily="mono">
            {totalUsd == null ? "—" : fmtUsd(totalUsd)}
          </Text>
          <Text fontSize="2xs" color="fg.muted">
            {nativeUsd != null ? `native ${fmtUsd(nativeUsd)}` : "native ?"} ·{" "}
            {tokensUsd != null ? `${tokens.length} tok ${fmtUsd(tokensUsd)}` : `${tokens.length} tok (unpriced)`}
          </Text>
        </Stack>
        <Stack gap="0" minW="120px">
          <Text fontSize="xs" color={surface === "none" ? "fg.muted" : "red.500"}>At risk · this rule</Text>
          <Text fontSize="2xl" fontWeight="bold" fontFamily="mono"
            color={surface === "none" ? "fg.muted" : "red.500"}>
            {surface === "none" ? "$0" : atRiskUsd == null ? "—" : fmtUsd(atRiskUsd)}
          </Text>
          <Text fontSize="2xs" color="fg.muted">{SURFACE_LABEL[surface].toLowerCase()}</Text>
        </Stack>
        {outOfScopeUsd != null && outOfScopeUsd > 0 && (
          <Stack gap="0" minW="120px">
            <Text fontSize="xs" color="fg.muted">Out of scope</Text>
            <Text fontSize="2xl" fontWeight="bold" fontFamily="mono" color="fg.muted">
              {fmtUsd(outOfScopeUsd)}
            </Text>
            <Text fontSize="2xs" color="fg.muted">held but not drainable by this rule</Text>
          </Stack>
        )}
      </HStack>

      <Stack gap="1">
        <Text fontSize="xs" color="fg.muted" mb="1">Holdings ({tokens.length + (exp.nativeWei !== "0" ? 1 : 0)})</Text>
        {exp.nativeWei !== "0" && (
          <HoldingRow
            symbol={exp.nativeSymbol}
            name={`Native ${exp.nativeSymbol}`}
            amount={fmtNativeAmount(exp.nativeWei, exp.nativeSymbol, exp.nativeDecimals)}
            usd={nativeUsd}
            relevant={nativeRelevant}
          />
        )}
        {tokens.map((t) => (
          <HoldingRow
            key={t.address}
            symbol={t.symbol}
            name={t.name}
            address={t.address}
            amount={fmtTokenAmount(t.balance, t.decimals)}
            usd={t.usdValue ?? null}
            unpriced={t.usdValue == null}
            relevant={tokenRelevant}
          />
        ))}
        {tokens.length === 0 && exp.nativeWei === "0" && (
          <Text fontSize="sm" color="fg.muted">No on-chain assets held by this contract.</Text>
        )}
      </Stack>
      {exp.dustTokensFiltered && exp.dustTokensFiltered > 0 ? (
        <Text fontSize="2xs" color="fg.muted" mt="2">
          {exp.dustTokensFiltered} priced token(s) under the $1.00 dust threshold were hidden.
        </Text>
      ) : null}
    </Box>
  );
}

function HoldingRow({
  symbol, name, amount, usd, relevant, address, unpriced,
}: {
  symbol: string; name: string; amount: string; usd: number | null;
  relevant: boolean; address?: string; unpriced?: boolean;
}) {
  return (
    <HStack
      gap="3"
      p="2"
      bg={relevant ? "bg" : "transparent"}
      rounded="sm"
      borderLeft={relevant ? "2px solid" : "2px solid transparent"}
      borderLeftColor={relevant ? "red.500" : "transparent"}
      opacity={relevant ? 1 : 0.55}
    >
      <Box minW="60px">
        <Text fontSize="sm" fontWeight="semibold">{symbol}</Text>
      </Box>
      <Box flex="1" minW="0">
        <Text fontSize="xs" color="fg.muted" title={address}>{name}</Text>
      </Box>
      <Text fontSize="sm" fontFamily="mono" whiteSpace="nowrap">{amount}</Text>
      <Box minW="80px" textAlign="right">
        {unpriced ? (
          <Text fontSize="xs" color="fg.muted" title="No USD price available (unknown to CoinGecko)">unpriced</Text>
        ) : (
          <Text fontSize="sm" fontFamily="mono" fontWeight="semibold"
            color={relevant ? "fg" : "fg.muted"}>
            {fmtUsd(usd)}
          </Text>
        )}
      </Box>
      <Badge size="xs" variant="subtle" colorPalette={relevant ? "red" : "gray"}
        title={relevant ? "This asset CAN be drained by the rule" : "Held but not drainable by this rule"}>
        {relevant ? "at risk" : "out of scope"}
      </Badge>
    </HStack>
  );
}

function isResolverNoise(s: string): boolean {
  return (
    /remote selector request failed/i.test(s) ||
    /Remote selector resolution skipped/i.test(s) ||
    /API error for 0x[0-9a-fA-F]+:.*selector/i.test(s)
  );
}

function SimulationView({ finding: f }: { finding: Finding }) {
  if (!f.simulation_status) {
    return (
      <Text fontSize="sm" color="fg.muted">
        No fork simulation has run for this finding yet. The background worker verifies
        critical/high findings on supported rules; you can also click <em>Run fork simulation</em>{" "}
        above to verify now.
      </Text>
    );
  }
  let evidence: any = {};
  try {
    evidence = f.simulation_evidence_json ? JSON.parse(f.simulation_evidence_json) : {};
  } catch {
    evidence = {};
  }
  const attempts: any[] = Array.isArray(evidence?.attempts) ? evidence.attempts : [];
  const color = SIM_COLOR_MAP[f.simulation_status] ?? "gray";
  const attackerKind = attackerKindOf(f);
  const isOwnerOnly = f.simulation_status === "verified" && attackerKind === "owner";
  const verifiedLabel = isOwnerOnly
    ? `Owner-only exploit (attacker EOA blocked${evidence?.attackerAddress ? ` — owner: ${evidence.attackerAddress}` : ""})`
    : "Exploit witnessed on fork (any caller)";
  const verifiedPalette = isOwnerOnly ? "orange" : color;
  return (
    <Stack gap="3">
      <HStack gap="2" wrap="wrap">
        <Badge colorPalette={verifiedPalette} variant={f.simulation_status === "verified" ? "solid" : "subtle"}>
          {f.simulation_status === "verified"
            ? verifiedLabel
            : f.simulation_status === "not_exploitable"
            ? "No exploit witnessed (likely false positive)"
            : f.simulation_status === "inconclusive"
            ? "Inconclusive"
            : f.simulation_status === "skipped"
            ? "Skipped"
            : f.simulation_status}
        </Badge>
        {f.simulation_engine && <Badge variant="outline">engine: {f.simulation_engine}</Badge>}
        {f.simulated_at && (
          <Text fontSize="xs" color="fg.muted">
            ran {new Date(f.simulated_at).toLocaleString()}
          </Text>
        )}
      </HStack>
      {f.simulation_verdict && (
        <Box bg="bg.subtle" p="3" rounded="md" border="1px solid" borderColor="border">
          <Text fontSize="sm" whiteSpace="pre-wrap">
            {f.simulation_verdict}
          </Text>
        </Box>
      )}
      <Box>
        <Text fontSize="xs" color="fg.muted" mb="1.5">Fork context</Text>
        <FactRow k="Chain" v={String(evidence?.chainId ?? "?")} />
        <FactRow k="Fork block" v={String(evidence?.forkBlock ?? "—")} />
        <FactRow k="Probe address" v={evidence?.probeAddress ?? "—"} />
        <FactRow k="Candidate selectors" v={String(evidence?.candidateCount ?? 0)} />
        <FactRow k="Attempts tried" v={String(evidence?.attemptsTried ?? attempts.length)} />
        {evidence?.decon && (
          <FactRow
            k="Decon tags"
            v={
              (evidence.decon.contractFamily ? `family=${evidence.decon.contractFamily}; ` : "") +
              (Array.isArray(evidence.decon.globalTags) ? evidence.decon.globalTags.slice(0, 6).join(", ") : "")
            }
          />
        )}
      </Box>
      {attempts.length > 0 && (
        <Box>
          <Text fontSize="xs" color="fg.muted" mb="1.5">Per-selector attempts</Text>
          <Stack gap="1.5">
            {attempts.map((a, i) => (
              <Box
                key={i}
                bg={a.hit ? "red.subtle" : "bg.subtle"}
                p="2"
                rounded="md"
                border="1px solid"
                borderColor={a.hit ? "red.muted" : "border"}
              >
                <HStack gap="2" wrap="wrap">
                  <Badge size="xs" variant={a.hit ? "solid" : "subtle"} colorPalette={a.hit ? "red" : "gray"}>
                    {a.hit ? `HIT (${a.hitKind ?? "CALL"})` : "miss"}
                  </Badge>
                  <Text fontSize="xs" fontFamily="mono">{a.selector}</Text>
                  <Text fontSize="xs" color="fg.muted">
                    {a.argCount} args · positions [{(a.positionsTried ?? []).join(",")}]
                    {a.hitPosition != null ? ` · hit@${a.hitPosition}` : ""}
                  </Text>
                  {a.fromOwner && (
                    <Badge size="xs" colorPalette="orange" variant="subtle">
                      owner only
                    </Badge>
                  )}
                  <Text fontSize="xs" color="fg.muted" ml="auto">
                    {a.durationMs}ms
                  </Text>
                </HStack>
                {a.revertReason && (
                  <Text fontSize="2xs" color="orange.500" mt="1" fontFamily="mono" wordBreak="break-all">
                    revert: {a.revertReason}
                  </Text>
                )}
                {a.txError && (
                  <Text fontSize="2xs" color="fg.muted" mt="1" fontFamily="mono" wordBreak="break-all">
                    {a.txError}
                  </Text>
                )}
              </Box>
            ))}
          </Stack>
        </Box>
      )}
    </Stack>
  );
}

function InspectView({ data }: { data: any }) {
  if (!data) return null;
  if (data.error) {
    return (
      <Box mt="4" bg="red.subtle" p="3" rounded="md" border="1px solid" borderColor="red.muted">
        <Text fontSize="sm" color="red.fg">Inspect failed: {data.error}</Text>
      </Box>
    );
  }
  const summary = data.summary ?? {};
  const attempts: any[] = Array.isArray(data.attempts) ? data.attempts : [];
  const hits = attempts.filter((a) => a.hit);
  const others = attempts.filter((a) => !a.hit);
  return (
    <Box mt="6" borderTop="1px solid" borderColor="border" pt="4">
      <HStack mb="2" gap="2">
        <Heading size="sm">Verbose inspect</Heading>
        {summary.hits > 0 ? (
          <Badge colorPalette="red" variant="solid">EXPLOITABLE ({summary.hits} hits)</Badge>
        ) : summary.authReverts === attempts.length && attempts.length > 0 ? (
          <Badge colorPalette="orange" variant="subtle">All auth-reverted</Badge>
        ) : (
          <Badge colorPalette="gray" variant="subtle">No witness</Badge>
        )}
        <Text fontSize="xs" color="fg.muted" ml="auto">{data.durationMs}ms</Text>
      </HStack>
      {summary.suggestion && (
        <Box bg="bg.subtle" p="2.5" rounded="md" border="1px solid" borderColor="border" mb="3">
          <Text fontSize="sm" whiteSpace="pre-wrap">{summary.suggestion}</Text>
        </Box>
      )}
      <FactRow k="Decon functions" v={String(data.decon?.functionCount ?? 0)} />
      <FactRow
        k="Candidates after ranking"
        v={String((data.candidates ?? []).length)}
      />
      <FactRow k="Attempts run" v={String(data.attemptCount ?? 0)} />
      {data.proxy?.isProxy && (
        <FactRow k="Proxy" v={`family=${data.proxy.family} impl=${data.proxy.impl ?? "?"}`} />
      )}
      {data.owner && <FactRow k="Owner" v={data.owner} />}
      {hits.length > 0 && (
        <Box mt="3">
          <Text fontSize="xs" color="fg.muted" mb="1.5">Witnessed hits ({hits.length})</Text>
          <Stack gap="1.5">
            {hits.slice(0, 20).map((a, i) => (
              <Box key={i} bg="red.subtle" p="2" rounded="md" border="1px solid" borderColor="red.muted">
                <HStack gap="2" wrap="wrap">
                  <Badge size="xs" variant="solid" colorPalette="red">HIT</Badge>
                  <Text fontSize="xs" fontFamily="mono">{a.selector}</Text>
                  <Text fontSize="xs" color="fg.muted">
                    pos={a.position} bytes={a.bytesPayload} value={a.value}
                  </Text>
                </HStack>
              </Box>
            ))}
          </Stack>
        </Box>
      )}
      {others.length > 0 && (
        <Box mt="3">
          <Text fontSize="xs" color="fg.muted" mb="1.5">
            Misses ({others.length}) — top reverts:
          </Text>
          <Stack gap="1">
            {others.slice(0, 30).map((a, i) => (
              <Box key={i} bg="bg.subtle" p="1.5" rounded="md" border="1px solid" borderColor="border">
                <HStack gap="2" wrap="wrap">
                  <Text fontSize="2xs" fontFamily="mono">{a.selector}</Text>
                  <Text fontSize="2xs" color="fg.muted">
                    pos={a.position} bytes={a.bytesPayload}
                  </Text>
                  {a.authRevert && (
                    <Badge size="xs" variant="subtle" colorPalette="orange">auth</Badge>
                  )}
                  <Text fontSize="2xs" color="orange.500" fontFamily="mono" ml="auto" wordBreak="break-all">
                    {a.revertReason || a.traceError || "—"}
                  </Text>
                </HStack>
              </Box>
            ))}
          </Stack>
        </Box>
      )}
      <Box mt="4">
        <Text fontSize="xs" color="fg.muted" mb="1.5">Raw inspect dump (for debugging)</Text>
        <JsonView value={data} maxHeight="320px" />
      </Box>
    </Box>
  );
}

function FactRow({ k, v, mono = true }: { k: string; v: React.ReactNode; mono?: boolean }) {
  return (
    <Box display="grid" gridTemplateColumns="160px 1fr" gap="3" py="1.5" borderBottom="1px dashed" borderColor="border">
      <Text fontSize="xs" color="fg.muted">{k}</Text>
      <Text fontSize="sm" fontFamily={mono ? "mono" : "body"} wordBreak="break-all">
        {v}
      </Text>
    </Box>
  );
}

function SummaryView({ finding: f }: { finding: Finding }) {
  const raw = f.raw ?? {};
  const reporting = raw.reporting ?? {};
  const affected = asArray(raw.affected_functions ?? (raw.function ? [raw.function] : []));
  const preconds = raw.exploit_preconditions;
  const warnings: string[] = (Array.isArray(raw.analysis_warnings) ? raw.analysis_warnings : []).filter(
    (s: any) => typeof s === "string" && !isResolverNoise(s),
  );
  const resolverNoise = (Array.isArray(raw.analysis_warnings) ? raw.analysis_warnings : []).filter(
    (s: any) => typeof s === "string" && isResolverNoise(s),
  ).length;

  return (
    <Stack gap="4">
      <Box bg="bg.subtle" p="4" rounded="md" border="1px solid" borderColor="border">
        <Text fontSize="xs" color="fg.muted" textTransform="uppercase" mb="2">Key facts</Text>
        <Stack gap="0">
          <FactRow k="Rule" v={f.rule_id} />
          {f.internal_name && <FactRow k="Internal name" v={f.internal_name} />}
          <FactRow
            k="Severity / Status"
            v={
              <HStack gap="2">
                <Badge colorPalette={SEVERITY_COLORS[f.severity] ?? "gray"} variant="subtle" size="sm">
                  {f.severity}
                </Badge>
                {f.status && <Badge variant="outline" size="sm">{f.status}</Badge>}
                {f.confidence && <Badge variant="outline" size="sm">conf {f.confidence}</Badge>}
              </HStack>
            }
            mono={false}
          />
          {raw.match_count != null && <FactRow k="Match count" v={String(raw.match_count)} />}
          {f.contract_address && <FactRow k="Contract" v={f.contract_address} />}
          {f.chain_id != null && <FactRow k="Chain" v={`${chainName(f.chain_id)} (${f.chain_id})`} mono={false} />}
          {f.block_number != null && <FactRow k="Block" v={String(f.block_number)} />}
          {f.tx_hash && <FactRow k="Tx hash" v={f.tx_hash} />}
          {f.bytecode_hash && <FactRow k="Bytecode hash" v={f.bytecode_hash} />}
          <FactRow k="Discovered" v={new Date(f.discovered_at).toLocaleString()} mono={false} />
          <FactRow k="Source" v={<Badge variant="subtle" size="sm">{f.source}</Badge>} mono={false} />
          {f.judged_by && (
            <FactRow
              k="LLM judge"
              v={
                <HStack gap="2">
                  <Badge variant="subtle" colorPalette="purple" size="sm">{f.judged_by}</Badge>
                  {f.judge_verdict && <Badge variant="outline" size="sm">{f.judge_verdict}</Badge>}
                  {f.judge_confidence && <Badge variant="outline" size="sm">conf {f.judge_confidence}</Badge>}
                </HStack>
              }
              mono={false}
            />
          )}
        </Stack>
      </Box>

      {affected.length > 0 && (
        <Box bg="bg.subtle" p="4" rounded="md" border="1px solid" borderColor="border">
          <Text fontSize="xs" color="fg.muted" textTransform="uppercase" mb="2">
            Affected functions ({affected.length})
          </Text>
          <Stack gap="1.5">
            {affected.map((fn: any, i: number) => (
              <HStack key={i} gap="3" align="flex-start">
                <Badge variant="outline" fontFamily="mono" size="sm">
                  {fn.selector ?? "—"}
                </Badge>
                <Box>
                  <Text fontSize="sm">{fn.name ?? fn.signature ?? "(no name)"}</Text>
                  {fn.signature && fn.name !== fn.signature && (
                    <Text fontSize="xs" color="fg.muted" fontFamily="mono">{fn.signature}</Text>
                  )}
                </Box>
              </HStack>
            ))}
          </Stack>
        </Box>
      )}

      {reporting.user_summary && (
        <Box bg="bg.subtle" p="4" rounded="md" border="1px solid" borderColor="border">
          <Text fontSize="xs" color="fg.muted" textTransform="uppercase" mb="2">What it is</Text>
          <Text fontSize="sm">{reporting.user_summary}</Text>
        </Box>
      )}

      {reporting.technical_summary && (
        <Box bg="bg.subtle" p="4" rounded="md" border="1px solid" borderColor="border">
          <Text fontSize="xs" color="fg.muted" textTransform="uppercase" mb="2">Why it matched</Text>
          <Text fontSize="sm">{reporting.technical_summary}</Text>
        </Box>
      )}

      {reporting.exploit_narrative && (
        <Box bg="bg.subtle" p="4" rounded="md" border="1px solid" borderColor="border">
          <Text fontSize="xs" color="fg.muted" textTransform="uppercase" mb="2">Exploit scenario</Text>
          <Text fontSize="sm">{reporting.exploit_narrative}</Text>
        </Box>
      )}

      {preconds && (
        <Box bg="bg.subtle" p="4" rounded="md" border="1px solid" borderColor="border">
          <Text fontSize="xs" color="fg.muted" textTransform="uppercase" mb="2">Exploit preconditions</Text>
          {Array.isArray(preconds) ? (
            <Stack as="ol" gap="1" pl="4">
              {preconds.map((p: any, i: number) => (
                <Text as="li" key={i} fontSize="sm">
                  {typeof p === "string" ? p : JSON.stringify(p)}
                </Text>
              ))}
            </Stack>
          ) : typeof preconds === "string" ? (
            <Text fontSize="sm" whiteSpace="pre-wrap">{preconds}</Text>
          ) : (
            <Text fontSize="xs" fontFamily="mono" as="pre" whiteSpace="pre-wrap">
              {JSON.stringify(preconds, null, 2)}
            </Text>
          )}
        </Box>
      )}

      {reporting.recommendation && (
        <Box bg="green.subtle" p="4" rounded="md" border="1px solid" borderColor="green.muted">
          <Text fontSize="xs" color="green.fg" textTransform="uppercase" mb="2">Recommendation</Text>
          <Text fontSize="sm">{reporting.recommendation}</Text>
        </Box>
      )}

      {(warnings.length > 0 || resolverNoise > 0) && (
        <Box bg="yellow.subtle" p="4" rounded="md" border="1px solid" borderColor="yellow.muted">
          <Text fontSize="xs" color="yellow.fg" textTransform="uppercase" mb="2">Analysis warnings</Text>
          <Stack as="ul" gap="1" pl="4">
            {warnings.map((w: string, i: number) => (
              <Text as="li" key={i} fontSize="xs" fontFamily="mono">{w}</Text>
            ))}
            {resolverNoise > 0 && (
              <Text fontSize="xs" color="fg.muted">
                {resolverNoise} 4byte selector-resolver entries suppressed (cosmetic).
              </Text>
            )}
          </Stack>
        </Box>
      )}

      {!reporting.user_summary && !reporting.technical_summary && (
        <Text fontSize="sm" color="fg.muted">no rendered summary on this finding.</Text>
      )}
    </Stack>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// ProofOfExploitPanel
//
// Shows the rescue-prove PoE artifact (when present): verdict, total rescued
// USD, asset breakdown, and the drain plan that moved them on the fork. Also
// renders the timeline of rescue-related actions logged for this finding.
//
// When no PoE exists yet (typical for findings whose rule isn't in rescue-
// prove's v1 scope — economic.*, access.*, etc), the panel renders nothing
// so it doesn't visually pollute the page with empty state.
// ─────────────────────────────────────────────────────────────────────────────

interface PoeAsset {
  token: string | null;
  amountBase: string;
  symbol: string;
  decimals: number;
  usdValue: number | null;
  quirk?: {
    kind: "normal" | "fee-on-transfer" | "paused" | "blacklisted" | "non-transferable" | "errored";
    feeBps?: number;
    detail?: string;
  };
}
interface PoeStep {
  index: number;
  to: string;
  data: string;
  value: string;
  asset: string;
  gasUsed: string | null;
  success: boolean;
  revertReason: string | null;
  executor?: "attacker" | "owner";
  from?: string;
  strategy?: string;
}
interface PoeResp {
  finding: { id: string; ruleId: string; contractAddress: string | null; chainId: number | null };
  poe: {
    attemptId: string;
    findingId: string;
    chainId: number;
    contractAddress: string;
    attackerKind: "any" | "owner" | "unknown";
    executorOwner?: string | null;
    escrowAddress: string;
    verdict:
      | "true_positive_drained"
      | "true_positive_partial"
      | "no_rescue_possible"
      | "skipped"
      | "error"
      | "victim_approval_rescue"
      | "requires_flashloan_helper"
      | "trapped_assets_only"
      | "requires_safe_signing";
    blockNumber: number | null;
    rescuedAssets: PoeAsset[];
    drainPlan: PoeStep[];
    totalRescuedUsd: number | null;
    notes: string[];
    engine: string;
    engineVersion: string;
    createdAt: number;
    durationMs: number;
    error: string | null;
    approvalVictims?: Array<{
      victim: string;
      token: string;
      tokenSymbol: string;
      tokenDecimals: number;
      allowance: string;
      balance: string;
      drainable: string;
      drainableUsd: number | null;
      consented: boolean;
    }>;
    trappedAssets?: Array<{
      token: string | null;
      symbol: string;
      decimals: number;
      balance: string;
      usdValue: number | null;
      reason: string;
    }>;
    flashloanRequirement?: {
      asset: string;
      amount: string;
      suggestedPool: string | null;
      notes: string[];
    } | null;
    safeRequirement?: {
      safeAddress: string;
      chainShortName: string | null;
      threshold: number | null;
      ownerCount: number | null;
      appDeeplink: string | null;
      txServiceEndpoint: string | null;
      instructions: string[];
    } | null;
  } | null;
  actions: Array<{
    id: number;
    kind: string;
    actor: string | null;
    detail_json: string | null;
    at: number;
  }>;
}

function ProofOfExploitPanel({ findingId }: { findingId: string }) {
  const [data, setData] = useState<PoeResp | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [rescueBusy, setRescueBusy] = useState<null | "dry-run-fork" | "dry-run-sign" | "live">(null);
  const [rescueResult, setRescueResult] = useState<string | null>(null);
  const [confirmLive, setConfirmLive] = useState(false);
  const [authToken, setAuthToken] = useState("");

  useEffect(() => {
    let cancelled = false;
    fetch(`/api/proofs/${findingId}`)
      .then((r) => r.json())
      .then((j) => {
        if (cancelled) return;
        if (j.error) setErr(j.error);
        else setData(j);
      })
      .catch((e) => !cancelled && setErr(String(e?.message ?? e)));
    return () => {
      cancelled = true;
    };
  }, [findingId]);

  const refresh = () =>
    fetch(`/api/proofs/${findingId}`)
      .then((r) => r.json())
      .then((j) => setData(j))
      .catch(() => null);

  const runRescue = async (mode: "dry-run-fork" | "dry-run-sign" | "live") => {
    setRescueBusy(mode);
    setRescueResult(null);
    try {
      const body: any = { mode };
      if (mode === "live") body.authToken = authToken;
      const r = await fetch(`/api/proofs/${findingId}/rescue`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const j = await r.json();
      if (j.error) {
        setRescueResult(`error: ${j.error}`);
      } else {
        const ok = j.results?.filter((x: any) => !x.error).length ?? 0;
        const total = j.results?.length ?? 0;
        const txList = (j.results ?? [])
          .filter((s: any) => s.txHash)
          .map((s: any) => `  ${s.asset.slice(0, 30)} → ${String(s.txHash).slice(0, 18)}…`)
          .join("\n");
        const tag =
          mode === "live"
            ? "LIVE BROADCAST"
            : mode === "dry-run-sign"
              ? "Signed (not broadcast)"
              : "Fork dry-run";
        setRescueResult(
          `${tag}: ${ok}/${total} step(s) succeeded.${txList ? "\n" + txList : ""}` +
            (j.ok ? "" : `\n(some steps failed)`),
        );
      }
      await refresh();
    } catch (e: any) {
      setRescueResult(`error: ${String(e?.message ?? e)}`);
    } finally {
      setRescueBusy(null);
      setConfirmLive(false);
    }
  };

  if (err) {
    // Just hide errors silently — PoE data is optional context, not critical.
    return null;
  }
  if (!data) return null;
  const poe = data.poe;
  if (!poe) {
    // No PoE yet. Show a minimal hint so users know the rescue pipeline is
    // wired but hasn't run for this finding (and why, when we can tell).
    const eligible =
      data.finding.ruleId.startsWith("call.") ||
      data.finding.ruleId.startsWith("control.unguarded_selfdestruct");
    if (!eligible) return null;
    return (
      <Box border="1px solid" borderColor="border.muted" rounded="md" p="3" bg="bg.subtle">
        <HStack justify="space-between">
          <Heading size="xs">Proof-of-Exploit</Heading>
          <Text fontSize="xs" color="fg.muted">no PoE yet — rescue-prove will run after the next simulation pass</Text>
        </HStack>
      </Box>
    );
  }

  const verdictColor =
    poe.verdict === "true_positive_drained"
      ? "red"
      : poe.verdict === "true_positive_partial"
        ? "orange"
        : poe.verdict === "victim_approval_rescue"
          ? "purple"
          : poe.verdict === "requires_flashloan_helper"
            ? "blue"
            : poe.verdict === "requires_safe_signing"
              ? "teal"
              : poe.verdict === "trapped_assets_only"
                ? "yellow"
                : poe.verdict === "no_rescue_possible"
                  ? "yellow"
                  : poe.verdict === "skipped"
                    ? "gray"
                    : "red";

  return (
    <Box border="1px solid" borderColor={`${verdictColor}.muted`} rounded="md" p="4" bg={`${verdictColor}.subtle`}>
      <Stack gap="3">
        <HStack justify="space-between" wrap="wrap" gap="2">
          <HStack gap="2">
            <Heading size="sm">Proof-of-Exploit</Heading>
            <Badge colorPalette={verdictColor}>{poe.verdict}</Badge>
            <Badge variant="outline" size="xs">
              {poe.engine}@{poe.engineVersion}
            </Badge>
            {poe.drainPlan.some((s) => s.executor === "owner") && (
              <Badge colorPalette="purple" size="xs" title={
                "At least one drain step needs the owner's signing key. The live broadcaster " +
                "refuses to send these unless RESCUE_OWNER_PRIVATE_KEY is configured with the " +
                "correct deployer key — your stated 'deployer authorises rescue' workflow."
              }>
                owner-required
              </Badge>
            )}
          </HStack>
          <HStack gap="3" fontSize="xs" color="fg.muted">
            <Text>block: {poe.blockNumber ?? "?"}</Text>
            <Text>attacker: {poe.attackerKind}</Text>
            {poe.executorOwner && (
              <Text title={poe.executorOwner}>
                owner: {poe.executorOwner.slice(0, 6)}…{poe.executorOwner.slice(-4)}
              </Text>
            )}
            <Text>{poe.durationMs} ms</Text>
          </HStack>
        </HStack>

        {poe.totalRescuedUsd != null && (
          <HStack gap="6">
            <Box>
              <Text fontSize="xs" color="fg.muted" textTransform="uppercase">Rescuable</Text>
              <Text fontSize="xl" fontWeight="bold" color={`${verdictColor}.fg`}>
                {fmtUsd(poe.totalRescuedUsd)}
              </Text>
            </Box>
            <Box>
              <Text fontSize="xs" color="fg.muted" textTransform="uppercase">Assets</Text>
              <Text fontSize="xl" fontWeight="bold">{poe.rescuedAssets.length}</Text>
            </Box>
            <Box>
              <Text fontSize="xs" color="fg.muted" textTransform="uppercase">Drain steps</Text>
              <Text fontSize="xl" fontWeight="bold">
                {poe.drainPlan.filter((s) => s.success).length}/{poe.drainPlan.length}
              </Text>
            </Box>
          </HStack>
        )}

        {poe.rescuedAssets.length > 0 && (
          <Box bg="bg.canvas" rounded="md" p="2">
            <Text fontSize="xs" color="fg.muted" textTransform="uppercase" mb="1">
              Rescuable assets
            </Text>
            <Stack gap="1">
              {poe.rescuedAssets.map((a, i) => (
                <HStack key={i} fontSize="sm" justify="space-between">
                  <HStack gap="2">
                    <Text fontFamily="mono" fontSize="xs">
                      {a.symbol} {a.token ? `(${shortHash(a.token)})` : "(native)"}
                    </Text>
                    {a.quirk && a.quirk.kind !== "normal" && (
                      <Badge
                        size="xs"
                        colorPalette={
                          a.quirk.kind === "fee-on-transfer"
                            ? "orange"
                            : a.quirk.kind === "paused" || a.quirk.kind === "blacklisted"
                              ? "red"
                              : "gray"
                        }
                        title={a.quirk.detail}
                      >
                        {a.quirk.kind}
                        {a.quirk.kind === "fee-on-transfer" && a.quirk.feeBps != null
                          ? ` ${(a.quirk.feeBps / 100).toFixed(2)}%`
                          : ""}
                      </Badge>
                    )}
                  </HStack>
                  <Text fontFamily="mono" fontSize="xs">
                    {fmtTokenAmount(a.amountBase, a.decimals)}
                  </Text>
                  <Text color="fg.muted" minW="80px" textAlign="right">
                    {a.usdValue != null ? fmtUsd(a.usdValue) : "—"}
                  </Text>
                </HStack>
              ))}
            </Stack>
          </Box>
        )}

        {/* v3-Q: trapped assets — value the contract holds that can't be drained */}
        {poe.trappedAssets && poe.trappedAssets.length > 0 && (
          <Box bg="yellow.subtle" border="1px solid" borderColor="yellow.muted" rounded="md" p="2">
            <HStack justify="space-between" mb="1">
              <Text fontSize="xs" color="fg.muted" textTransform="uppercase">
                Trapped assets (not rescuable)
              </Text>
              <Text fontSize="xs" color="yellow.fg" fontWeight="bold">
                {fmtUsd(
                  poe.trappedAssets.reduce(
                    (acc, t) => (t.usdValue != null ? acc + t.usdValue : acc),
                    0,
                  ),
                )}
              </Text>
            </HStack>
            <Stack gap="1">
              {poe.trappedAssets.slice(0, 12).map((t, i) => (
                <HStack key={i} fontSize="xs" justify="space-between">
                  <Text fontFamily="mono">
                    {t.symbol} {t.token ? `(${shortHash(t.token)})` : "(native)"}
                  </Text>
                  <Text fontFamily="mono" color="fg.muted">
                    {fmtTokenAmount(t.balance, t.decimals)}
                  </Text>
                  <Text color="yellow.fg" minW="160px" textAlign="right">
                    {t.reason.slice(0, 40)}
                  </Text>
                </HStack>
              ))}
              {poe.trappedAssets.length > 12 && (
                <Text fontSize="xs" color="fg.muted">
                  …and {poe.trappedAssets.length - 12} more
                </Text>
              )}
            </Stack>
          </Box>
        )}

        {/* v3-A: approval-surface victims */}
        {poe.approvalVictims && poe.approvalVictims.length > 0 && (
          <Box
            bg="purple.subtle"
            border="1px solid"
            borderColor="purple.muted"
            rounded="md"
            p="2"
          >
            <HStack justify="space-between" mb="1">
              <HStack gap="2">
                <Text fontSize="xs" color="purple.fg" textTransform="uppercase" fontWeight="bold">
                  Approval-surface victims
                </Text>
                <Badge colorPalette="purple" size="xs" title="These are VICTIMS' funds, not the contract's. Live rescue requires per-victim off-chain consent listed in RESCUE_APPROVAL_CONSENT_VICTIMS env.">
                  CONSENT REQUIRED
                </Badge>
              </HStack>
              <Text fontSize="xs" color="purple.fg" fontWeight="bold">
                {fmtUsd(
                  poe.approvalVictims.reduce(
                    (acc, v) => (v.drainableUsd != null ? acc + v.drainableUsd : acc),
                    0,
                  ),
                )}{" "}
                ({poe.approvalVictims.filter((v) => v.consented).length}/
                {poe.approvalVictims.length} consented)
              </Text>
            </HStack>
            <Stack gap="1">
              {poe.approvalVictims.slice(0, 10).map((v, i) => (
                <HStack key={i} fontSize="xs" justify="space-between">
                  <Text fontFamily="mono">
                    {shortHash(v.victim)}{" "}
                    {v.consented ? (
                      <Badge colorPalette="green" size="xs" ml="1">
                        consented
                      </Badge>
                    ) : null}
                  </Text>
                  <Text fontFamily="mono" color="fg.muted">
                    {v.tokenSymbol} {fmtTokenAmount(v.drainable, v.tokenDecimals)}
                  </Text>
                  <Text color="purple.fg" minW="80px" textAlign="right">
                    {v.drainableUsd != null ? fmtUsd(v.drainableUsd) : "—"}
                  </Text>
                </HStack>
              ))}
              {poe.approvalVictims.length > 10 && (
                <Text fontSize="xs" color="fg.muted">
                  …and {poe.approvalVictims.length - 10} more
                </Text>
              )}
            </Stack>
          </Box>
        )}

        {/* v3-FL: flashloan requirement */}
        {poe.flashloanRequirement && (
          <Box bg="blue.subtle" border="1px solid" borderColor="blue.muted" rounded="md" p="2">
            <HStack gap="2" mb="1">
              <Text fontSize="xs" color="blue.fg" textTransform="uppercase" fontWeight="bold">
                Flash-loan requirement
              </Text>
              <Badge colorPalette="blue" size="xs">
                {poe.flashloanRequirement.asset}
              </Badge>
            </HStack>
            <Text fontSize="xs">
              suggested pool:{" "}
              <Text as="span" fontFamily="mono">
                {poe.flashloanRequirement.suggestedPool ?? "n/a for this chain"}
              </Text>
            </Text>
            {poe.flashloanRequirement.notes.map((n, i) => (
              <Text key={i} fontSize="xs" color="fg.muted" mt="1">
                • {n}
              </Text>
            ))}
          </Box>
        )}

        {/* v4-Safe: Safe-multisig requirement */}
        {poe.safeRequirement && (
          <Box bg="teal.subtle" border="1px solid" borderColor="teal.muted" rounded="md" p="2">
            <HStack gap="2" mb="1">
              <Text fontSize="xs" color="teal.fg" textTransform="uppercase" fontWeight="bold">
                Safe multisig — propose required
              </Text>
              {poe.safeRequirement.threshold && poe.safeRequirement.ownerCount && (
                <Badge colorPalette="teal" size="xs">
                  {poe.safeRequirement.threshold}/{poe.safeRequirement.ownerCount}
                </Badge>
              )}
            </HStack>
            <Text fontSize="xs" mb="1">
              Safe:{" "}
              <Text as="span" fontFamily="mono">
                {poe.safeRequirement.safeAddress}
              </Text>
            </Text>
            {poe.safeRequirement.appDeeplink && (
              <Button
                as="a"
                {...({ href: poe.safeRequirement.appDeeplink, target: "_blank", rel: "noreferrer" } as any)}
                size="xs"
                colorPalette="teal"
                variant="solid"
                mt="1"
              >
                Open in Safe app
              </Button>
            )}
            {poe.safeRequirement.instructions.slice(1).map((line, i) => (
              <Text key={i} fontSize="xs" color="fg.muted" mt="1">
                {line}
              </Text>
            ))}
          </Box>
        )}

        {poe.notes.length > 0 && (
          <Stack gap="1">
            {poe.notes.map((n, i) => (
              <Text key={i} fontSize="xs" color="fg.muted">
                • {n}
              </Text>
            ))}
          </Stack>
        )}

        <HStack gap="2" wrap="wrap">
          <Button
            size="xs"
            colorPalette={verdictColor}
            variant="outline"
            onClick={() => runRescue("dry-run-fork")}
            loading={rescueBusy === "dry-run-fork"}
            disabled={
              rescueBusy != null ||
              (poe.verdict !== "true_positive_drained" && poe.verdict !== "true_positive_partial")
            }
            title="Re-run the drain plan on a fresh fork. No real chain interaction."
          >
            Dry-run on fork
          </Button>
          <Button
            size="xs"
            colorPalette={verdictColor}
            variant="ghost"
            onClick={() => runRescue("dry-run-sign")}
            loading={rescueBusy === "dry-run-sign"}
            disabled={
              rescueBusy != null ||
              (poe.verdict !== "true_positive_drained" && poe.verdict !== "true_positive_partial")
            }
            title="Sign each tx locally with RESCUER_PRIVATE_KEY; returns raw payload(s), NO broadcast."
          >
            Sign only (no broadcast)
          </Button>
          {!confirmLive ? (
            <Button
              size="xs"
              colorPalette="red"
              variant="solid"
              onClick={() => setConfirmLive(true)}
              disabled={
                rescueBusy != null ||
                (poe.verdict !== "true_positive_drained" && poe.verdict !== "true_positive_partial")
              }
              title="Broadcast the drain plan against mainnet — moves funds to escrow."
            >
              Rescue (live)
            </Button>
          ) : (
            <HStack
              gap="1"
              border="1px solid"
              borderColor="red.muted"
              rounded="md"
              p="1"
              bg="red.subtle"
            >
              <Text fontSize="2xs" color="red.fg" px="1">
                broadcast to {data.finding.contractAddress?.slice(0, 8)}… on chain {data.finding.chainId}
              </Text>
              <input
                value={authToken}
                onChange={(e) => setAuthToken(e.target.value)}
                placeholder="RESCUE_AUTH_TOKEN"
                type="password"
                autoFocus
                style={{
                  fontSize: "11px",
                  fontFamily: "monospace",
                  padding: "2px 6px",
                  width: "200px",
                  border: "1px solid var(--chakra-colors-red-muted)",
                  borderRadius: 4,
                  background: "var(--chakra-colors-bg-canvas)",
                }}
              />
              <Button
                size="xs"
                colorPalette="red"
                variant="solid"
                onClick={() => runRescue("live")}
                loading={rescueBusy === "live"}
                disabled={!authToken || rescueBusy != null}
              >
                Confirm broadcast
              </Button>
              <Button
                size="xs"
                variant="ghost"
                onClick={() => {
                  setConfirmLive(false);
                  setAuthToken("");
                }}
                disabled={rescueBusy != null}
              >
                Cancel
              </Button>
            </HStack>
          )}
          <Button size="xs" variant="ghost" asChild>
            <a href={`/api/proofs/${findingId}/poe.json`} download>
              Download PoE JSON
            </a>
          </Button>
          <Text fontSize="xs" color="fg.muted">
            escrow: <Text as="span" fontFamily="mono">{shortHash(poe.escrowAddress)}</Text>
          </Text>
        </HStack>

        {rescueResult && (
          <Text
            fontSize="xs"
            color="fg.muted"
            fontFamily="mono"
            whiteSpace="pre-wrap"
            bg="bg.canvas"
            p="2"
            rounded="md"
          >
            {rescueResult}
          </Text>
        )}

        {data.actions.length > 0 && (
          <Box>
            <Text fontSize="xs" color="fg.muted" textTransform="uppercase" mb="1">
              Timeline
            </Text>
            <Stack gap="1">
              {data.actions.slice(-10).map((a) => (
                <Text key={a.id} fontSize="xs" fontFamily="mono" color="fg.muted">
                  {new Date(a.at).toISOString().replace("T", " ").slice(0, 19)} · {a.kind}
                  {a.actor ? ` · ${a.actor}` : ""}
                </Text>
              ))}
            </Stack>
          </Box>
        )}
      </Stack>
    </Box>
  );
}
