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
import { fmtTs, SEVERITY_COLORS, shortHash } from "@/src/lib/format";
import { chainName } from "@/src/lib/chains";
import { EvidenceRenderer, CounterEvidenceRenderer } from "./EvidenceRenderer";
import { JsonView } from "./JsonView";

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
          {f.contract_address && (
            <Text fontSize="xs" color="fg.muted" fontFamily="mono">
              contract {shortHash(f.contract_address, 10, 6)}
            </Text>
          )}
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
