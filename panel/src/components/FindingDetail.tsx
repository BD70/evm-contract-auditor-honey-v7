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
  raw: any;
  affectedFunctions: any[];
}

export function FindingDetail({ id }: { id: string }) {
  const [f, setF] = useState<Finding | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [reauditing, setReauditing] = useState(false);

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
        </HStack>
      </Box>

      <Tabs.Root defaultValue="summary" variant="line">
        <Tabs.List>
          <Tabs.Trigger value="summary">Summary</Tabs.Trigger>
          <Tabs.Trigger value="evidence">Evidence</Tabs.Trigger>
          <Tabs.Trigger value="counter">Counter-evidence</Tabs.Trigger>
          <Tabs.Trigger value="witness">Witness</Tabs.Trigger>
          <Tabs.Trigger value="judge">Judge</Tabs.Trigger>
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
