"use client";

import {
  Badge,
  Box,
  Button,
  Checkbox,
  HStack,
  Heading,
  Input,
  Stack,
  Switch,
  Text,
  Table,
} from "@chakra-ui/react";
import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { BytecodeInput, type InputValue } from "./BytecodeInput";
import { JsonView } from "./JsonView";
import { fmtAge, fmtDuration, SEVERITY_COLORS } from "@/src/lib/format";

interface RunRow {
  id: string;
  kind: string;
  inputSummary: string | null;
  startedAt: number;
  durationMs: number | null;
  status: string;
  findingCount: number | null;
  error: string | null;
}

interface ProgressEvt {
  ts: number;
  level: "info" | "warn" | "error";
  msg: string;
}

interface FindingRow {
  id: string;
  ruleId: string;
  severity: string;
  title: string | null;
  simulationStatus: string | null;
  simulationVerdict: string | null;
  simulationEngine: string | null;
  simulationAttackerKind: "any" | "owner" | null;
}

const SIM_BADGE_COLOR: Record<string, string> = {
  verified: "red",
  not_exploitable: "green",
  inconclusive: "yellow",
  skipped: "gray",
  error: "orange",
};

function simBadgeLabel(s: string | null, attackerKind: "any" | "owner" | null = null): string {
  switch (s) {
    case "verified":
      return attackerKind === "owner" ? "OWNER-ONLY exploit" : "exploit witnessed (any caller)";
    case "not_exploitable": return "no exploit (likely FP)";
    case "inconclusive": return "inconclusive";
    case "skipped": return "sim skipped";
    case "error": return "sim error";
    default: return "sim pending";
  }
}

function simBadgePalette(s: string | null, attackerKind: "any" | "owner" | null = null): string {
  if (s === "verified" && attackerKind === "owner") return "orange";
  return SIM_BADGE_COLOR[s ?? ""] ?? "purple";
}

export function TestRunner() {
  const [input, setInput] = useState<InputValue | null>(null);
  const [llmJudge, setLlmJudge] = useState(false);
  const [refreshJudge, setRefreshJudge] = useState(false);
  const [rulesPath, setRulesPath] = useState("");
  const [runId, setRunId] = useState<string | null>(null);
  const [progress, setProgress] = useState<ProgressEvt[]>([]);
  const [done, setDone] = useState<{ status: string; findingCount: number } | null>(null);
  const [result, setResult] = useState<any>(null);
  const [findingRows, setFindingRows] = useState<FindingRow[]>([]);
  const [runs, setRuns] = useState<RunRow[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const esRef = useRef<EventSource | null>(null);
  const pollRef = useRef<NodeJS.Timeout | null>(null);

  const loadRuns = async () => {
    try {
      const j = await fetch("/api/audits").then((r) => r.json());
      setRuns(j.rows ?? []);
    } catch {}
  };

  useEffect(() => {
    loadRuns();
  }, []);

  useEffect(() => {
    if (!runId) return;
    const es = new EventSource(`/api/audits/stream/${runId}`);
    esRef.current = es;
    es.addEventListener("progress", (e: MessageEvent) => {
      try {
        setProgress((p) => [...p, JSON.parse(e.data)]);
      } catch {}
    });
    es.addEventListener("done", (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data);
        setDone({ status: data.status, findingCount: data.findingCount });
        // Initial fetch + start polling for sim verdicts to land. The
        // background sim worker is wake()'d on ingest so verdicts typically
        // arrive within seconds; we poll for ~60s and stop when every
        // finding has a verdict (or the user navigates away).
        const refresh = () =>
          fetch(`/api/audits/${runId}`)
            .then((r) => r.json())
            .then((j) => {
              setResult(j.raw ?? null);
              const rows: FindingRow[] = Array.isArray(j.findings) ? j.findings : [];
              setFindingRows(rows);
              return rows;
            })
            .catch(() => [] as FindingRow[]);
        refresh().then((rows) => {
          if (pollRef.current) clearInterval(pollRef.current);
          const startedAt = Date.now();
          pollRef.current = setInterval(() => {
            const allDone = rows.length > 0 && rows.every((r) => r.simulationStatus != null);
            if (allDone || Date.now() - startedAt > 60_000) {
              if (pollRef.current) {
                clearInterval(pollRef.current);
                pollRef.current = null;
              }
              return;
            }
            refresh().then((updated) => {
              rows = updated;
            });
          }, 2500);
        });
        loadRuns();
      } catch {}
    });
    return () => {
      es.close();
      esRef.current = null;
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
    };
  }, [runId]);

  const submit = async () => {
    if (!input) return;
    setSubmitting(true);
    setProgress([]);
    setDone(null);
    setResult(null);
    try {
      const r = await fetch("/api/audits", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...input,
          llmJudge,
          llmJudgeRefresh: llmJudge && refreshJudge,
          rulesPath: rulesPath || undefined,
        }),
      });
      const j = await r.json();
      if (j.ok && j.runId) {
        setRunId(j.runId);
      } else {
        setProgress([{ ts: Date.now(), level: "error", msg: j.error ?? "submit failed" }]);
      }
    } catch (err: any) {
      setProgress([{ ts: Date.now(), level: "error", msg: err?.message ?? String(err) }]);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Stack gap="5">
      <Heading size="lg">Manual audit</Heading>

      <Box bg="bg.panel" border="1px solid" borderColor="border" rounded="lg" p="4">
        <Stack gap="4">
          <BytecodeInput onChange={setInput} />

          <HStack gap="6" wrap="wrap" align="flex-end">
            <Stack gap="1">
              <Text fontSize="xs" color="fg.muted">
                Rules path (optional)
              </Text>
              <Input size="sm" placeholder="rules/core" value={rulesPath} onChange={(e) => setRulesPath(e.target.value)} w="240px" />
            </Stack>
            <HStack gap="2">
              <Switch.Root checked={llmJudge} onCheckedChange={(d) => setLlmJudge(d.checked)} size="sm">
                <Switch.HiddenInput />
                <Switch.Control>
                  <Switch.Thumb />
                </Switch.Control>
                <Switch.Label>LLM judge</Switch.Label>
              </Switch.Root>
              {llmJudge && (
                <Checkbox.Root checked={refreshJudge} onCheckedChange={(d) => setRefreshJudge(d.checked === true)} size="sm">
                  <Checkbox.HiddenInput />
                  <Checkbox.Control />
                  <Checkbox.Label>refresh cache</Checkbox.Label>
                </Checkbox.Root>
              )}
            </HStack>
            <Button colorPalette="purple" onClick={submit} loading={submitting} disabled={!input}>
              Run audit
            </Button>
          </HStack>
        </Stack>
      </Box>

      {runId && (
        <Box bg="bg.panel" border="1px solid" borderColor="border" rounded="lg" p="4">
          <HStack justify="space-between" mb="2">
            <Heading size="sm">Run {runId.slice(0, 8)}…</Heading>
            {done && (
              <HStack gap="2">
                <Badge colorPalette={done.status === "ok" ? "green" : "red"} variant="subtle">
                  {done.status}
                </Badge>
                <Text fontSize="xs" color="fg.muted">
                  {done.findingCount} findings
                </Text>
              </HStack>
            )}
          </HStack>
          <Box bg="bg.inverted" color="fg.inverted" fontFamily="mono" fontSize="xs" p="2" rounded="md" maxH="240px" overflowY="auto">
            {progress.length === 0 ? <Text color="fg.muted">starting subprocess…</Text> : null}
            {progress.map((p, i) => (
              <Box key={i} display="flex" gap="2">
                <Text color="fg.muted" minW="68px">
                  {new Date(p.ts).toLocaleTimeString()}
                </Text>
                <Text color={p.level === "error" ? "red.300" : "inherit"}>{p.msg}</Text>
              </Box>
            ))}
          </Box>
          {result && (
            <Stack gap="3" mt="3">
              <HStack gap="2" wrap="wrap">
                {(result.findings ?? []).slice(0, 6).map((f: any, i: number) => (
                  <Badge key={i} colorPalette={SEVERITY_COLORS[f.severity] ?? "gray"} variant="subtle">
                    {f.severity}: {f.rule_id}
                  </Badge>
                ))}
                {(result.findings ?? []).length > 6 && (
                  <Text fontSize="xs" color="fg.muted">
                    +{result.findings.length - 6} more…
                  </Text>
                )}
              </HStack>
              {findingRows.length > 0 && (
                <Box>
                  <Text fontSize="xs" color="fg.muted" mb="2">
                    Fork-simulation verdicts (live; updates within seconds of ingest)
                  </Text>
                  <Stack gap="1.5">
                    {findingRows.map((row) => (
                      <HStack
                        key={row.id}
                        gap="2"
                        wrap="wrap"
                        bg="bg.subtle"
                        p="2"
                        rounded="md"
                        border="1px solid"
                        borderColor="border"
                      >
                        <Badge size="xs" colorPalette={SEVERITY_COLORS[row.severity] ?? "gray"} variant="subtle">
                          {row.severity}
                        </Badge>
                        <Text fontSize="xs" fontFamily="mono">{row.ruleId}</Text>
                        <Badge
                          size="xs"
                          colorPalette={simBadgePalette(row.simulationStatus, row.simulationAttackerKind)}
                          variant={row.simulationStatus === "verified" ? "solid" : "subtle"}
                          ml="auto"
                          title={row.simulationVerdict ?? undefined}
                        >
                          {simBadgeLabel(row.simulationStatus, row.simulationAttackerKind)}
                        </Badge>
                        <Link href={`/findings/${row.id}`} style={{ fontSize: 11 }}>
                          detail →
                        </Link>
                      </HStack>
                    ))}
                  </Stack>
                </Box>
              )}
              <JsonView value={result} maxHeight="320px" />
              <HStack>
                <Link href="/findings" style={{ fontSize: 13 }}>
                  see all findings →
                </Link>
              </HStack>
            </Stack>
          )}
        </Box>
      )}

      <Box bg="bg.panel" border="1px solid" borderColor="border" rounded="lg" p="4">
        <Heading size="sm" mb="2">
          Recent manual runs
        </Heading>
        <Table.Root size="sm">
          <Table.Header>
            <Table.Row>
              <Table.ColumnHeader>Run</Table.ColumnHeader>
              <Table.ColumnHeader>Kind</Table.ColumnHeader>
              <Table.ColumnHeader>Input</Table.ColumnHeader>
              <Table.ColumnHeader>Duration</Table.ColumnHeader>
              <Table.ColumnHeader>Findings</Table.ColumnHeader>
              <Table.ColumnHeader>Status</Table.ColumnHeader>
              <Table.ColumnHeader>When</Table.ColumnHeader>
            </Table.Row>
          </Table.Header>
          <Table.Body>
            {runs.filter((r) => r.kind !== "runner").slice(0, 30).map((r) => (
              <Table.Row key={r.id} _hover={{ bg: "bg.muted" }} cursor="pointer" onClick={() => setRunId(r.id)}>
                <Table.Cell>
                  <Text fontFamily="mono" fontSize="xs">
                    {r.id.slice(0, 10)}
                  </Text>
                </Table.Cell>
                <Table.Cell>
                  <Badge variant="subtle" size="xs">
                    {r.kind}
                  </Badge>
                </Table.Cell>
                <Table.Cell>
                  <Text fontSize="xs" lineClamp={1}>
                    {r.inputSummary ?? "—"}
                  </Text>
                </Table.Cell>
                <Table.Cell>
                  <Text fontSize="xs">{fmtDuration(r.durationMs)}</Text>
                </Table.Cell>
                <Table.Cell>
                  <Text fontSize="xs">{r.findingCount ?? 0}</Text>
                </Table.Cell>
                <Table.Cell>
                  <Badge colorPalette={r.status === "ok" ? "green" : r.status === "running" ? "yellow" : "red"} variant="subtle" size="xs">
                    {r.status}
                  </Badge>
                </Table.Cell>
                <Table.Cell>
                  <Text fontSize="xs" color="fg.muted">
                    {fmtAge(r.startedAt)}
                  </Text>
                </Table.Cell>
              </Table.Row>
            ))}
            {runs.length === 0 && (
              <Table.Row>
                <Table.Cell colSpan={7}>
                  <Text fontSize="sm" color="fg.muted" textAlign="center" py="4">
                    no manual runs yet
                  </Text>
                </Table.Cell>
              </Table.Row>
            )}
          </Table.Body>
        </Table.Root>
      </Box>
    </Stack>
  );
}
