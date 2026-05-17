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
  Textarea,
} from "@chakra-ui/react";
import { useEffect, useState } from "react";
import { JsonView } from "./JsonView";
import { SEVERITY_COLORS } from "@/src/lib/format";

interface RulePayload {
  meta: {
    ruleId: string;
    internalName: string | null;
    severity: string | null;
    category: string | null;
    userSummary: string | null;
    technicalSummary: string | null;
    fileName: string;
  };
  raw: any;
  rawText: string;
  filePath: string;
}

export function RuleDetail({ ruleId }: { ruleId: string }) {
  const [rule, setRule] = useState<RulePayload | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [auditJsonText, setAuditJsonText] = useState("");
  const [explainResult, setExplainResult] = useState<any>(null);
  const [explainPending, setExplainPending] = useState(false);
  const [testResult, setTestResult] = useState<any>(null);
  const [testPending, setTestPending] = useState(false);

  useEffect(() => {
    fetch(`/api/rules/${encodeURIComponent(ruleId)}`)
      .then((r) => (r.ok ? r.json() : r.json().then((j) => Promise.reject(j))))
      .then(setRule)
      .catch((e) => setErr(e?.error ?? "load failed"));
  }, [ruleId]);

  if (err) return <Text color="red.500">{err}</Text>;
  if (!rule) return <Text color="fg.muted">loading…</Text>;

  const handleExplain = async () => {
    let parsed: any;
    try {
      parsed = JSON.parse(auditJsonText);
    } catch (e: any) {
      setExplainResult({ error: `invalid JSON: ${e.message}` });
      return;
    }
    setExplainPending(true);
    try {
      const r = await fetch(`/api/rules/${encodeURIComponent(ruleId)}/explain`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ auditJson: parsed }),
      });
      setExplainResult(await r.json());
    } catch (e: any) {
      setExplainResult({ error: e?.message ?? String(e) });
    } finally {
      setExplainPending(false);
    }
  };

  const handleTest = async () => {
    setTestPending(true);
    try {
      const r = await fetch(`/api/rules/${encodeURIComponent(ruleId)}/test`, { method: "POST" });
      setTestResult(await r.json());
    } catch (e: any) {
      setTestResult({ error: e?.message ?? String(e) });
    } finally {
      setTestPending(false);
    }
  };

  return (
    <Stack gap="4">
      <Box>
        <HStack gap="2" mb="2" wrap="wrap">
          {rule.meta.severity && (
            <Badge colorPalette={SEVERITY_COLORS[rule.meta.severity] ?? "gray"} variant="subtle">
              {rule.meta.severity}
            </Badge>
          )}
          {rule.meta.category && <Badge variant="outline">{rule.meta.category}</Badge>}
        </HStack>
        <Heading size="md" fontFamily="mono">
          {rule.meta.ruleId}
        </Heading>
        {rule.meta.internalName && (
          <Text fontFamily="mono" fontSize="xs" color="fg.muted">
            {rule.meta.internalName}
          </Text>
        )}
        {rule.meta.userSummary && (
          <Text mt="2" fontSize="sm">
            {rule.meta.userSummary}
          </Text>
        )}
        {rule.meta.technicalSummary && (
          <Text mt="1" fontSize="sm" color="fg.muted">
            {rule.meta.technicalSummary}
          </Text>
        )}
      </Box>

      <Tabs.Root defaultValue="json" variant="line">
        <Tabs.List>
          <Tabs.Trigger value="json">Detector JSON</Tabs.Trigger>
          <Tabs.Trigger value="explain">Explain</Tabs.Trigger>
          <Tabs.Trigger value="test">Corpus tests</Tabs.Trigger>
        </Tabs.List>

        <Tabs.Content value="json">
          <JsonView value={rule.raw} maxHeight="70vh" />
        </Tabs.Content>

        <Tabs.Content value="explain">
          <Stack gap="3">
            <Text fontSize="sm" color="fg.muted">
              Paste an audit JSON (typically the output of <code>evm_decon --format json</code>) to run <code>evm_rule explain</code>.
            </Text>
            <Textarea
              rows={10}
              value={auditJsonText}
              onChange={(e) => setAuditJsonText(e.target.value)}
              placeholder='{ "schema": "evm-audit.behavior.v2", ... }'
              fontFamily="mono"
              fontSize="xs"
            />
            <HStack>
              <Button size="sm" colorPalette="purple" onClick={handleExplain} loading={explainPending} disabled={!auditJsonText.trim()}>
                Run explain
              </Button>
            </HStack>
            {explainResult && (
              <Box>
                {explainResult.error && (
                  <Text color="red.500" fontSize="sm">
                    {explainResult.error}
                  </Text>
                )}
                {explainResult.stdout && (
                  <Box mt="2">
                    <Text fontSize="xs" color="fg.muted">stdout</Text>
                    <JsonView value={explainResult.stdout} maxHeight="320px" />
                  </Box>
                )}
                {explainResult.stderr && (
                  <Box mt="2">
                    <Text fontSize="xs" color="fg.muted">stderr</Text>
                    <Box as="pre" bg="bg.subtle" p="2" fontSize="xs" rounded="md" maxH="220px" overflow="auto">
                      {explainResult.stderr}
                    </Box>
                  </Box>
                )}
              </Box>
            )}
          </Stack>
        </Tabs.Content>

        <Tabs.Content value="test">
          <Stack gap="3">
            <Text fontSize="sm" color="fg.muted">
              Runs <code>evm_rule test &lt;rule&gt; &lt;corpus&gt;</code> against the detector's fixture corpus.
            </Text>
            <HStack>
              <Button size="sm" colorPalette="purple" onClick={handleTest} loading={testPending}>
                Run corpus tests
              </Button>
              {testResult?.corpusDir && (
                <Text fontSize="xs" color="fg.muted" fontFamily="mono">
                  {testResult.corpusDir}
                </Text>
              )}
            </HStack>
            {testResult && (
              <Stack gap="2">
                {testResult.code != null && (
                  <Badge colorPalette={testResult.code === 0 ? "green" : "red"} variant="subtle" w="fit-content">
                    exit {testResult.code}
                  </Badge>
                )}
                {testResult.stdout && (
                  <Box>
                    <Text fontSize="xs" color="fg.muted">stdout</Text>
                    <Box as="pre" bg="bg.inverted" color="fg.inverted" p="2" fontSize="xs" rounded="md" maxH="320px" overflow="auto" whiteSpace="pre-wrap">
                      {testResult.stdout}
                    </Box>
                  </Box>
                )}
                {testResult.stderr && (
                  <Box>
                    <Text fontSize="xs" color="fg.muted">stderr</Text>
                    <Box as="pre" bg="bg.subtle" p="2" fontSize="xs" rounded="md" maxH="220px" overflow="auto">
                      {testResult.stderr}
                    </Box>
                  </Box>
                )}
              </Stack>
            )}
          </Stack>
        </Tabs.Content>
      </Tabs.Root>
    </Stack>
  );
}
