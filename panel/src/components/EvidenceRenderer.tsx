"use client";

import { Badge, Box, HStack, Heading, Stack, Text } from "@chakra-ui/react";

interface Props {
  raw: any;
}

function Section({ title, children, count }: { title: string; children: React.ReactNode; count?: number }) {
  return (
    <Box bg="bg.subtle" rounded="md" p="3" border="1px solid" borderColor="border">
      <HStack mb="2" justify="space-between">
        <Heading size="xs" textTransform="uppercase" color="fg.muted">
          {title}
        </Heading>
        {count != null && (
          <Badge variant="subtle" size="xs">
            {count}
          </Badge>
        )}
      </HStack>
      {children}
    </Box>
  );
}

function asArray(v: any): any[] {
  if (Array.isArray(v)) return v;
  if (v == null) return [];
  if (typeof v === "object") return Object.values(v);
  return [v];
}

function Pair({ k, v }: { k: string; v: any }) {
  return (
    <HStack align="flex-start" gap="3">
      <Text fontSize="xs" color="fg.muted" minW="120px" fontFamily="mono">
        {k}
      </Text>
      <Text fontSize="xs" fontFamily="mono" wordBreak="break-all">
        {typeof v === "object" ? JSON.stringify(v) : String(v)}
      </Text>
    </HStack>
  );
}

export function EvidenceRenderer({ raw }: Props) {
  const evidence = raw?.evidence ?? {};
  const witness = raw?.witness ?? raw?.witness_evidence;
  const actions = asArray(evidence?.actions);
  const flows = asArray(evidence?.flows);
  const arithmetic = asArray(evidence?.arithmetic);
  const accounting = asArray(evidence?.accounting);
  const details = evidence?.details;
  const affected = asArray(raw?.affected_functions ?? (raw?.function ? [raw.function] : []));

  return (
    <Stack gap="3">
      {affected.length > 0 && (
        <Section title="Affected functions" count={affected.length}>
          <Stack gap="1">
            {affected.map((f: any, i: number) => (
              <HStack key={i} gap="3">
                <Badge fontFamily="mono" variant="outline" size="xs">
                  {f.selector ?? "—"}
                </Badge>
                <Text fontSize="sm">{f.name ?? f.signature ?? "—"}</Text>
              </HStack>
            ))}
          </Stack>
        </Section>
      )}

      {actions.length > 0 && (
        <Section title="Actions" count={actions.length}>
          <Stack gap="1.5">
            {actions.map((a: any, i: number) => (
              <Box key={i} fontFamily="mono" fontSize="xs">
                <HStack gap="2">
                  <Badge variant="outline" size="xs">
                    {a.kind ?? a.opcode ?? "action"}
                  </Badge>
                  {a.pc != null && (
                    <Text color="fg.muted">pc={a.pc}</Text>
                  )}
                  {a.opcode && a.kind !== a.opcode && (
                    <Text color="fg.muted">{a.opcode}</Text>
                  )}
                </HStack>
                {a.detail && <Text mt="0.5" wordBreak="break-all">{a.detail}</Text>}
                {a.note && <Text mt="0.5" color="fg.muted">{a.note}</Text>}
                {a.target && <Text mt="0.5">→ {a.target}</Text>}
                {a.value != null && <Text mt="0.5">value: {String(a.value)}</Text>}
              </Box>
            ))}
          </Stack>
        </Section>
      )}

      {flows.length > 0 && (
        <Section title="Flows" count={flows.length}>
          <Stack gap="2">
            {flows.map((f: any, i: number) => (
              <Box key={i} fontFamily="mono" fontSize="xs">
                <HStack gap="1.5" wrap="wrap">
                  {asArray(f.steps ?? f.path ?? [f.source, f.sink]).map((step: any, j: number, arr: any[]) => (
                    <HStack key={j} gap="1">
                      <Badge variant="subtle" size="xs">
                        {typeof step === "string" ? step : step?.kind ?? step?.opcode ?? "step"}
                      </Badge>
                      {j < arr.length - 1 && <Text color="fg.muted">→</Text>}
                    </HStack>
                  ))}
                </HStack>
                {f.summary && <Text mt="1">{f.summary}</Text>}
              </Box>
            ))}
          </Stack>
        </Section>
      )}

      {arithmetic.length > 0 && (
        <Section title="Arithmetic" count={arithmetic.length}>
          <Stack gap="1">
            {arithmetic.map((a: any, i: number) => (
              <HStack key={i} gap="3">
                <Badge size="xs" variant="outline">
                  {a.op ?? a.kind ?? "?"}
                </Badge>
                <Text fontSize="xs" fontFamily="mono">
                  {a.note ?? a.summary ?? JSON.stringify(a)}
                </Text>
              </HStack>
            ))}
          </Stack>
        </Section>
      )}

      {accounting.length > 0 && (
        <Section title="Accounting" count={accounting.length}>
          <Stack gap="1">
            {accounting.map((a: any, i: number) => (
              <Text key={i} fontSize="xs" fontFamily="mono">
                {a.note ?? JSON.stringify(a)}
              </Text>
            ))}
          </Stack>
        </Section>
      )}

      {details && (
        <Section title="Details">
          <Stack gap="1">
            {Object.entries(details).map(([k, v]) => (
              <Pair key={k} k={k} v={v} />
            ))}
          </Stack>
        </Section>
      )}

      {witness && (
        <Section title="Witness">
          <Stack gap="1">
            {Object.entries(witness).map(([k, v]) => (
              <Pair key={k} k={k} v={v} />
            ))}
          </Stack>
        </Section>
      )}
    </Stack>
  );
}

export function CounterEvidenceRenderer({ raw }: Props) {
  const ce = raw?.counter_evidence ?? {};
  const matched = asArray(ce?.matched ?? ce?.tokens_matched);
  const unmatched = asArray(ce?.unmatched ?? ce?.tokens_unmatched);
  const requirements = ce?.requirements ?? raw?.analysis_requirements;
  const coverage = raw?.coverage_gates ?? ce?.coverage_gates;
  return (
    <Stack gap="3">
      <Section title="Tokens matched" count={matched.length}>
        {matched.length === 0 ? (
          <Text fontSize="xs" color="fg.muted">none</Text>
        ) : (
          <HStack wrap="wrap" gap="1">
            {matched.map((t: any, i: number) => (
              <Badge key={i} variant="subtle" colorPalette="orange" size="xs">
                {typeof t === "string" ? t : t.id ?? JSON.stringify(t)}
              </Badge>
            ))}
          </HStack>
        )}
      </Section>
      <Section title="Tokens unmatched" count={unmatched.length}>
        {unmatched.length === 0 ? (
          <Text fontSize="xs" color="fg.muted">none</Text>
        ) : (
          <HStack wrap="wrap" gap="1">
            {unmatched.map((t: any, i: number) => (
              <Badge key={i} variant="outline" size="xs">
                {typeof t === "string" ? t : t.id ?? JSON.stringify(t)}
              </Badge>
            ))}
          </HStack>
        )}
      </Section>
      {requirements && (
        <Section title="Analysis requirements">
          <Stack gap="1">
            {Object.entries(requirements).map(([k, v]) => (
              <Pair key={k} k={k} v={v} />
            ))}
          </Stack>
        </Section>
      )}
      {coverage && (
        <Section title="Coverage gates">
          <Stack gap="1">
            {Object.entries(coverage as any).map(([k, v]) => (
              <Pair key={k} k={k} v={v} />
            ))}
          </Stack>
        </Section>
      )}
    </Stack>
  );
}
