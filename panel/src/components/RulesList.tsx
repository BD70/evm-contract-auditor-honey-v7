"use client";

import { Badge, Box, HStack, Heading, Input, Stack, Text } from "@chakra-ui/react";
import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { SEVERITY_COLORS } from "@/src/lib/format";

interface RuleMeta {
  ruleId: string;
  internalName: string | null;
  severity: string | null;
  category: string | null;
  userSummary: string | null;
}

export function RulesList() {
  const [rules, setRules] = useState<RuleMeta[]>([]);
  const [q, setQ] = useState("");

  useEffect(() => {
    fetch("/api/rules")
      .then((r) => r.json())
      .then((j) => setRules(j.rules ?? []));
  }, []);

  const grouped = useMemo(() => {
    const out: Record<string, RuleMeta[]> = {};
    for (const r of rules) {
      if (q && !r.ruleId.toLowerCase().includes(q.toLowerCase()) && !(r.userSummary ?? "").toLowerCase().includes(q.toLowerCase())) continue;
      const family = r.ruleId.split(".")[0];
      (out[family] ??= []).push(r);
    }
    return Object.entries(out).sort(([a], [b]) => a.localeCompare(b));
  }, [rules, q]);

  return (
    <Stack gap="4">
      <Heading size="lg">Detector workbench</Heading>
      <HStack>
        <Input size="sm" placeholder="search detector id or summary…" value={q} onChange={(e) => setQ(e.target.value)} maxW="320px" />
        <Text fontSize="xs" color="fg.muted">
          {rules.length} detectors
        </Text>
      </HStack>
      {grouped.map(([family, items]) => (
        <Box key={family} bg="bg.panel" border="1px solid" borderColor="border" rounded="lg" p="3">
          <Heading size="xs" textTransform="uppercase" color="fg.muted" mb="2">
            {family}
          </Heading>
          <Stack gap="1.5">
            {items.map((r) => (
              <Link key={r.ruleId} href={`/rules/${encodeURIComponent(r.ruleId)}`} style={{ textDecoration: "none" }}>
                <Box p="2" rounded="md" _hover={{ bg: "bg.muted" }}>
                  <HStack gap="2">
                    {r.severity && (
                      <Badge colorPalette={SEVERITY_COLORS[r.severity] ?? "gray"} size="xs" variant="subtle">
                        {r.severity}
                      </Badge>
                    )}
                    <Text fontFamily="mono" fontSize="sm">
                      {r.ruleId}
                    </Text>
                  </HStack>
                  {r.userSummary && (
                    <Text fontSize="xs" color="fg.muted" mt="0.5" lineClamp={2}>
                      {r.userSummary}
                    </Text>
                  )}
                </Box>
              </Link>
            ))}
          </Stack>
        </Box>
      ))}
    </Stack>
  );
}
