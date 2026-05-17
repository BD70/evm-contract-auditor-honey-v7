"use client";

import {
  Badge,
  Box,
  Grid,
  GridItem,
  HStack,
  Heading,
  SimpleGrid,
  Stack,
  Text,
} from "@chakra-ui/react";
import { useEffect, useState } from "react";
import Link from "next/link";
import { LogStream } from "./LogStream";
import { fmtAge, fmtDuration, shortHash, SEVERITY_COLORS } from "@/src/lib/format";
import { chainName } from "@/src/lib/chains";

interface RunnerSnap {
  status: string;
  pid: number | null;
  startedAt: number | null;
  lastExitCode: number | null;
  lastError: string | null;
  health: any;
  metrics: Record<string, number> | null;
}

interface FindingRow {
  id: string;
  ruleId: string;
  severity: string;
  title: string | null;
  contractAddress?: string | null;
  discoveredAt: number;
  source: string;
}

export function Dashboard() {
  const [snap, setSnap] = useState<RunnerSnap | null>(null);
  const [recent, setRecent] = useState<FindingRow[]>([]);
  const [sevCounts, setSevCounts] = useState<Record<string, number>>({});
  const [chains, setChains] = useState<
    { slug: string; name: string; enabled: boolean; runner: { status: string } | null }[]
  >([]);

  useEffect(() => {
    let alive = true;
    const load = () =>
      fetch("/api/chains")
        .then((r) => r.json())
        .then((j) => {
          if (alive) setChains(j.chains ?? []);
        })
        .catch(() => {});
    load();
    const t = setInterval(load, 7000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  useEffect(() => {
    let alive = true;
    const fetchAll = async () => {
      try {
        const [s, f] = await Promise.all([
          fetch("/api/runner/status").then((r) => r.json()),
          fetch("/api/findings?limit=10").then((r) => r.json()),
        ]);
        if (!alive) return;
        setSnap(s);
        setRecent(f.rows ?? []);
        setSevCounts(f.severityCounts ?? {});
      } catch {}
    };
    fetchAll();
    const t = setInterval(fetchAll, 7000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  useEffect(() => {
    const es = new EventSource("/api/runner/stream");
    es.addEventListener("state", (e: MessageEvent) => {
      try { setSnap(JSON.parse(e.data)); } catch {}
    });
    return () => es.close();
  }, []);

  useEffect(() => {
    const es = new EventSource("/api/findings/stream");
    es.addEventListener("finding", (e: MessageEvent) => {
      try {
        const evt = JSON.parse(e.data) as FindingRow;
        setRecent((prev) => [evt, ...prev].slice(0, 10));
      } catch {}
    });
    return () => es.close();
  }, []);

  const audits = snap?.metrics?.evm_runner_audits_total ?? 0;
  const errors = snap?.metrics?.evm_runner_audit_errors_total ?? 0;
  const queue = snap?.metrics?.evm_runner_queue_depth ?? 0;
  const uptime = snap?.metrics?.evm_runner_uptime_seconds ?? 0;
  const lastBlock = snap?.health?.lastProcessedBlock ?? snap?.health?.checkpoint?.lastProcessedBlock ?? null;
  const chainId = snap?.health?.chainId ?? null;

  return (
    <Stack gap="5">
      <Heading size="lg">Dashboard</Heading>

      {chains.length > 0 && (
        <Card>
          <HStack justify="space-between" mb="3">
            <Heading size="sm">Chains</Heading>
            <Link href="/chains" style={{ fontSize: 12 }}>
              manage →
            </Link>
          </HStack>
          <SimpleGrid columns={{ base: 1, md: 2, lg: 4 }} gap="3">
            {chains.map((c) => {
              const st = c.runner?.status ?? "idle";
              return (
                <HStack
                  key={c.slug}
                  justify="space-between"
                  bg="bg.subtle"
                  rounded="md"
                  px="3"
                  py="2"
                >
                  <Stack gap="0">
                    <Text fontSize="sm" fontWeight="medium" lineClamp={1}>
                      {c.name}
                    </Text>
                    <Text fontSize="xs" color="fg.muted" fontFamily="mono">
                      {c.slug}
                    </Text>
                  </Stack>
                  <Badge
                    variant="subtle"
                    colorPalette={
                      st === "running" ? "green" : st === "crashed" ? "red" : st === "idle" ? "gray" : "yellow"
                    }
                    size="sm"
                  >
                    {c.enabled ? st : "disabled"}
                  </Badge>
                </HStack>
              );
            })}
          </SimpleGrid>
        </Card>
      )}

      <SimpleGrid columns={{ base: 1, md: 2, lg: 4 }} gap="4">
        <Card>
          <Text fontSize="xs" color="fg.muted" textTransform="uppercase">
            Runner
          </Text>
          <HStack mt="1" gap="2">
            <Heading size="md">{snap?.status ?? "—"}</Heading>
            {snap?.pid && (
              <Badge variant="subtle" colorPalette="gray">
                pid {snap.pid}
              </Badge>
            )}
          </HStack>
          <Text fontSize="xs" color="fg.muted" mt="2">
            Uptime: {uptime ? fmtDuration(uptime * 1000) : "—"}
          </Text>
          {snap?.lastError && (
            <Text fontSize="xs" color="red.500" mt="1">
              {snap.lastError}
            </Text>
          )}
        </Card>

        <Card>
          <Text fontSize="xs" color="fg.muted" textTransform="uppercase">
            Last block
          </Text>
          <Heading size="md" mt="1">
            {lastBlock != null ? lastBlock : "—"}
          </Heading>
          <Text fontSize="xs" color="fg.muted" mt="2">
            {chainName(chainId)}
          </Text>
        </Card>

        <Card>
          <Text fontSize="xs" color="fg.muted" textTransform="uppercase">
            Audits run
          </Text>
          <Heading size="md" mt="1">
            {audits}
          </Heading>
          <Text fontSize="xs" color="fg.muted" mt="2">
            queue depth {queue}; {errors} errors
          </Text>
        </Card>

        <Card>
          <Text fontSize="xs" color="fg.muted" textTransform="uppercase">
            Findings (24h)
          </Text>
          <Heading size="md" mt="1">
            {Object.values(sevCounts).reduce((a, b) => a + b, 0)}
          </Heading>
          <HStack mt="2" gap="1" wrap="wrap">
            {["critical", "high", "medium", "low"].map((s) =>
              sevCounts[s] ? (
                <Badge key={s} colorPalette={SEVERITY_COLORS[s] ?? "gray"} variant="subtle" size="xs">
                  {s}: {sevCounts[s]}
                </Badge>
              ) : null,
            )}
          </HStack>
        </Card>
      </SimpleGrid>

      <Grid templateColumns={{ base: "1fr", lg: "2fr 1fr" }} gap="5">
        <GridItem>
          <Card>
            <HStack justify="space-between" mb="3">
              <Heading size="sm">Live logs</Heading>
              <Link href="/logs" style={{ fontSize: 12 }}>
                expand →
              </Link>
            </HStack>
            <LogStream maxHeight="420px" maxLines={50} />
          </Card>
        </GridItem>
        <GridItem>
          <Card>
            <HStack justify="space-between" mb="3">
              <Heading size="sm">Recent findings</Heading>
              <Link href="/findings" style={{ fontSize: 12 }}>
                browse →
              </Link>
            </HStack>
            <Stack gap="2" maxH="420px" overflowY="auto">
              {recent.length === 0 && (
                <Text fontSize="sm" color="fg.muted">
                  none yet
                </Text>
              )}
              {recent.map((f) => (
                <Link key={f.id} href={`/findings/${f.id}`} style={{ textDecoration: "none" }}>
                  <Box
                    p="2"
                    rounded="md"
                    bg="bg.subtle"
                    _hover={{ bg: "bg.muted" }}
                    borderLeft="3px solid"
                    borderColor={`${SEVERITY_COLORS[f.severity] ?? "gray"}.500`}
                  >
                    <HStack gap="2" mb="1">
                      <Badge colorPalette={SEVERITY_COLORS[f.severity] ?? "gray"} size="xs" variant="subtle">
                        {f.severity}
                      </Badge>
                      <Text fontSize="xs" color="fg.muted">
                        {fmtAge(f.discoveredAt)}
                      </Text>
                    </HStack>
                    <Text fontSize="sm" fontWeight="medium" lineClamp={1}>
                      {f.title ?? f.ruleId}
                    </Text>
                    <Text fontSize="xs" color="fg.muted">
                      {f.ruleId}
                      {f.contractAddress ? ` · ${shortHash(f.contractAddress)}` : ""}
                    </Text>
                  </Box>
                </Link>
              ))}
            </Stack>
          </Card>
        </GridItem>
      </Grid>
    </Stack>
  );
}

function Card(props: React.ComponentProps<typeof Box>) {
  return (
    <Box
      bg="bg.panel"
      border="1px solid"
      borderColor="border"
      rounded="lg"
      p="4"
      {...props}
    />
  );
}
