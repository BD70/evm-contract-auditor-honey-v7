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
import { fmtAge, shortHash, SEVERITY_COLORS } from "@/src/lib/format";
import { CHAINS, chainName } from "@/src/lib/chains";

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

  const query = useMemo(() => {
    const p = new URLSearchParams();
    p.set("limit", String(limit));
    p.set("offset", String(offset));
    if (search) p.set("q", search);
    if (sevFilter.length) p.set("severity", sevFilter.join(","));
    if (source) p.set("source", source);
    if (chainId) p.set("chainId", chainId);
    return p.toString();
  }, [search, sevFilter, source, chainId, offset]);

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
                <Table.Cell colSpan={9}>
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
