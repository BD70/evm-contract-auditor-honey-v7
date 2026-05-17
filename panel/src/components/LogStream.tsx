"use client";

import { Box, HStack, Input, Stack, Text, Badge, Button } from "@chakra-ui/react";
import { useEffect, useRef, useState, useCallback, memo } from "react";
import { LuPause, LuPlay, LuTrash, LuChevronRight, LuChevronDown } from "react-icons/lu";

interface LogLine {
  ts: number;
  level: string;
  msg: string;
  slug?: string;
  raw?: any;
}

const SKIP_FIELDS = new Set([
  "message", "msg", "level", "ts", "time", "timestamp",
  "name", "logger", "pid", "hostname", "slug",
]);

const PRIORITY_FIELDS = [
  "blockNumber", "block", "chainId", "txHash", "contractAddress",
  "address", "deployer", "ruleId", "rule_id", "severity",
  "findingCount", "durationMs", "duration_ms", "bytecodeHash",
  "creationBytecodeHash", "correlationId", "eventType", "proxyKind",
  "proxyTarget", "auditStatus", "targetKind", "attempts", "failureReason",
  "auditorExitCode", "auditorStderrTail", "lastError", "selector", "function",
];

const CHAIN_PALETTES = [
  "blue", "green", "orange", "purple", "teal",
  "pink", "cyan", "red", "yellow", "indigo",
];

function chainColor(slug: string): string {
  let h = 0;
  for (let i = 0; i < slug.length; i++) h = (h * 31 + slug.charCodeAt(i)) >>> 0;
  return CHAIN_PALETTES[h % CHAIN_PALETTES.length];
}

function shortVal(v: unknown): string {
  if (v == null) return "—";
  if (typeof v === "string") {
    if (/^0x[0-9a-fA-F]{40,}$/.test(v) && v.length > 14) return `${v.slice(0, 8)}…${v.slice(-6)}`;
    return v.length > 80 ? v.slice(0, 80) + "…" : v;
  }
  if (typeof v === "object") {
    const s = JSON.stringify(v);
    return s.length > 80 ? s.slice(0, 80) + "…" : s;
  }
  return String(v);
}

function structuredFields(raw: any): { key: string; value: unknown }[] {
  if (!raw || typeof raw !== "object") return [];
  const seen = new Set<string>();
  const out: { key: string; value: unknown }[] = [];
  for (const k of PRIORITY_FIELDS) {
    if (k in raw && !SKIP_FIELDS.has(k) && !seen.has(k)) {
      const v = raw[k];
      if (v != null && v !== "") { out.push({ key: k, value: v }); seen.add(k); }
    }
  }
  for (const [k, v] of Object.entries(raw)) {
    if (SKIP_FIELDS.has(k) || seen.has(k)) continue;
    if (v == null || v === "") continue;
    if (typeof v === "object") continue;
    out.push({ key: k, value: v });
    seen.add(k);
  }
  return out;
}

const LEVEL_COLOR: Record<string, string> = {
  debug: "gray", info: "blue", warn: "yellow", error: "red", stderr: "red",
};

const DEFAULT_MAX_LINES = 500;
const FLUSH_MS = 250;

export function LogStream({
  maxHeight = "calc(100vh - 260px)",
  maxLines = DEFAULT_MAX_LINES,
}: {
  maxHeight?: string;
  maxLines?: number;
}) {
  const [lines, setLines] = useState<LogLine[]>([]);
  const [follow, setFollow] = useState(true);
  const [filter, setFilter] = useState("");
  const [levelFilter, setLevelFilter] = useState<string>("all");
  const [slugFilter, setSlugFilter] = useState<string>("all");
  const [slugs, setSlugs] = useState<string[]>([]);
  const boxRef = useRef<HTMLDivElement>(null);
  const pendingRef = useRef<LogLine[]>([]);
  const bufRef = useRef<LogLine[]>([]);
  const knownSlugsRef = useRef<Set<string>>(new Set());

  const flush = useCallback(() => {
    if (pendingRef.current.length === 0) return;
    const incoming = pendingRef.current;
    pendingRef.current = [];
    const combined = bufRef.current.concat(incoming);
    bufRef.current = combined.length > maxLines ? combined.slice(combined.length - maxLines) : combined;
    setLines(bufRef.current.slice());
  }, [maxLines]);

  useEffect(() => {
    const t = setInterval(flush, FLUSH_MS);
    return () => clearInterval(t);
  }, [flush]);

  useEffect(() => {
    const es = new EventSource("/api/runner/stream");
    const onLog = (e: MessageEvent) => {
      try {
        const line = JSON.parse(e.data) as LogLine;
        pendingRef.current.push(line);
        if (line.slug && !knownSlugsRef.current.has(line.slug)) {
          knownSlugsRef.current.add(line.slug);
          setSlugs((prev) => [...prev, line.slug!].sort());
        }
      } catch {}
    };
    es.addEventListener("log", onLog as EventListener);
    return () => es.close();
  }, []);

  useEffect(() => {
    if (follow && boxRef.current) {
      boxRef.current.scrollTop = boxRef.current.scrollHeight;
    }
  }, [lines, follow]);

  const filtered = lines.filter((l) => {
    if (levelFilter !== "all" && l.level !== levelFilter) return false;
    if (slugFilter !== "all" && l.slug !== slugFilter) return false;
    if (filter && !l.msg.toLowerCase().includes(filter.toLowerCase())) return false;
    return true;
  });

  const handleClear = useCallback(() => {
    pendingRef.current = [];
    bufRef.current = [];
    setLines([]);
  }, []);

  const isMultiChain = slugs.length > 0;

  return (
    <Stack gap="2">
      {/* Toolbar */}
      <HStack gap="2" wrap="wrap" align="center">
        <Input
          size="sm"
          placeholder="search…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          maxW="220px"
          borderRadius="md"
        />

        {/* Level filter */}
        <HStack gap="1">
          {(["all", "info", "warn", "error", "debug"] as const).map((lv) => (
            <Button
              key={lv}
              size="xs"
              variant={levelFilter === lv ? "solid" : "ghost"}
              colorPalette={lv === "all" ? "gray" : LEVEL_COLOR[lv]}
              onClick={() => setLevelFilter(lv)}
            >
              {lv}
            </Button>
          ))}
        </HStack>

        {/* Chain selector — only shown in multi-chain mode */}
        {isMultiChain && (
          <HStack gap="1" align="center">
            <Text fontSize="xs" color="fg.muted" whiteSpace="nowrap">chain:</Text>
            <select
              value={slugFilter}
              onChange={(e) => setSlugFilter(e.target.value)}
              style={{
                fontSize: "0.75rem",
                fontFamily: "monospace",
                padding: "2px 8px",
                borderRadius: "6px",
                border: "1px solid var(--chakra-colors-border)",
                background: "var(--chakra-colors-bg-panel)",
                color: "var(--chakra-colors-fg)",
                cursor: "pointer",
                outline: "none",
              }}
            >
              <option value="all">all chains ({lines.length})</option>
              {slugs.map((s) => {
                const count = lines.filter((l) => l.slug === s).length;
                return (
                  <option key={s} value={s}>
                    {s} ({count})
                  </option>
                );
              })}
            </select>
            {slugFilter !== "all" && (
              <Button size="xs" variant="ghost" colorPalette="gray" onClick={() => setSlugFilter("all")}>
                ✕
              </Button>
            )}
          </HStack>
        )}

        <HStack gap="1" ml="auto">
          <Button size="xs" variant="ghost" onClick={() => setFollow((f) => !f)}>
            {follow ? <LuPause /> : <LuPlay />}
            <Text ml="1">{follow ? "Pause" : "Follow"}</Text>
          </Button>
          <Button size="xs" variant="ghost" onClick={handleClear}>
            <LuTrash />
            <Text ml="1">Clear</Text>
          </Button>
          <Text fontSize="xs" color="fg.muted">
            {filtered.length}/{lines.length}
          </Text>
        </HStack>
      </HStack>

      {/* Log area */}
      <Box
        ref={boxRef}
        bg="gray.950"
        _light={{ bg: "gray.50" }}
        rounded="md"
        p="3"
        fontFamily="mono"
        fontSize="xs"
        h={maxHeight}
        overflowY="auto"
        css={{ scrollbarWidth: "thin" }}
      >
        {filtered.length === 0 && (
          <Text color="fg.muted" p="2">
            {lines.length === 0
              ? "no logs yet — start the runner to see live output"
              : "no lines match the current filter"}
          </Text>
        )}
        {filtered.map((l, i) => (
          <LogRow key={i} line={l} showChain={isMultiChain && slugFilter === "all"} />
        ))}
      </Box>
    </Stack>
  );
}

const LogRow = memo(function LogRow({
  line,
  showChain,
}: {
  line: LogLine;
  showChain: boolean;
}) {
  const [open, setOpen] = useState(false);
  const fields = structuredFields(line.raw);
  const hasNested =
    line.raw &&
    typeof line.raw === "object" &&
    Object.values(line.raw).some((v) => v && typeof v === "object");
  const expandable = fields.length > 4 || hasNested;
  const levelColor = LEVEL_COLOR[line.level] ?? "gray";
  const isBad = line.level === "error" || line.level === "stderr" || line.level === "warn";

  return (
    <Box
      mb="1px"
      px="1.5"
      py="0.5"
      borderRadius="sm"
      bg={isBad ? (line.level === "warn" ? "yellow.950" : "red.950") : "transparent"}
      _light={{
        bg: isBad ? (line.level === "warn" ? "yellow.50" : "red.50") : "transparent",
      }}
      borderLeft="2px solid"
      borderColor={isBad ? `${levelColor}.500` : "transparent"}
      _hover={{ bg: "whiteAlpha.50", _light: { bg: "blackAlpha.50" } }}
    >
      <Box display="flex" gap="2" alignItems="baseline" flexWrap="wrap">
        {/* Timestamp */}
        <Text color="fg.muted" flexShrink={0} minW="60px" fontSize="2xs">
          {new Date(line.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
        </Text>

        {/* Level */}
        <Badge
          colorPalette={levelColor}
          variant="subtle"
          size="xs"
          flexShrink={0}
          minW="40px"
          textAlign="center"
          fontSize="2xs"
          textTransform="uppercase"
        >
          {line.level === "stderr" ? "err" : line.level}
        </Badge>

        {/* Chain badge (multi-chain "all" view) */}
        {showChain && line.slug && (
          <Badge
            colorPalette={chainColor(line.slug)}
            variant="subtle"
            size="xs"
            flexShrink={0}
            fontSize="2xs"
            fontFamily="mono"
            maxW="120px"
            overflow="hidden"
            textOverflow="ellipsis"
            whiteSpace="nowrap"
          >
            {line.slug}
          </Badge>
        )}

        {/* Message + structured fields */}
        <Box flex="1" minW="0">
          <HStack gap="3" wrap="wrap" align="baseline">
            <Text
              fontWeight={isBad ? "semibold" : "normal"}
              color={isBad ? (line.level === "warn" ? "yellow.300" : "red.300") : "fg"}
              _light={{ color: isBad ? (line.level === "warn" ? "yellow.700" : "red.700") : "fg" }}
              wordBreak="break-word"
            >
              {line.msg}
            </Text>
            {fields.slice(0, 5).map((f) => (
              <HStack key={f.key} gap="0.5" fontSize="2xs" flexShrink={0}>
                <Text color="fg.muted">{f.key}=</Text>
                <Text color="cyan.400" _light={{ color: "cyan.700" }} fontFamily="mono">
                  {shortVal(f.value)}
                </Text>
              </HStack>
            ))}
            {fields.length > 5 && !open && (
              <Text fontSize="2xs" color="fg.muted">
                +{fields.length - 5} more
              </Text>
            )}
            {expandable && (
              <Button
                size="2xs"
                variant="ghost"
                onClick={() => setOpen((o) => !o)}
                p="0"
                minW="auto"
                h="auto"
                color="fg.muted"
              >
                {open ? <LuChevronDown size={10} /> : <LuChevronRight size={10} />}
              </Button>
            )}
          </HStack>
          {open && (
            <Box
              mt="1"
              ml="1"
              pl="2"
              borderLeft="2px solid"
              borderColor="border"
              fontSize="2xs"
              color="fg.muted"
            >
              <Box as="pre" whiteSpace="pre-wrap" wordBreak="break-all" m="0">
                {JSON.stringify(line.raw ?? { msg: line.msg }, null, 2)}
              </Box>
            </Box>
          )}
        </Box>
      </Box>
    </Box>
  );
});
