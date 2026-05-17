"use client";

import {
  Badge,
  Box,
  Button,
  HStack,
  Input,
  NativeSelect,
  Stack,
  Tabs,
  Text,
  Textarea,
} from "@chakra-ui/react";
import { useEffect, useMemo, useState } from "react";
import { CHAINS } from "@/src/lib/chains";

export type InputMode = "manual_hex" | "manual_file" | "manual_address";

export interface InputValue {
  kind: InputMode;
  bytecode?: string;
  filename?: string;
  address?: string;
  chainId?: number;
  rpcUrl?: string;
}

interface ChainlistChain {
  chainId: number;
  name: string;
  shortName: string;
  nativeSymbol: string;
  nativeDecimals: number;
  isTestnet: boolean;
  httpRpcs: string[];
  wssRpcs: string[];
  explorers: string[];
  tvl?: number;
}

const CHAINLIST_LOCALSTORAGE_KEY = "chainlist-cache-v1";
const CHAINLIST_CLIENT_TTL_MS = 6 * 60 * 60_000; // 6h

interface CachedChainlist { fetchedAt: number; chains: ChainlistChain[] }

// Module-scoped set of URLs the auto-fill has ever set; used to decide
// whether the rpcUrl field still holds a suggested value (safe to overwrite
// on chain change) or a user-pasted URL we must preserve.
const rpcSuggestionsCache = new Set<string>();

function hostnameOnly(url: string): string {
  try {
    const u = new URL(url);
    return u.hostname + (u.pathname && u.pathname !== "/" ? u.pathname.slice(0, 24) : "");
  } catch {
    return url.slice(0, 32);
  }
}

function loadCachedChainlist(): CachedChainlist | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.localStorage.getItem(CHAINLIST_LOCALSTORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as CachedChainlist;
    if (!parsed?.fetchedAt || !Array.isArray(parsed.chains)) return null;
    if (Date.now() - parsed.fetchedAt > CHAINLIST_CLIENT_TTL_MS) return null;
    return parsed;
  } catch {
    return null;
  }
}

function saveCachedChainlist(c: CachedChainlist) {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(CHAINLIST_LOCALSTORAGE_KEY, JSON.stringify(c));
  } catch {}
}

export function BytecodeInput({ onChange }: { onChange: (v: InputValue | null) => void }) {
  const [tab, setTab] = useState<InputMode>("manual_hex");
  // hex
  const [hex, setHex] = useState("");
  // file
  const [fileName, setFileName] = useState<string | null>(null);
  const [fileText, setFileText] = useState<string | null>(null);
  // address
  const [address, setAddress] = useState("");
  const [chainId, setChainId] = useState(1);
  const [rpcUrl, setRpcUrl] = useState("");
  const [fetched, setFetched] = useState<{ bytes: number | null; error?: string } | null>(null);
  const [fetching, setFetching] = useState(false);
  const [chainlist, setChainlist] = useState<ChainlistChain[]>([]);
  const [chainlistLoaded, setChainlistLoaded] = useState(false);
  const [showAllChains, setShowAllChains] = useState(false);

  // Fetch (or load from cache) chainlist on mount.
  useEffect(() => {
    const cached = loadCachedChainlist();
    if (cached) {
      setChainlist(cached.chains);
      setChainlistLoaded(true);
      return;
    }
    fetch("/api/chainlist")
      .then((r) => r.json())
      .then((j) => {
        if (Array.isArray(j?.chains)) {
          setChainlist(j.chains);
          setChainlistLoaded(true);
          saveCachedChainlist({ fetchedAt: Date.now(), chains: j.chains });
        }
      })
      .catch(() => {
        setChainlistLoaded(true);
      });
  }, []);

  // Auto-fill RPC URL when chainId changes, if the field is empty or held the
  // previously-suggested RPC. Don't clobber user-pasted URLs.
  useEffect(() => {
    const chain = chainlist.find((c) => c.chainId === chainId);
    const firstRpc = chain?.httpRpcs?.[0] ?? "";
    if (!firstRpc) return;
    if (rpcUrl && !rpcSuggestionsCache.has(rpcUrl)) return; // user typed something custom
    rpcSuggestionsCache.add(firstRpc);
    setRpcUrl(firstRpc);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [chainId, chainlist]);

  // Combined chain dropdown options: prefer the curated CHAINS list (always
  // shown at top), then fall through to the full chainlist when toggled.
  const curatedIds = useMemo(() => new Set(CHAINS.map((c) => c.id)), []);
  const allChainsSorted = useMemo(() => {
    const list = chainlist
      .filter((c) => !curatedIds.has(c.chainId))
      .sort((a, b) => (b.tvl ?? 0) - (a.tvl ?? 0));
    return list;
  }, [chainlist, curatedIds]);
  const selectedChain = chainlist.find((c) => c.chainId === chainId);

  function emit(v: InputValue | null) {
    onChange(v);
  }

  function setTabAndReset(t: InputMode) {
    setTab(t);
    emit(null);
  }

  const handleHex = (val: string) => {
    setHex(val);
    const clean = val.replace(/^0[xX]/, "").trim();
    if (!clean) return emit(null);
    if (!/^[0-9a-fA-F]+$/.test(clean)) return emit(null);
    emit({ kind: "manual_hex", bytecode: val });
  };

  const handleFile = async (file: File) => {
    setFileName(file.name);
    const txt = await file.text();
    setFileText(txt);
    emit({ kind: "manual_file", bytecode: txt, filename: file.name });
  };

  const fetchAddress = async () => {
    setFetching(true);
    setFetched(null);
    try {
      const url = rpcUrl || "";
      if (!url) {
        setFetched({ bytes: null, error: "RPC URL required" });
        return;
      }
      const r = await fetch("/api/rpc/code", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rpcUrl: url, address }),
      });
      const j = await r.json();
      if (!r.ok || j.error) {
        setFetched({ bytes: null, error: j.error ?? "fetch failed" });
        emit(null);
      } else if (j.empty) {
        setFetched({ bytes: 0, error: "no code at address" });
        emit(null);
      } else {
        setFetched({ bytes: j.bytes });
        emit({ kind: "manual_address", address, chainId, rpcUrl: url });
      }
    } finally {
      setFetching(false);
    }
  };

  return (
    <Tabs.Root value={tab} onValueChange={(v) => setTabAndReset(v.value as InputMode)} variant="enclosed">
      <Tabs.List>
        <Tabs.Trigger value="manual_hex">Hex paste</Tabs.Trigger>
        <Tabs.Trigger value="manual_file">File upload</Tabs.Trigger>
        <Tabs.Trigger value="manual_address">Fetch by address</Tabs.Trigger>
      </Tabs.List>
      <Tabs.Content value="manual_hex">
        <Stack gap="2">
          <Textarea
            placeholder="0x6080604052..."
            value={hex}
            onChange={(e) => handleHex(e.target.value)}
            rows={10}
            fontFamily="mono"
            fontSize="xs"
          />
          {hex && (
            <Text fontSize="xs" color="fg.muted">
              {Math.floor((hex.replace(/^0[xX]/, "").length || 0) / 2)} bytes
            </Text>
          )}
        </Stack>
      </Tabs.Content>
      <Tabs.Content value="manual_file">
        <Stack gap="2">
          <Box
            border="1px dashed"
            borderColor="border"
            rounded="md"
            p="6"
            textAlign="center"
            bg="bg.subtle"
          >
            <input
              type="file"
              accept=".hex,.bin,.json,.txt"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) handleFile(f);
              }}
              style={{ display: "block", margin: "0 auto" }}
            />
            <Text fontSize="xs" color="fg.muted" mt="2">
              accepts .hex / .bin / Solidity artifact .json
            </Text>
          </Box>
          {fileName && (
            <HStack gap="2">
              <Badge variant="subtle">{fileName}</Badge>
              <Text fontSize="xs" color="fg.muted">
                {(fileText?.length ?? 0).toLocaleString()} chars
              </Text>
            </HStack>
          )}
        </Stack>
      </Tabs.Content>
      <Tabs.Content value="manual_address">
        <Stack gap="2">
          <HStack gap="2" wrap="wrap">
            <NativeSelect.Root size="sm" w="260px">
              <NativeSelect.Field value={chainId} onChange={(e) => setChainId(Number(e.target.value))}>
                <optgroup label="Common chains">
                  {CHAINS.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.name} ({c.id})
                    </option>
                  ))}
                </optgroup>
                {showAllChains && allChainsSorted.length > 0 && (
                  <optgroup label="All chains (sorted by TVL)">
                    {allChainsSorted.slice(0, 250).map((c) => (
                      <option key={c.chainId} value={c.chainId}>
                        {c.name} ({c.chainId}){c.isTestnet ? " · testnet" : ""}
                      </option>
                    ))}
                  </optgroup>
                )}
              </NativeSelect.Field>
              <NativeSelect.Indicator />
            </NativeSelect.Root>
            <Button
              size="xs"
              variant="ghost"
              onClick={() => setShowAllChains((v) => !v)}
              disabled={!chainlistLoaded}
            >
              {showAllChains ? "common chains" : `all ${chainlist.length || ""} chains…`}
            </Button>
            <Input
              size="sm"
              placeholder="0xabc...0000"
              value={address}
              onChange={(e) => setAddress(e.target.value)}
              fontFamily="mono"
              flex="1"
              minW="280px"
            />
          </HStack>
          <Input
            size="sm"
            placeholder="RPC URL (auto-filled from chainlist; paste your own for private endpoints)"
            value={rpcUrl}
            onChange={(e) => {
              const v = e.target.value;
              setRpcUrl(v);
              if (v) rpcSuggestionsCache.delete(v);
            }}
            fontFamily="mono"
          />
          {selectedChain && (selectedChain.httpRpcs.length > 1 || selectedChain.wssRpcs.length > 0) && (
            <Box>
              <HStack gap="2" wrap="wrap" align="center">
                <Text fontSize="xs" color="fg.muted">
                  Public RPCs ({selectedChain.nativeSymbol}):
                </Text>
                {selectedChain.httpRpcs.slice(0, 5).map((u) => (
                  <Button
                    key={u}
                    size="2xs"
                    variant={rpcUrl === u ? "solid" : "outline"}
                    colorPalette={rpcUrl === u ? "purple" : undefined}
                    onClick={() => {
                      rpcSuggestionsCache.add(u);
                      setRpcUrl(u);
                    }}
                    fontFamily="mono"
                  >
                    {hostnameOnly(u)}
                  </Button>
                ))}
              </HStack>
              {selectedChain.wssRpcs.length > 0 && (
                <HStack gap="2" wrap="wrap" align="center" mt="1.5">
                  <Text fontSize="xs" color="fg.muted">
                    WSS:
                  </Text>
                  {selectedChain.wssRpcs.slice(0, 3).map((u) => (
                    <Box
                      key={u}
                      onClick={() => {
                        navigator.clipboard?.writeText(u).catch(() => {});
                      }}
                      cursor="pointer"
                      title="click to copy"
                    >
                      <Badge size="xs" variant="outline" fontFamily="mono">
                        {hostnameOnly(u)}
                      </Badge>
                    </Box>
                  ))}
                  <Text fontSize="2xs" color="fg.muted">
                    (click to copy)
                  </Text>
                </HStack>
              )}
              {selectedChain.explorers[0] && address && (
                <Text fontSize="2xs" color="fg.muted" mt="1.5">
                  Explorer:{" "}
                  <a
                    href={`${selectedChain.explorers[0].replace(/\/$/, "")}/address/${address}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ textDecoration: "underline" }}
                  >
                    {selectedChain.explorers[0]}
                  </a>
                </Text>
              )}
            </Box>
          )}
          <HStack gap="2">
            <Button
              size="sm"
              variant="subtle"
              onClick={fetchAddress}
              loading={fetching}
              disabled={!address || !rpcUrl}
            >
              Fetch code
            </Button>
            {fetched && (
              <Text fontSize="xs" color={fetched.error ? "red.500" : "fg.muted"}>
                {fetched.error ?? `${fetched.bytes} bytes ready`}
              </Text>
            )}
          </HStack>
        </Stack>
      </Tabs.Content>
    </Tabs.Root>
  );
}
