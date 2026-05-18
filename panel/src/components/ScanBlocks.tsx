"use client";

import { useState, useEffect } from "react";
import { Box, Heading, Text, HStack, VStack, Stack, Badge, Button, Input } from "@chakra-ui/react";

type ScanMode = "block" | "range" | "lastN" | "head";

interface Chain {
  slug: string;
  enabled: boolean;
}

export function ScanBlocks() {
  const [chains, setChains] = useState<string[]>([]);
  const [selectedChain, setSelectedChain] = useState<string>("");
  const [mode, setMode] = useState<ScanMode>("lastN");
  const [block, setBlock] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [lastN, setLastN] = useState("100");
  const [startBlock, setStartBlock] = useState("");
  const [noWebhook, setNoWebhook] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/scan/blocks")
      .then((r) => r.json())
      .then((d) => {
        if (d.chains) {
          setChains(d.chains);
          if (d.chains.length > 0 && !selectedChain) setSelectedChain(d.chains[0]);
        }
      })
      .catch(() => null);
  }, []);

  const submit = async () => {
    setBusy(true);
    setResult(null);
    try {
      const body: any = { chain: selectedChain, mode, noWebhook };
      if (mode === "block") body.block = Number(block);
      if (mode === "range") { body.from = Number(from); body.to = Number(to); }
      if (mode === "lastN") body.lastN = Number(lastN);
      if (mode === "head" && startBlock) body.startBlock = Number(startBlock);

      const r = await fetch("/api/scan/blocks", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const j = await r.json();
      if (j.ok) {
        setResult(`Started: ${j.message}`);
      } else {
        setResult(`Error: ${j.error}`);
      }
    } catch (e: any) {
      setResult(`Error: ${e?.message ?? e}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <VStack align="stretch" gap="4" maxW="700px">
      <Heading size="md">Block Scanner</Heading>
      <Text fontSize="sm" color="fg.muted">
        Scan specific blocks, ranges, last N blocks, or follow new blocks on any chain.
      </Text>

      <Box border="1px solid" borderColor="border.muted" rounded="md" p="4" bg="bg.panel">
        <Stack gap="3">
          {/* Chain selector */}
          <Box>
            <Text fontSize="xs" fontWeight="medium" mb="1">Chain</Text>
            <HStack gap="1" wrap="wrap">
              {chains.map((c) => (
                <Button
                  key={c}
                  size="xs"
                  variant={selectedChain === c ? "solid" : "outline"}
                  colorPalette={selectedChain === c ? "blue" : "gray"}
                  onClick={() => setSelectedChain(c)}
                >
                  {c.replace("-mainnet", "")}
                </Button>
              ))}
            </HStack>
          </Box>

          {/* Mode selector */}
          <Box>
            <Text fontSize="xs" fontWeight="medium" mb="1">Scan Mode</Text>
            <HStack gap="1">
              {(["lastN", "block", "range", "head"] as ScanMode[]).map((m) => (
                <Button
                  key={m}
                  size="xs"
                  variant={mode === m ? "solid" : "outline"}
                  colorPalette={mode === m ? "purple" : "gray"}
                  onClick={() => setMode(m)}
                >
                  {m === "lastN" ? "Last N blocks" : m === "block" ? "Specific block" : m === "range" ? "Block range" : "Follow head"}
                </Button>
              ))}
            </HStack>
          </Box>

          {/* Mode-specific inputs */}
          {mode === "block" && (
            <Box>
              <Text fontSize="xs" color="fg.muted" mb="1">Block number</Text>
              <Input size="sm" type="number" placeholder="e.g. 25100000" value={block} onChange={(e) => setBlock(e.target.value)} />
            </Box>
          )}
          {mode === "range" && (
            <HStack gap="2">
              <Box flex="1">
                <Text fontSize="xs" color="fg.muted" mb="1">From block</Text>
                <Input size="sm" type="number" placeholder="e.g. 25100000" value={from} onChange={(e) => setFrom(e.target.value)} />
              </Box>
              <Box flex="1">
                <Text fontSize="xs" color="fg.muted" mb="1">To block</Text>
                <Input size="sm" type="number" placeholder="e.g. 25100100" value={to} onChange={(e) => setTo(e.target.value)} />
              </Box>
            </HStack>
          )}
          {mode === "lastN" && (
            <Box>
              <Text fontSize="xs" color="fg.muted" mb="1">Number of recent blocks to scan</Text>
              <Input size="sm" type="number" placeholder="100" value={lastN} onChange={(e) => setLastN(e.target.value)} />
            </Box>
          )}
          {mode === "head" && (
            <Box>
              <Text fontSize="xs" color="fg.muted" mb="1">Start from block (optional, blank = latest)</Text>
              <Input size="sm" type="number" placeholder="blank = latest head" value={startBlock} onChange={(e) => setStartBlock(e.target.value)} />
            </Box>
          )}

          {/* Options */}
          <HStack gap="2">
            <Button
              size="xs"
              variant={noWebhook ? "solid" : "outline"}
              colorPalette={noWebhook ? "yellow" : "gray"}
              onClick={() => setNoWebhook(!noWebhook)}
            >
              {noWebhook ? "Webhooks OFF" : "Webhooks ON"}
            </Button>
          </HStack>

          {/* Submit */}
          <Button
            colorPalette="green"
            size="sm"
            onClick={submit}
            disabled={busy || !selectedChain}
            loading={busy}
          >
            {mode === "head" ? "Start head-follow" : "Start scan"}
          </Button>
        </Stack>
      </Box>

      {/* Result */}
      {result && (
        <Box
          border="1px solid"
          borderColor={result.startsWith("Error") ? "border.error" : "border.success"}
          bg={result.startsWith("Error") ? "bg.error" : "bg.success"}
          rounded="md"
          p="3"
        >
          <Text fontSize="sm" whiteSpace="pre-wrap">{result}</Text>
        </Box>
      )}

      {/* Usage info */}
      <Box border="1px solid" borderColor="border.muted" rounded="md" p="3" bg="bg.subtle">
        <Heading size="xs" mb="2">Scan Modes</Heading>
        <Stack gap="1" fontSize="xs" color="fg.muted">
          <Text><Badge size="sm" colorPalette="purple">Last N</Badge> Scan the most recent N blocks from the current head. Good for catching recent deployments.</Text>
          <Text><Badge size="sm" colorPalette="purple">Specific block</Badge> Scan exactly one block. Use when you know a contract was deployed in a specific block.</Text>
          <Text><Badge size="sm" colorPalette="purple">Block range</Badge> Scan all blocks in a from:to range (max 10,000). Good for historical sweeps.</Text>
          <Text><Badge size="sm" colorPalette="purple">Follow head</Badge> Continuous mode — watches new blocks as they arrive. This is the default runner mode.</Text>
        </Stack>
      </Box>
    </VStack>
  );
}
