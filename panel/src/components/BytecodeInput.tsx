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
import { useState } from "react";
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
          <HStack gap="2">
            <NativeSelect.Root size="sm" w="220px">
              <NativeSelect.Field value={chainId} onChange={(e) => setChainId(Number(e.target.value))}>
                {CHAINS.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name}
                  </option>
                ))}
              </NativeSelect.Field>
              <NativeSelect.Indicator />
            </NativeSelect.Root>
            <Input
              size="sm"
              placeholder="0xabc...0000"
              value={address}
              onChange={(e) => setAddress(e.target.value)}
              fontFamily="mono"
            />
          </HStack>
          <Input
            size="sm"
            placeholder="RPC URL (e.g. https://rpc.ankr.com/eth)"
            value={rpcUrl}
            onChange={(e) => setRpcUrl(e.target.value)}
          />
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
