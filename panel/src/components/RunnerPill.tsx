"use client";

import { Badge, Button, HStack, Text, Spinner } from "@chakra-ui/react";
import { useEffect, useState, useCallback } from "react";
import Link from "next/link";

type Status = "idle" | "starting" | "running" | "stopping" | "crashed" | "unknown";

const STATUS_COLOR: Record<Status, string> = {
  idle: "gray",
  starting: "yellow",
  running: "green",
  stopping: "yellow",
  crashed: "red",
  unknown: "gray",
};

interface StatusResponse {
  status: Status;
  pid?: number | null;
  chainMode?: boolean;
  running?: number;
  total?: number;
}

export function RunnerPill() {
  const [snap, setSnap] = useState<StatusResponse>({ status: "unknown" });
  const [pending, setPending] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const r = await fetch("/api/runner/status", { cache: "no-store" });
      const j: StatusResponse = await r.json();
      setSnap(j);
    } catch {
      setSnap({ status: "unknown" });
    }
  }, []);

  useEffect(() => {
    refresh();
    const es = new EventSource("/api/runner/stream");
    es.addEventListener("state", (e: MessageEvent) => {
      try {
        const data: StatusResponse = JSON.parse(e.data);
        setSnap((prev) => ({ ...prev, ...data }));
      } catch {}
    });
    return () => es.close();
  }, [refresh]);

  const post = async (path: string) => {
    setPending(true);
    try {
      await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    } finally {
      setPending(false);
      refresh();
    }
  };

  const { status, pid, chainMode, running = 0, total = 0 } = snap;
  const anyRunning = status === "running" || status === "starting" || status === "stopping";
  const transitioning = status === "starting" || status === "stopping";

  if (chainMode) {
    return (
      <HStack gap="3">
        <Badge colorPalette={STATUS_COLOR[status] ?? "gray"} size="md" variant="subtle">
          <HStack gap="1.5">
            {transitioning && <Spinner size="xs" />}
            <Text fontSize="xs" fontWeight="medium">
              {running}/{total} chains
            </Text>
          </HStack>
        </Badge>
        <HStack gap="1">
          {!anyRunning ? (
            <Button size="xs" variant="subtle" colorPalette="green" loading={pending} onClick={() => post("/api/runner/start")}>
              Start all
            </Button>
          ) : (
            <Button size="xs" variant="subtle" colorPalette="red" loading={pending} onClick={() => post("/api/runner/stop")}>
              Stop all
            </Button>
          )}
          <Link href="/chains">
            <Button size="xs" variant="ghost" as="span">
              Manage →
            </Button>
          </Link>
        </HStack>
      </HStack>
    );
  }

  return (
    <HStack gap="3">
      <Badge colorPalette={STATUS_COLOR[status] ?? "gray"} size="md" variant="subtle">
        <HStack gap="1.5">
          {transitioning && <Spinner size="xs" />}
          <Text fontSize="xs" fontWeight="medium" textTransform="uppercase">
            {status}
          </Text>
        </HStack>
      </Badge>
      {pid != null && (
        <Text fontSize="xs" color="fg.muted">
          pid {pid}
        </Text>
      )}
      <HStack gap="1">
        {!anyRunning ? (
          <Button size="xs" variant="subtle" colorPalette="green" loading={pending} onClick={() => post("/api/runner/start")}>
            Start
          </Button>
        ) : (
          <Button size="xs" variant="subtle" colorPalette="red" loading={pending} onClick={() => post("/api/runner/stop")}>
            Stop
          </Button>
        )}
        <Button size="xs" variant="ghost" loading={pending} onClick={() => post("/api/runner/restart")}>
          Restart
        </Button>
      </HStack>
    </HStack>
  );
}
