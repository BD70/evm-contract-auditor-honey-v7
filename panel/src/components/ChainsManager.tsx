"use client";

import {
  Badge,
  Box,
  Button,
  HStack,
  Heading,
  Input,
  Spinner,
  Stack,
  Switch,
  Text,
} from "@chakra-ui/react";
import { useCallback, useEffect, useState } from "react";

const SECRET_MASK = "***";

type RunnerStatus = "idle" | "starting" | "running" | "stopping" | "crashed";

interface ChainRow {
  slug: string;
  name: string;
  enabled: boolean;
  rpcHttpUrl: string;
  rpcWsUrl?: string;
  startBlock?: number;
  confirmations?: number;
  webhookUrl?: string;
  webhookAuthHeader?: string;
  rulesPath?: string;
  healthPort: number;
  runner: { status: RunnerStatus; pid: number | null } | null;
}

const STATUS_COLOR: Record<string, string> = {
  idle: "gray",
  starting: "yellow",
  running: "green",
  stopping: "yellow",
  crashed: "red",
};

type FormState = Partial<ChainRow> & { slug: string; name: string; rpcHttpUrl: string };

const EMPTY_FORM: FormState = {
  slug: "",
  name: "",
  rpcHttpUrl: "",
  rpcWsUrl: "",
  enabled: true,
  startBlock: 0,
  confirmations: 2,
  webhookUrl: "",
  webhookAuthHeader: "",
  rulesPath: "",
};

export function ChainsManager() {
  const [chains, setChains] = useState<ChainRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [editing, setEditing] = useState<string | null>(null); // slug or "__new__"
  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [busy, setBusy] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const r = await fetch("/api/chains", { cache: "no-store" });
      const j = await r.json();
      setChains(j.chains ?? []);
      setErr(null);
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 4000);
    return () => clearInterval(t);
  }, [refresh]);

  const lifecycle = async (slug: string, action: "start" | "stop" | "restart") => {
    setBusy(`${slug}:${action}`);
    setErr(null);
    try {
      const r = await fetch(`/api/chains/${slug}/${action}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      const j = await r.json();
      if (!j.ok) setErr(j.error ?? `${action} failed`);
    } finally {
      setBusy(null);
      refresh();
    }
  };

  const startEdit = (c?: ChainRow) => {
    setMsg(null);
    setErr(null);
    setEditing(c ? c.slug : "__new__");
    setForm(c ? { ...EMPTY_FORM, ...c } : EMPTY_FORM);
  };

  const save = async () => {
    setBusy("save");
    setErr(null);
    setMsg(null);
    try {
      const isNew = editing === "__new__";
      const body: any = {
        slug: form.slug,
        name: form.name,
        enabled: form.enabled ?? true,
        rpcHttpUrl: form.rpcHttpUrl,
        rpcWsUrl: form.rpcWsUrl || undefined,
        startBlock: form.startBlock === undefined || form.startBlock === ("" as any) ? undefined : Number(form.startBlock),
        confirmations:
          form.confirmations === undefined || form.confirmations === ("" as any) ? undefined : Number(form.confirmations),
        webhookUrl: form.webhookUrl || undefined,
        webhookAuthHeader: form.webhookAuthHeader || undefined,
        rulesPath: form.rulesPath || undefined,
      };
      const r = await fetch(isNew ? "/api/chains" : `/api/chains/${form.slug}`, {
        method: isNew ? "POST" : "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const j = await r.json();
      if (!j.ok) {
        setErr(j.error ?? "save failed");
        return;
      }
      setMsg(isNew ? `chain ${form.slug} added` : `chain ${form.slug} updated`);
      setEditing(null);
      await refresh();
    } finally {
      setBusy(null);
    }
  };

  const remove = async (slug: string) => {
    if (!confirm(`Delete chain "${slug}"? Its runner must be stopped.`)) return;
    setBusy(`${slug}:delete`);
    setErr(null);
    try {
      const r = await fetch(`/api/chains/${slug}`, { method: "DELETE" });
      const j = await r.json();
      if (!j.ok) setErr(j.error ?? "delete failed");
      else setMsg(`chain ${slug} deleted`);
    } finally {
      setBusy(null);
      refresh();
    }
  };

  return (
    <Stack gap="5">
      <HStack justify="space-between">
        <Heading size="lg">Chains</Heading>
        <HStack gap="2">
          <Button size="sm" variant="ghost" onClick={refresh}>
            Reload
          </Button>
          <Button size="sm" colorPalette="purple" onClick={() => startEdit()}>
            Add chain
          </Button>
        </HStack>
      </HStack>

      <Text fontSize="sm" color="fg.muted">
        Each enabled chain runs as its own runner process with an isolated state dir
        (<code>STATE_DIR/&lt;slug&gt;</code>), lock, checkpoint and health port. With no chains
        defined the panel falls back to the single <code>.env</code>-driven runner.
      </Text>

      {msg && <Box bg="green.subtle" color="green.fg" rounded="md" px="3" py="2" fontSize="sm">{msg}</Box>}
      {err && <Box bg="red.subtle" color="red.fg" rounded="md" px="3" py="2" fontSize="sm">{err}</Box>}

      {editing && (
        <Box bg="bg.panel" border="1px solid" borderColor="border" rounded="lg" p="4">
          <Heading size="sm" mb="3">
            {editing === "__new__" ? "New chain" : `Edit ${editing}`}
          </Heading>
          <Stack gap="3">
            <Field label="slug" hint="lowercase a-z0-9-, stable id for state dir">
              <Input
                size="sm"
                fontFamily="mono"
                value={form.slug}
                disabled={editing !== "__new__"}
                onChange={(e) => setForm((f) => ({ ...f, slug: e.target.value }))}
              />
            </Field>
            <Field label="name">
              <Input size="sm" value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} />
            </Field>
            <Field label="rpcHttpUrl" hint="required, http(s)://">
              <Input
                size="sm"
                fontFamily="mono"
                value={form.rpcHttpUrl}
                onChange={(e) => setForm((f) => ({ ...f, rpcHttpUrl: e.target.value }))}
              />
            </Field>
            <Field label="rpcWsUrl" hint="optional, ws(s)://">
              <Input
                size="sm"
                fontFamily="mono"
                value={form.rpcWsUrl ?? ""}
                onChange={(e) => setForm((f) => ({ ...f, rpcWsUrl: e.target.value }))}
              />
            </Field>
            <HStack gap="4">
              <Field label="startBlock">
                <Input
                  size="sm"
                  type="number"
                  maxW="160px"
                  value={String(form.startBlock ?? "")}
                  onChange={(e) => setForm((f) => ({ ...f, startBlock: e.target.value === "" ? undefined : Number(e.target.value) }))}
                />
              </Field>
              <Field label="confirmations">
                <Input
                  size="sm"
                  type="number"
                  maxW="160px"
                  value={String(form.confirmations ?? "")}
                  onChange={(e) => setForm((f) => ({ ...f, confirmations: e.target.value === "" ? undefined : Number(e.target.value) }))}
                />
              </Field>
              <Field label="enabled">
                <Switch.Root
                  checked={form.enabled ?? true}
                  onCheckedChange={(d) => setForm((f) => ({ ...f, enabled: d.checked }))}
                  size="sm"
                >
                  <Switch.HiddenInput />
                  <Switch.Control>
                    <Switch.Thumb />
                  </Switch.Control>
                </Switch.Root>
              </Field>
            </HStack>
            <Field label="webhookUrl" hint="optional, overrides global WEBHOOK_URL">
              <Input
                size="sm"
                fontFamily="mono"
                value={form.webhookUrl ?? ""}
                onChange={(e) => setForm((f) => ({ ...f, webhookUrl: e.target.value }))}
              />
            </Field>
            <Field label="webhookAuthHeader" hint="optional secret; leave as *** to keep existing">
              <Input
                size="sm"
                type="password"
                fontFamily="mono"
                placeholder={SECRET_MASK}
                value={form.webhookAuthHeader ?? ""}
                onChange={(e) => setForm((f) => ({ ...f, webhookAuthHeader: e.target.value }))}
              />
            </Field>
            <Field label="rulesPath" hint="optional, overrides RULES_PATH">
              <Input
                size="sm"
                fontFamily="mono"
                value={form.rulesPath ?? ""}
                onChange={(e) => setForm((f) => ({ ...f, rulesPath: e.target.value }))}
              />
            </Field>
            <HStack gap="2">
              <Button size="sm" colorPalette="purple" loading={busy === "save"} onClick={save}>
                Save
              </Button>
              <Button size="sm" variant="ghost" onClick={() => setEditing(null)}>
                Cancel
              </Button>
            </HStack>
          </Stack>
        </Box>
      )}

      {loading ? (
        <HStack><Spinner size="sm" /><Text fontSize="sm">loading…</Text></HStack>
      ) : chains.length === 0 ? (
        <Box bg="bg.panel" border="1px solid" borderColor="border" rounded="lg" p="6">
          <Text fontSize="sm" color="fg.muted">
            No chains defined. The panel is using the single <code>.env</code> runner.
            Add a chain to enable multi-chain monitoring.
          </Text>
        </Box>
      ) : (
        <Stack gap="3">
          {chains.map((c) => {
            const status = c.runner?.status ?? "idle";
            const running = status === "running" || status === "starting" || status === "stopping";
            return (
              <Box key={c.slug} bg="bg.panel" border="1px solid" borderColor="border" rounded="lg" p="4">
                <HStack justify="space-between" align="start">
                  <Stack gap="1">
                    <HStack gap="2">
                      <Heading size="sm">{c.name}</Heading>
                      <Badge variant="subtle" fontFamily="mono">{c.slug}</Badge>
                      {!c.enabled && <Badge colorPalette="gray" variant="outline">disabled</Badge>}
                      <Badge colorPalette={STATUS_COLOR[status] ?? "gray"} variant="subtle">
                        <HStack gap="1">
                          {(status === "starting" || status === "stopping") && <Spinner size="xs" />}
                          <Text fontSize="xs" textTransform="uppercase">{status}</Text>
                        </HStack>
                      </Badge>
                      {c.runner?.pid != null && (
                        <Text fontSize="xs" color="fg.muted">pid {c.runner.pid}</Text>
                      )}
                    </HStack>
                    <Text fontSize="xs" color="fg.muted" fontFamily="mono">{c.rpcHttpUrl}</Text>
                    <Text fontSize="xs" color="fg.muted">
                      health :{c.healthPort} · confirmations {c.confirmations ?? "—"} · startBlock {c.startBlock ?? 0}
                    </Text>
                  </Stack>
                  <HStack gap="1">
                    {!running ? (
                      <Button
                        size="xs"
                        variant="subtle"
                        colorPalette="green"
                        loading={busy === `${c.slug}:start`}
                        disabled={!c.enabled}
                        onClick={() => lifecycle(c.slug, "start")}
                      >
                        Start
                      </Button>
                    ) : (
                      <Button
                        size="xs"
                        variant="subtle"
                        colorPalette="red"
                        loading={busy === `${c.slug}:stop`}
                        onClick={() => lifecycle(c.slug, "stop")}
                      >
                        Stop
                      </Button>
                    )}
                    <Button
                      size="xs"
                      variant="ghost"
                      loading={busy === `${c.slug}:restart`}
                      disabled={!c.enabled}
                      onClick={() => lifecycle(c.slug, "restart")}
                    >
                      Restart
                    </Button>
                    <Button size="xs" variant="ghost" onClick={() => startEdit(c)}>
                      Edit
                    </Button>
                    <Button
                      size="xs"
                      variant="ghost"
                      colorPalette="red"
                      loading={busy === `${c.slug}:delete`}
                      disabled={running}
                      onClick={() => remove(c.slug)}
                    >
                      Delete
                    </Button>
                  </HStack>
                </HStack>
              </Box>
            );
          })}
        </Stack>
      )}
    </Stack>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <Box>
      <HStack gap="2" mb="1">
        <Text fontFamily="mono" fontSize="sm">{label}</Text>
        {hint && <Text fontSize="xs" color="fg.muted">{hint}</Text>}
      </HStack>
      {children}
    </Box>
  );
}
