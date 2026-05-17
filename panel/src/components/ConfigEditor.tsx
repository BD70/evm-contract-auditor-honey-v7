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
  Switch,
  Text,
} from "@chakra-ui/react";
import { useEffect, useMemo, useState } from "react";

interface FieldMeta {
  key: string;
  kind: "string" | "url" | "int" | "bool" | "secret" | "enum";
  group: string;
  default?: any;
  description: string;
  required?: boolean;
  secret?: boolean;
  options?: string[];
}

interface DiffEntry {
  key: string;
  before: string | null;
  after: string | null;
  secret: boolean;
}

const SECRET_MASK = "***";

export function ConfigEditor() {
  const [fields, setFields] = useState<FieldMeta[]>([]);
  const [values, setValues] = useState<Record<string, string>>({});
  const [patch, setPatch] = useState<Record<string, any>>({});
  const [diff, setDiff] = useState<DiffEntry[] | null>(null);
  const [pending, setPending] = useState(false);
  const [savedMsg, setSavedMsg] = useState<string | null>(null);
  const [errMsg, setErrMsg] = useState<string | null>(null);

  const refresh = async () => {
    const [s, v] = await Promise.all([
      fetch("/api/config/schema").then((r) => r.json()),
      fetch("/api/config").then((r) => r.json()),
    ]);
    setFields(s.fields ?? []);
    setValues(v.values ?? {});
    setPatch({});
  };

  useEffect(() => {
    refresh();
  }, []);

  const groups = useMemo(() => {
    const seen = new Set<string>();
    const order: string[] = [];
    for (const f of fields) if (!seen.has(f.group)) {
      seen.add(f.group);
      order.push(f.group);
    }
    return order;
  }, [fields]);

  const setVal = (key: string, v: any) => {
    setPatch((p) => ({ ...p, [key]: v }));
  };

  const handlePreview = async () => {
    setErrMsg(null);
    setSavedMsg(null);
    const r = await fetch("/api/config", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ patch: assemblePatch(patch, values), dryRun: true }),
    });
    const j = await r.json();
    if (!j.ok) {
      setErrMsg(j.error ?? "preview failed");
      return;
    }
    setDiff(j.diff ?? []);
  };

  const handleSave = async (restart: boolean) => {
    setPending(true);
    setErrMsg(null);
    setSavedMsg(null);
    try {
      const r = await fetch("/api/config", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ patch: assemblePatch(patch, values), restartRunner: restart }),
      });
      const j = await r.json();
      if (!j.ok) {
        setErrMsg(j.error ?? "save failed");
      } else {
        setSavedMsg(
          `applied ${j.applied?.length ?? 0} change(s)` + (j.restarted ? " · runner restarted" : restart ? " · restart skipped (runner idle)" : ""),
        );
        setDiff(null);
        await refresh();
      }
    } finally {
      setPending(false);
    }
  };

  return (
    <Stack gap="5">
      <HStack justify="space-between">
        <Heading size="lg">Configuration</Heading>
        <HStack gap="2">
          <Button size="sm" variant="ghost" onClick={refresh}>
            Reload
          </Button>
          <Button size="sm" variant="subtle" onClick={handlePreview} disabled={Object.keys(patch).length === 0}>
            Preview diff
          </Button>
          <Button
            size="sm"
            variant="subtle"
            colorPalette="purple"
            onClick={() => handleSave(false)}
            loading={pending}
            disabled={Object.keys(patch).length === 0}
          >
            Save
          </Button>
          <Button
            size="sm"
            colorPalette="purple"
            onClick={() => handleSave(true)}
            loading={pending}
            disabled={Object.keys(patch).length === 0}
          >
            Save &amp; restart
          </Button>
        </HStack>
      </HStack>

      {savedMsg && <Box bg="green.subtle" color="green.fg" rounded="md" px="3" py="2" fontSize="sm">{savedMsg}</Box>}
      {errMsg && <Box bg="red.subtle" color="red.fg" rounded="md" px="3" py="2" fontSize="sm">{errMsg}</Box>}

      {diff && (
        <Box bg="bg.panel" border="1px solid" borderColor="border" rounded="lg" p="3">
          <Heading size="sm" mb="2">
            Pending changes
          </Heading>
          {diff.length === 0 ? (
            <Text fontSize="sm" color="fg.muted">no changes vs current .env</Text>
          ) : (
            <Stack gap="1">
              {diff.map((d) => (
                <HStack key={d.key} fontFamily="mono" fontSize="xs" gap="3">
                  <Badge variant="subtle">{d.key}</Badge>
                  <Text color="fg.muted">{d.secret ? SECRET_MASK : d.before ?? "—"}</Text>
                  <Text>→</Text>
                  <Text>{d.secret ? SECRET_MASK : d.after ?? "(removed)"}</Text>
                </HStack>
              ))}
            </Stack>
          )}
        </Box>
      )}

      <MaintenancePanel onMsg={setSavedMsg} onErr={setErrMsg} />

      {groups.map((group) => (
        <Box key={group} bg="bg.panel" border="1px solid" borderColor="border" rounded="lg" p="4">
          <Heading size="sm" mb="3">
            {group}
          </Heading>
          <Stack gap="3">
            {fields.filter((f) => f.group === group).map((f) => (
              <Box key={f.key}>
                <HStack gap="2" mb="1">
                  <Text fontFamily="mono" fontSize="sm">
                    {f.key}
                  </Text>
                  {f.required && <Badge size="xs" colorPalette="red" variant="subtle">required</Badge>}
                  {f.secret && <Badge size="xs" variant="outline">secret</Badge>}
                  {f.default != null && (
                    <Text fontSize="xs" color="fg.muted">
                      default: <code>{String(f.default)}</code>
                    </Text>
                  )}
                </HStack>
                <Text fontSize="xs" color="fg.muted" mb="1.5">
                  {f.description}
                </Text>
                <FieldInput field={f} current={values[f.key]} value={patch[f.key]} onChange={(v) => setVal(f.key, v)} />
              </Box>
            ))}
          </Stack>
        </Box>
      ))}
    </Stack>
  );
}

function MaintenancePanel({ onMsg, onErr }: { onMsg: (s: string) => void; onErr: (s: string) => void }) {
  const [pending, setPending] = useState<string | null>(null);

  const prune = async () => {
    setPending("prune");
    try {
      const r = await fetch("/api/maintenance/prune", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ vacuum: true }),
      });
      const j = await r.json();
      onMsg(
        `pruned: ${j.findings} findings · ${j.auditRuns} runs · ${j.lifecycle} lifecycle · ${j.webhooks} webhooks · ${j.deployments} deployments`,
      );
    } catch (err: any) {
      onErr(`prune failed: ${err?.message ?? err}`);
    } finally {
      setPending(null);
    }
  };

  const resetState = async () => {
    if (!confirm("This wipes checkpoint.json and all artifacts in STATE_DIR. The runner must be idle. Continue?")) return;
    setPending("reset");
    try {
      const r = await fetch("/api/maintenance/reset-state", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ confirm: true }),
      });
      const j = await r.json();
      if (j.ok) onMsg(`runner state reset (${(j.removed ?? []).length} paths removed)`);
      else onErr(j.error ?? "reset failed");
    } catch (err: any) {
      onErr(`reset failed: ${err?.message ?? err}`);
    } finally {
      setPending(null);
    }
  };

  return (
    <Box bg="bg.panel" border="1px solid" borderColor="border" rounded="lg" p="4">
      <Heading size="sm" mb="2">
        Maintenance
      </Heading>
      <Text fontSize="xs" color="fg.muted" mb="3">
        Prune deletes old findings, audit runs, lifecycle and delivered webhook rows from the panel DB based on
        <code> PANEL_RETENTION_*_DAYS</code> env vars (defaults: 30 / 14 / 7 / 14 days). Reset wipes runner
        checkpoint + artifacts so the next start reprocesses from <code>START_BLOCK</code>.
      </Text>
      <HStack gap="2">
        <Button size="sm" variant="subtle" loading={pending === "prune"} onClick={prune}>
          Prune old data
        </Button>
        <Button size="sm" variant="subtle" colorPalette="red" loading={pending === "reset"} onClick={resetState}>
          Reset runner state
        </Button>
      </HStack>
    </Box>
  );
}

function assemblePatch(patch: Record<string, any>, current: Record<string, string>) {
  const out: Record<string, any> = {};
  for (const [k, v] of Object.entries(patch)) {
    out[k] = v;
  }
  // Keep unchanged secrets as masked to indicate "no change"
  for (const k of Object.keys(current)) {
    if (out[k] === undefined && current[k] === SECRET_MASK) out[k] = SECRET_MASK;
  }
  return out;
}

function FieldInput({
  field,
  current,
  value,
  onChange,
}: {
  field: FieldMeta;
  current: string | undefined;
  value: any;
  onChange: (v: any) => void;
}) {
  const displayedCurrent = field.secret && current === SECRET_MASK ? SECRET_MASK : current ?? "";
  const v = value !== undefined ? value : displayedCurrent;

  if (field.kind === "bool") {
    const checked = typeof v === "boolean" ? v : String(v).toLowerCase() === "true";
    return (
      <Switch.Root checked={checked} onCheckedChange={(d) => onChange(d.checked)} size="sm">
        <Switch.HiddenInput />
        <Switch.Control>
          <Switch.Thumb />
        </Switch.Control>
        <Switch.Label>{checked ? "true" : "false"}</Switch.Label>
      </Switch.Root>
    );
  }
  if (field.kind === "enum") {
    return (
      <NativeSelect.Root size="sm" w="240px">
        <NativeSelect.Field value={String(v ?? "")} onChange={(e) => onChange(e.target.value)}>
          <option value="">(unset)</option>
          {(field.options ?? []).map((opt) => (
            <option key={opt} value={opt}>
              {opt}
            </option>
          ))}
        </NativeSelect.Field>
        <NativeSelect.Indicator />
      </NativeSelect.Root>
    );
  }
  if (field.kind === "int") {
    return (
      <Input
        size="sm"
        type="number"
        value={String(v ?? "")}
        onChange={(e) => onChange(e.target.value === "" ? "" : Number(e.target.value))}
        maxW="220px"
        fontFamily="mono"
      />
    );
  }
  return (
    <Input
      size="sm"
      type={field.secret ? "password" : "text"}
      value={String(v ?? "")}
      onChange={(e) => onChange(e.target.value)}
      placeholder={field.secret ? SECRET_MASK : ""}
      fontFamily="mono"
    />
  );
}
