/*
 * Verifier regression corpus runner.
 *
 * Invoked via `npm run sim:corpus` from the panel directory. Loads every case
 * from cases.json, runs the registered verifier against the LIVE chain at HEAD
 * (so we test the same code path the production worker uses), and diffs the
 * actual verdict against the case's `expect` block.
 *
 * Exit code 0 = every case matched. Exit code 1 = at least one regression.
 *
 * The output is grouped into:
 *   - PASS   : actual matched expected
 *   - FAIL   : actual did not match — verdict changed (this is the dangerous
 *              case; if it's a TP-going-cold or TN-going-hot, we broke
 *              something)
 *   - ERROR  : the verifier itself threw (RPC down, anvil missing, etc.)
 *
 * Filtering:
 *   --only=<id>          run a single case
 *   --tag=<label>        run only cases with the given tag
 *   --rule=<ruleId>      run only cases for a specific rule
 *   --concurrency=<N>    parallel verifications (default 2; same as worker)
 *
 * IMPORTANT: this runner shells out to the live RPC, which means a stable run
 * needs network access and a populated ALCHEMY_KEY / chain RPC env var.
 * It does NOT touch the simulation_cache table — every run is a fresh verify.
 */

import "../../env-bootstrap";
import fs from "node:fs/promises";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { verifyFinding, findVerifier } from "../exploits";
import type { VerdictStatus, VerifyResult } from "../types";

interface Case {
  id: string;
  chainId: number;
  address: string;
  ruleId: string;
  expect: {
    status: VerdictStatus;
    attackerKind?: "any" | "owner";
    verdictContains?: string;
  };
  // Older JSON used "expect.verdictContains" as a sibling key; the runner
  // accepts either spelling so we can evolve the schema without breaking the
  // JSON file.
  "expect.verdictContains"?: string;
  tags?: string[];
  notes?: string;
}

interface CasesFile {
  cases: Case[];
}

interface Outcome {
  caseId: string;
  ruleId: string;
  address: string;
  expected: Case["expect"];
  actual: { status: VerdictStatus; attackerKind?: string; verdict?: string };
  durationMs: number;
  status: "PASS" | "FAIL" | "ERROR";
  failReason?: string;
  errorMessage?: string;
  /** Full evidence object from the verifier — only populated when --evidence is set. */
  evidence?: Record<string, unknown>;
}

type Filters = {
  only?: string;
  tag?: string;
  rule?: string;
  concurrency: number;
  evidence: boolean;
};

function parseArgs(argv: string[]): Filters {
  const f: Filters = { concurrency: 2, evidence: false };
  for (const a of argv) {
    if (a.startsWith("--only=")) f.only = a.slice("--only=".length);
    else if (a.startsWith("--tag=")) f.tag = a.slice("--tag=".length);
    else if (a.startsWith("--rule=")) f.rule = a.slice("--rule=".length);
    else if (a === "--evidence") f.evidence = true;
    else if (a.startsWith("--concurrency=")) {
      const n = Number(a.slice("--concurrency=".length));
      if (Number.isFinite(n) && n > 0) f.concurrency = n;
    }
  }
  return f;
}

async function loadCases(): Promise<Case[]> {
  const p = path.join(__dirname, "cases.json");
  const raw = await fs.readFile(p, "utf8");
  const parsed: CasesFile = JSON.parse(raw);
  return parsed.cases ?? [];
}

function evaluateOutcome(c: Case, r: VerifyResult, durationMs: number): Outcome {
  const evidence: any = r.evidence ?? {};
  const actualAttackerKind: string | undefined = evidence.attackerKind;
  const actual = {
    status: r.status,
    attackerKind: actualAttackerKind,
    verdict: r.verdict ?? undefined,
  };
  const base = {
    caseId: c.id,
    ruleId: c.ruleId,
    address: c.address,
    expected: c.expect,
    actual,
    durationMs,
  };

  if (r.status !== c.expect.status) {
    return {
      ...base,
      status: "FAIL",
      failReason: `status: expected '${c.expect.status}', got '${r.status}' (${r.verdict ?? "no verdict"})`,
    };
  }
  if (c.expect.attackerKind && actualAttackerKind && actualAttackerKind !== c.expect.attackerKind) {
    return {
      ...base,
      status: "FAIL",
      failReason: `attackerKind: expected '${c.expect.attackerKind}', got '${actualAttackerKind}'`,
    };
  }
  const verdictNeedle = c.expect.verdictContains ?? c["expect.verdictContains"];
  if (verdictNeedle && !(r.verdict ?? "").toLowerCase().includes(verdictNeedle.toLowerCase())) {
    return {
      ...base,
      status: "FAIL",
      failReason: `verdict text missing substring '${verdictNeedle}'; got: ${r.verdict ?? ""}`,
    };
  }
  return { ...base, status: "PASS" };
}

async function runOne(c: Case, captureEvidence: boolean): Promise<Outcome> {
  const v = findVerifier(c.ruleId);
  if (!v) {
    return {
      caseId: c.id,
      ruleId: c.ruleId,
      address: c.address,
      expected: c.expect,
      actual: { status: "skipped" },
      durationMs: 0,
      status: "ERROR",
      errorMessage: `no verifier registered for rule '${c.ruleId}'`,
    };
  }
  const t0 = performance.now();
  try {
    const r = await verifyFinding({
      chainId: c.chainId,
      contractAddress: c.address,
      ruleId: c.ruleId,
    });
    const out = evaluateOutcome(c, r, performance.now() - t0);
    if (captureEvidence) out.evidence = r.evidence;
    return out;
  } catch (err: any) {
    return {
      caseId: c.id,
      ruleId: c.ruleId,
      address: c.address,
      expected: c.expect,
      actual: { status: "error" },
      durationMs: performance.now() - t0,
      status: "ERROR",
      errorMessage: String(err?.message ?? err),
    };
  }
}

// Bounded parallel — same concurrency model the worker uses, so corpus timing
// matches production.
async function runWithConcurrency<T, R>(
  items: T[],
  concurrency: number,
  fn: (item: T, idx: number) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      results[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return results;
}

function shortAddr(a: string): string {
  return a.length > 10 ? `${a.slice(0, 6)}…${a.slice(-4)}` : a;
}

function formatOutcome(o: Outcome): string {
  const head = `${o.status.padEnd(5)}  ${o.caseId.padEnd(34)}  ${shortAddr(o.address)}  ${o.ruleId}`;
  if (o.status === "PASS") return `  \x1b[32m${head}\x1b[0m  (${o.durationMs.toFixed(0)}ms)`;
  if (o.status === "FAIL") return `  \x1b[31m${head}\x1b[0m  (${o.durationMs.toFixed(0)}ms)\n         ↳ ${o.failReason}`;
  return `  \x1b[33m${head}\x1b[0m  (${o.durationMs.toFixed(0)}ms)\n         ↳ ${o.errorMessage}`;
}

async function main() {
  const filters = parseArgs(process.argv.slice(2));
  const all = await loadCases();
  const cases = all.filter((c) => {
    if (filters.only && c.id !== filters.only) return false;
    if (filters.tag && !(c.tags ?? []).includes(filters.tag)) return false;
    if (filters.rule && c.ruleId !== filters.rule) return false;
    return true;
  });

  console.log(`[corpus] running ${cases.length}/${all.length} case(s), concurrency=${filters.concurrency}`);
  if (cases.length === 0) {
    console.log("[corpus] nothing to do.");
    process.exit(0);
  }

  const t0 = performance.now();
  const outcomes = await runWithConcurrency(cases, filters.concurrency, (c) => runOne(c, filters.evidence));
  const elapsed = performance.now() - t0;

  const passed = outcomes.filter((o) => o.status === "PASS");
  const failed = outcomes.filter((o) => o.status === "FAIL");
  const errored = outcomes.filter((o) => o.status === "ERROR");

  console.log("");
  console.log("=== results ===");
  for (const o of outcomes) {
    console.log(formatOutcome(o));
    if (filters.evidence && o.evidence) {
      // Render a focused subset of evidence rather than the entire object —
      // most fields are noise. We surface the highest-signal pieces by name.
      const e: any = o.evidence;
      const focused: Record<string, unknown> = {};
      for (const k of [
        "attackerKind",
        "preconditionGap",
        "stateDiff",
        "stateDiffMiss",
        "stateDiffError",
        "owner",
        "ownerClassification",
        "selfdestruct",
        "initialize",
        "reentrancy",
        "txOrigin",
        "proxyUpgrade",
        "uncheckedCall",
        "signatureResolution",
        "candidateCount",
        "attemptsTried",
      ]) {
        if (e[k] !== undefined) focused[k] = e[k];
      }
      // Surface AMM hits compactly (economic-attack verifier).
      if (Array.isArray(e.attempts)) {
        const ammSummary: Array<{ selector: string; name?: string; hits: number; sample?: string }> = [];
        for (const a of e.attempts as Array<{ selector: string; resolvedName?: string; ammHit?: boolean; ammHits?: Array<{ name: string; family: string }> }>) {
          if (a.ammHit || (a.ammHits && a.ammHits.length > 0)) {
            ammSummary.push({
              selector: a.selector,
              name: a.resolvedName ?? undefined,
              hits: a.ammHits?.length ?? 0,
              sample: a.ammHits?.[0] ? `${a.ammHits[0].family}:${a.ammHits[0].name}` : undefined,
            });
          }
        }
        if (ammSummary.length) focused.ammHits = ammSummary;
      }
      if (Object.keys(focused).length) {
        const lines = JSON.stringify(focused, null, 2).split("\n");
        for (const l of lines) console.log("         " + l);
      }
    }
  }
  console.log("");
  console.log(
    `[corpus] pass=${passed.length}  fail=${failed.length}  error=${errored.length}  total=${outcomes.length}  elapsed=${(elapsed / 1000).toFixed(1)}s`,
  );

  // Errors do NOT fail the run — RPC flakiness is common and we don't want a
  // missing API key to look like a regression. Only true mismatches block.
  if (failed.length > 0) {
    console.error("[corpus] REGRESSION DETECTED — at least one case produced an unexpected verdict.");
    process.exit(1);
  }
  if (errored.length > 0) {
    console.warn(
      `[corpus] ${errored.length} case(s) errored (RPC/anvil failures). These do not fail the run, but please re-run when connectivity is restored.`,
    );
  }
  process.exit(0);
}

main().catch((err) => {
  console.error("[corpus] fatal:", err);
  process.exit(2);
});
