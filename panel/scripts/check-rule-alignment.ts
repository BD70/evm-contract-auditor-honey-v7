/**
 * Rule-alignment guard. Enforces the contract from ARCHITECTURE_GUIDE.md
 * "Rule Taxonomy" section:
 *
 *   Every rule_id in a verifier's `RULES` array MUST be either:
 *     (1) a canonical Go rule under rules/core/<id>.json, OR
 *     (2) a documented sidecar-synthesized rule (see SIDECAR_RULES below).
 *
 *   Anything else is dead code — the verifier claims to handle a rule_id
 *   that nothing in the system actually emits, so its registration
 *   silently shadows nothing and runs never.
 *
 * Exit codes:
 *   0  alignment is clean
 *   1  one or more orphaned verifier rule IDs (the dead-code case)
 *   2  internal error
 *
 * Run from repo root: `npx tsx panel/scripts/check-rule-alignment.ts`
 * The CI workflow runs this as part of `npm test` for the panel.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

const REPO_ROOT = resolve(__dirname, "..", "..");
const RULES_DIR = join(REPO_ROOT, "rules", "core");
const VERIFIERS_DIR = join(REPO_ROOT, "panel", "src", "server", "sim", "exploits");
const SIDECAR_REGISTRY = join(REPO_ROOT, "panel", "src", "server", "sim", "sidecar.ts");

// Rule IDs that are intentionally TS-synthesized AND have no canonical Go
// rule file. These bypass the canonical-rule check. Everything else
// registered as a sidecar should also have a rules/core/<id>.json so the
// rest of the pipeline (UI, surface mapping, rescue prove) knows about it.
//
// The list is parsed from `panel/src/server/sim/sidecar.ts`'s SIDECARS
// array so it can't drift out of sync.
function loadSidecarRuleIds(): Set<string> {
  const ids = new Set<string>();
  try {
    const src = readFileSync(SIDECAR_REGISTRY, "utf8");
    // The SIDECARS array contains entries like `{ ruleId: "foo.bar", ... }`.
    // Pull every ruleId literal.
    for (const m of src.matchAll(/\bruleId:\s*"([A-Za-z_][A-Za-z0-9_.]*)"/g)) {
      ids.add(m[1]);
    }
  } catch {
    /* missing file means no sidecar bypass — fine */
  }
  return ids;
}
const SIDECAR_RULES = loadSidecarRuleIds();

function loadGoRuleIds(): Set<string> {
  const ids = new Set<string>();
  for (const entry of readdirSync(RULES_DIR)) {
    if (!entry.endsWith(".json")) continue;
    const raw = JSON.parse(readFileSync(join(RULES_DIR, entry), "utf8"));
    const id = raw?.rule?.id;
    if (typeof id === "string") ids.add(id);
  }
  return ids;
}

interface VerifierClaim {
  file: string;
  ruleIds: string[];
}

function loadVerifierClaims(): VerifierClaim[] {
  const claims: VerifierClaim[] = [];
  for (const entry of readdirSync(VERIFIERS_DIR)) {
    if (!entry.endsWith(".ts") || entry === "index.ts") continue;
    const path = join(VERIFIERS_DIR, entry);
    if (!statSync(path).isFile()) continue;
    const src = readFileSync(path, "utf8");

    // Match every `const SOME_RULES = [ "...", "..." ]` declaration. We
    // intentionally match all such arrays (e.g. CALL_RULES + DELEGATECALL_RULES
    // in arbitrary-call.ts) and union them per file.
    const ruleIds = new Set<string>();
    const re = /const\s+\w*RULES\b[^=]*=\s*\[([\s\S]*?)\]/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(src)) !== null) {
      const body = m[1];
      for (const sm of body.matchAll(/["']([A-Za-z_][A-Za-z0-9_.]*)["']/g)) {
        ruleIds.add(sm[1]);
      }
    }
    if (ruleIds.size > 0) claims.push({ file: entry, ruleIds: [...ruleIds].sort() });
  }
  return claims;
}

function main(): number {
  let go: Set<string>;
  let claims: VerifierClaim[];
  try {
    go = loadGoRuleIds();
    claims = loadVerifierClaims();
  } catch (err: any) {
    console.error("check-rule-alignment: internal error:", err?.message ?? err);
    return 2;
  }

  console.log(`Loaded ${go.size} canonical Go rule IDs from ${RULES_DIR}`);
  console.log(`Loaded ${claims.length} verifier file(s) from ${VERIFIERS_DIR}`);
  console.log(`Loaded ${SIDECAR_RULES.size} sidecar-bypass rule(s) from ${SIDECAR_REGISTRY}`);
  console.log("");

  const orphans: Array<{ file: string; ruleId: string }> = [];
  for (const claim of claims) {
    for (const id of claim.ruleIds) {
      if (!go.has(id) && !SIDECAR_RULES.has(id)) {
        orphans.push({ file: claim.file, ruleId: id });
      }
    }
  }

  if (orphans.length === 0) {
    console.log("OK — every verifier rule_id is canonical or documented sidecar.");
    return 0;
  }

  console.error("FAIL — orphaned verifier rule IDs (dead code):");
  for (const o of orphans) {
    console.error(`  ${o.file}: "${o.ruleId}"`);
  }
  console.error("");
  console.error("Fix: either (a) remove the rule_id from the verifier's RULES array,");
  console.error("           (b) add rules/core/<id>.json so the Go analyzer emits it, or");
  console.error("           (c) add it to SIDECAR_RULES with a corresponding worker.ts wiring.");
  console.error("See ARCHITECTURE_GUIDE.md \u00a7 Rule Taxonomy for details.");
  return 1;
}

process.exit(main());
