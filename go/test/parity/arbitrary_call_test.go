package parity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const arbitraryCallRule = "call.arbitrary_external_call_unvalidated_target"

// TestArbitraryExternalCallOnSwapV3 proves behavior-based (not bytecode-exact)
// detection: the deployed OnchainSwapV3 runtime — a real exploited contract
// (Symbiosis router arbitrary-call class, attacker controls both the call
// target and the calldata, guarded only by a blocklist != check) — must
// trigger call.arbitrary_external_call_unvalidated_target via the native Go
// pipeline. The detector keys on the call_index behavioral signature, never on
// function names or selectors, so any contract with this shape is caught.
func TestArbitraryExternalCallOnSwapV3(t *testing.T) {
	root := RepoRoot()
	if _, err := os.Stat(filepath.Join(root, "go", "bin", "evm-audit")); err != nil {
		t.Skip("go/bin/evm-audit missing — build it first")
	}
	hexPath := filepath.Join(root, "test", "onchainSwapV3", "deployed_bytecode.hex")
	b, err := os.ReadFile(hexPath)
	if err != nil {
		t.Skipf("fixture bytecode missing: %v", err)
	}
	hx := strings.TrimSpace(string(b))

	res := RunGoBin("evm-audit", "--hex", hx, "--rules", "rules/core", "--format", "api-json")
	if res.Err != nil {
		t.Fatalf("evm-audit failed: %v\nstderr: %s", res.Err, res.Stderr)
	}
	var doc map[string]any
	if err := json.Unmarshal(res.Stdout, &doc); err != nil {
		t.Fatalf("decode api-json: %v\nout: %s", err, res.Stdout)
	}
	findings, _ := doc["findings"].([]any)
	got := map[string]string{}
	for _, fAny := range findings {
		f, _ := fAny.(map[string]any)
		id, _ := f["rule_id"].(string)
		st, _ := f["status"].(string)
		got[id] = st
	}
	if _, ok := got[arbitraryCallRule]; !ok {
		t.Fatalf("expected %s to fire on OnchainSwapV3 runtime; findings=%v", arbitraryCallRule, got)
	}
	if st := got[arbitraryCallRule]; st == "suppressed" || st == "" {
		t.Fatalf("%s present but not actionable (status=%q)", arbitraryCallRule, st)
	}
}

// TestArbitraryExternalCallCorpus drives the curated corpus: positives fire,
// the allowlist/registry-guarded negative is suppressed, the ambiguous-origin
// case degrades to inconclusive.
func TestArbitraryExternalCallCorpus(t *testing.T) {
	root := RepoRoot()
	if _, err := os.Stat(filepath.Join(root, "go", "bin", "evm-check")); err != nil {
		t.Skip("go/bin/evm-check missing — build it first")
	}
	corpus := filepath.Join("corpus", "arbitrary_external_call_unvalidated_target")
	rule := filepath.Join("rules", "core", arbitraryCallRule+".json")

	cases := []struct {
		file       string
		wantFire   bool
		wantStatus string
	}{
		{"positive_calldata_target_blocklist.audit.json", true, "probable_vulnerability"},
		{"positive_calldata_target_accounting.audit.json", true, "probable_vulnerability"},
		{"negative_allowlist_guard.audit.json", false, ""},
		{"inconclusive_unresolved_target.audit.json", true, "analysis_inconclusive"},
	}
	for _, c := range cases {
		res := RunGoBin("evm-check", "--facts", filepath.Join(corpus, c.file), "--rules", rule, "--format", "json")
		if res.Err != nil {
			t.Fatalf("%s: evm-check failed: %v\nstderr: %s", c.file, res.Err, res.Stderr)
		}
		var doc map[string]any
		if err := json.Unmarshal(res.Stdout, &doc); err != nil {
			t.Fatalf("%s: decode: %v", c.file, err)
		}
		findings, _ := doc["findings"].([]any)
		if !c.wantFire {
			if len(findings) != 0 {
				t.Fatalf("%s: expected suppression, got %d findings", c.file, len(findings))
			}
			continue
		}
		if len(findings) == 0 {
			t.Fatalf("%s: expected a finding, got none", c.file)
		}
		f, _ := findings[0].(map[string]any)
		if id, _ := f["rule_id"].(string); id != arbitraryCallRule {
			t.Fatalf("%s: wrong rule_id %q", c.file, id)
		}
		if st, _ := f["status"].(string); st != c.wantStatus {
			t.Fatalf("%s: status=%q want %q", c.file, st, c.wantStatus)
		}
	}
}
