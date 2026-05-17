package parity

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type deconManifest struct {
	Fixtures []struct {
		File          string `json:"file"`
		Description   string `json:"description"`
		ParityInclude bool   `json:"parity_include"`
	} `json:"fixtures"`
}

// readHex returns the trimmed hex contents of a corpus/decon fixture.
func readHex(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return strings.TrimSpace(string(b))
}

func findingSet(raw []byte) (matched bool, count float64, set []string, ok bool) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return false, 0, nil, false
	}
	analysis, _ := doc["analysis"].(map[string]any)
	matched, _ = analysis["matched"].(bool)
	count, _ = analysis["finding_count"].(float64)
	findings, _ := doc["findings"].([]any)
	for _, f := range findings {
		fm, _ := f.(map[string]any)
		rid, _ := fm["rule_id"].(string)
		st, _ := fm["status"].(string)
		sev, _ := fm["severity"].(string)
		set = append(set, fmt.Sprintf("%s|%s|%s", rid, st, sev))
	}
	sort.Strings(set)
	return matched, count, set, true
}

func tokenSet(raw []byte, indexKey string) (map[string]struct{}, bool) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, false
	}
	sm, _ := doc["state_model"].(map[string]any)
	out := map[string]struct{}{}
	list, _ := sm[indexKey].([]any)
	for _, e := range list {
		em, _ := e.(map[string]any)
		if id, ok := em["id"].(string); ok && id != "" {
			out[id] = struct{}{}
		}
	}
	return out, true
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestDeconParity asserts functional + token-exact parity between the Python
// reference and the Go port over corpus/decon: identical evm-audit finding
// sets, and identical state_model.library_fingerprints / guard_catalog token
// ids from evm-decon. (Plan stage 3.)
func TestDeconParity(t *testing.T) {
	root := RepoRoot()
	manifestPath := filepath.Join(root, "corpus", "decon", "manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Skipf("no decon manifest (%v)", err)
	}
	var mf deconManifest
	if err := json.Unmarshal(raw, &mf); err != nil {
		t.Fatalf("manifest parse: %v", err)
	}

	// Skip the whole suite cleanly if the Python reference is unavailable.
	probe := RunPython("evm_decon", "--hex", "0x00", "--format", "json")
	if probe.Err != nil && len(probe.Stdout) == 0 {
		t.Skipf("python reference unavailable: %v (%s)", probe.Err, strings.TrimSpace(string(probe.Stderr)))
	}

	rulesArg := filepath.Join("rules", "core")

	for _, fx := range mf.Fixtures {
		fx := fx
		if !fx.ParityInclude {
			continue
		}
		t.Run(fx.File, func(t *testing.T) {
			hexPath := filepath.Join(root, "corpus", "decon", fx.File)
			h := readHex(t, hexPath)

			// 1. Functional parity: evm-audit api-json finding sets.
			pyA := RunPython("evm_audit", "--hex", h, "--rules", rulesArg, "--format", "api-json")
			goA := RunGoBin("evm-audit", "--hex", h, "--rules", rulesArg, "--format", "api-json")
			pyM, pyC, pySet, okPy := findingSet(pyA.Stdout)
			goM, goC, goSet, okGo := findingSet(goA.Stdout)
			if !okPy || !okGo {
				t.Fatalf("unparseable api-json\n  python err=%v stderr=%s\n  go err=%v stderr=%s",
					pyA.Err, strings.TrimSpace(string(pyA.Stderr)),
					goA.Err, strings.TrimSpace(string(goA.Stderr)))
			}
			if pyM != goM || pyC != goC || strings.Join(pySet, ",") != strings.Join(goSet, ",") {
				t.Errorf("finding-set mismatch\n  python: matched=%v count=%v %v\n  go:     matched=%v count=%v %v",
					pyM, pyC, pySet, goM, goC, goSet)
			}

			// 2. Token-exact parity: library_fingerprints + guard_catalog ids.
			pyD := RunPython("evm_decon", "--hex", h, "--format", "json")
			goD := RunGoBin("evm-decon", "--hex", h, "--format", "json")
			for _, key := range []string{"library_fingerprints", "guard_catalog"} {
				pyT, okp := tokenSet(pyD.Stdout, key)
				goT, okg := tokenSet(goD.Stdout, key)
				if !okp || !okg {
					t.Fatalf("unparseable decon json for %s\n  python err=%v stderr=%s\n  go err=%v stderr=%s",
						key, pyD.Err, strings.TrimSpace(string(pyD.Stderr)),
						goD.Err, strings.TrimSpace(string(goD.Stderr)))
				}
				pk, gk := sortedKeys(pyT), sortedKeys(goT)
				if strings.Join(pk, ",") != strings.Join(gk, ",") {
					t.Errorf("%s token mismatch\n  python: %v\n  go:     %v", key, pk, gk)
				}
			}
		})
	}
}
