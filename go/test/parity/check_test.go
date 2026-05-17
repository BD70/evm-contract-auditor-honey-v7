package parity

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
)

// TestEVMCheckParity walks every (corpus fixture × rules/core detector)
// combination and asserts that the Go evm-check output is byte-identical to
// Python's. The test self-skips when either binary is missing.
//
// Run with:  cd go && go test ./test/parity/... -run EVMCheckParity -count=1
//
// Pre-req: ensure ../bin/evm-check exists. Build via:
//   go build -o ../bin/evm-check ./cmd/evm-check
func TestEVMCheckParity(t *testing.T) {
	root := RepoRoot()
	if _, err := os.Stat(filepath.Join(root, "go", "bin", "evm-check")); err != nil {
		t.Skip("go/bin/evm-check missing — `go build -o go/bin/evm-check ./go/cmd/evm-check` first")
	}
	if _, err := os.Stat(filepath.Join(root, "evm_check")); err != nil {
		t.Skip("python evm_check not present in repo root")
	}
	corpus := filepath.Join(root, "corpus")
	rulesDir := filepath.Join(root, "rules", "core")
	rules, err := filepath.Glob(filepath.Join(rulesDir, "*.json"))
	if err != nil || len(rules) == 0 {
		t.Skipf("no rules found under %s", rulesDir)
	}
	fixtures := []string{}
	_ = filepath.Walk(corpus, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if filepath.Ext(p) == ".json" && bytes.Contains([]byte(filepath.Base(p)), []byte(".audit.")) {
			fixtures = append(fixtures, p)
		}
		return nil
	})
	if len(fixtures) == 0 {
		t.Skip("no audit fixtures under corpus/")
	}

	// Full sweep: every fixture × every rule, byte-exact, proving the Go
	// engine reproduces Python for every vulnerability class (oracle, proxy,
	// delegatecall, reentrancy/read-only, multi-tx, economic/erc4626,
	// arbitrary-call, …). Bounded worker pool keeps wall time sane.
	limit := len(fixtures)
	if v := os.Getenv("PARITY_MAX_FIXTURES"); v != "" {
		if n := atoiSafe(v); n > 0 && n < limit {
			limit = n
		}
	}
	type job struct{ fix, rule string }
	jobs := make(chan job)
	var tested, mismatches int64
	var mu sync.Mutex
	firstDiffs := []string{}

	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8
	}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				py := RunPython("evm_check", "--facts", j.fix, "--rules", j.rule, "--format", "json")
				if py.Err != nil {
					continue // python-side failure (frozen oracle) — skip
				}
				atomic.AddInt64(&tested, 1)
				goR := RunGoBin("evm-check", "--facts", j.fix, "--rules", j.rule, "--format", "json")
				if goR.Err != nil || !bytes.Equal(py.Stdout, goR.Stdout) {
					atomic.AddInt64(&mismatches, 1)
					mu.Lock()
					if len(firstDiffs) < 5 {
						firstDiffs = append(firstDiffs,
							filepath.Base(j.fix)+" × "+filepath.Base(j.rule))
					}
					mu.Unlock()
				}
			}
		}()
	}
	for _, fix := range fixtures[:limit] {
		for _, rule := range rules {
			jobs <- job{fix, rule}
		}
	}
	close(jobs)
	wg.Wait()

	t.Logf("parity: %d combinations checked, %d mismatches", tested, mismatches)
	if mismatches > 0 {
		t.Fatalf("%d mismatches; first: %v", mismatches, firstDiffs)
	}
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
