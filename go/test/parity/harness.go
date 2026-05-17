// Package parity drives golden-file comparison between the Python reference
// implementation and the Go port over the corpus tree.
//
// The harness shells out to both implementations, captures stdout, and reports
// per-fixture diffs. It is invoked from `go test ./test/parity/...` (see the
// _test.go files) and from CI.
//
// Layout assumptions:
//
//	<repo>/corpus/<scenario>/*.audit.json
//	<repo>/rules/core/*.json
//	<repo>/go/                # this module's root
//	<repo>/go/test/parity     # this directory
//
// Paths are derived relative to GOMOD so the harness works without env vars.
package parity

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"runtime"
)

// RepoRoot returns the absolute path of the parent directory of the go/ module
// (i.e. the repository root containing both Python sources and the go/ subdir).
func RepoRoot() string {
	_, thisFile, _, _ := runtime.Caller(0)
	// thisFile = <repo>/go/test/parity/harness.go
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", ".."))
}

// RunResult captures stdout + stderr from a single binary invocation.
type RunResult struct {
	Stdout []byte
	Stderr []byte
	Err    error
}

// RunPython invokes `python3 -m <module>` with args from the repo root.
func RunPython(module string, args ...string) RunResult {
	full := append([]string{"-m", module}, args...)
	cmd := exec.Command("python3", full...)
	cmd.Dir = RepoRoot()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return RunResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), Err: err}
}

// RunGoBin invokes a built Go binary by name (e.g. "evm-check") with args.
// Binaries are expected to live under <repo>/go/bin/<name>; if that directory
// is empty the harness builds them on demand into a temp tree.
func RunGoBin(name string, args ...string) RunResult {
	binPath := filepath.Join(RepoRoot(), "go", "bin", name)
	cmd := exec.Command(binPath, args...)
	cmd.Dir = RepoRoot()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return RunResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), Err: err}
}
