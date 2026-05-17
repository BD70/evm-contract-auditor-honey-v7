// Package audit orchestrates Go decon + Go check end-to-end. No subprocess.
package audit

import (
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/evm-auditor/evm-auditor/internal/check/engine"
	"github.com/evm-auditor/evm-auditor/internal/check/loader"
	"github.com/evm-auditor/evm-auditor/internal/decon/builder"
	"github.com/evm-auditor/evm-auditor/internal/decon/pipeline"
)

// Options mirrors evm_audit CLI flags relevant to the decon pipeline.
type Options struct {
	NoResolve    bool
	NoProfiles   bool
	ProfileDirs  []string
	EOF          bool
	ProxyShell   bool
	StepBudgetMs int
	RulesPath    string
	BytecodePath string
	BytecodeHex  string
	InputKind    string
}

// BuildBehavior runs the in-process Go decon pipeline. Recovers from panics
// in any sub-stage and returns them as errors so a single malformed input
// cannot crash a long-lived runner process.
func BuildBehavior(opts Options) (out map[string]any, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("decon pipeline panic: %v\n%s", r, debug.Stack())
		}
	}()
	hex := opts.BytecodeHex
	if hex == "" && opts.BytecodePath != "" {
		raw, e := os.ReadFile(opts.BytecodePath)
		if e != nil {
			return nil, fmt.Errorf("read bytecode file: %w", e)
		}
		hex = strings.TrimSpace(string(raw))
	}
	if hex == "" {
		return nil, fmt.Errorf("bytecode hex or path required")
	}
	art, e := pipeline.Analyze(hex, pipeline.Options{
		NoResolve:   opts.NoResolve,
		NoProfiles:  opts.NoProfiles,
		EOFFormat:   opts.EOF,
		ProxyShell:  opts.ProxyShell,
		ProfileDirs: opts.ProfileDirs,
		StepBudget:  opts.StepBudgetMs,
	})
	if e != nil {
		return nil, fmt.Errorf("decon pipeline: %w", e)
	}
	return builder.Build(art), nil
}

// AuditBytecode runs decon → check and returns (behavior, checker). Same panic
// guard as BuildBehavior.
func AuditBytecode(opts Options) (behavior map[string]any, checker map[string]any, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("audit panic: %v\n%s", r, debug.Stack())
		}
	}()
	behavior, err = BuildBehavior(opts)
	if err != nil {
		return nil, nil, err
	}
	rules, err := loader.LoadRules(opts.RulesPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load rules: %w", err)
	}
	checker, err = engine.CheckAudit(behavior, rules)
	if err != nil {
		return nil, nil, fmt.Errorf("check engine: %w", err)
	}
	return behavior, checker, nil
}
