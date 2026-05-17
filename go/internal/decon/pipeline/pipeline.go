// Package pipeline orchestrates the deconstruction stages.
//
// Standalone Go pipeline (no Python subprocess). Stages: disasm → metadata →
// strip+re-disasm → selectors → patterns → blocks → stacksim → cfg → slicer
// → resolver → storage layout → ABI recovery → semantic analysis.
package pipeline

import (
	"github.com/evm-auditor/evm-auditor/internal/decon/abi"
	"github.com/evm-auditor/evm-auditor/internal/decon/blocks"
	"github.com/evm-auditor/evm-auditor/internal/decon/cfg"
	"github.com/evm-auditor/evm-auditor/internal/decon/disasm"
	"github.com/evm-auditor/evm-auditor/internal/decon/knownbc"
	"github.com/evm-auditor/evm-auditor/internal/decon/meta"
	"github.com/evm-auditor/evm-auditor/internal/decon/patterns"
	"github.com/evm-auditor/evm-auditor/internal/decon/resolver"
	"github.com/evm-auditor/evm-auditor/internal/decon/selector"
	"github.com/evm-auditor/evm-auditor/internal/decon/semantic"
	"github.com/evm-auditor/evm-auditor/internal/decon/slicer"
	"github.com/evm-auditor/evm-auditor/internal/decon/stacksim"
	"github.com/evm-auditor/evm-auditor/internal/decon/storage"
	"github.com/evm-auditor/evm-auditor/pkg/keccak"
)

// Options mirrors evm_decon.pipeline.PipelineOptions.
type Options struct {
	NoResolve   bool
	NoProfiles  bool
	NoBlocks    bool
	NoDeep      bool
	EOFFormat   bool
	ProxyShell  bool
	StepBudget  int
	ProfileDirs []string
}

// Artifacts is the full typed pipeline output.
type Artifacts struct {
	BytecodeHex         string
	RuntimeBytecodeHex  string
	AnalysisBytecodeHex string
	OriginalHash        string
	RuntimeHash         string
	AnalysisHash        string
	Disasm              disasm.Result
	Metadata            meta.Result
	Selectors           selector.Result
	Patterns            patterns.Result
	Blocks              *blocks.Analysis
	Sim                 *stacksim.Result
	CFG                 *cfg.Analysis
	Slice               *slicer.Result
	Resolved            map[string]string
	Storage             *storage.Result
	ABI                 []abi.Recovered
	Semantic            *semantic.Analysis
	Fingerprint         knownbc.Result
	PipelineWarnings    []string
}

// Analyze runs the full Go pipeline.
func Analyze(bytecodeHex string, opts Options) (*Artifacts, error) {
	clean, err := normalizeAndValidate(bytecodeHex)
	if err != nil {
		return nil, err
	}
	a := &Artifacts{
		BytecodeHex:        clean,
		RuntimeBytecodeHex: clean,
	}
	if rawBytes, err := hexToBytes(clean); err == nil {
		a.OriginalHash = "0x" + keccak.HashHex(rawBytes)
		a.RuntimeHash = a.OriginalHash
	}
	a.Fingerprint = knownbc.Fingerprint(clean)

	d, err := disasm.Disassemble(clean)
	if err != nil {
		return nil, err
	}
	a.Disasm = d

	a.Metadata = meta.Extract(clean)
	if a.Metadata.Found && a.Metadata.MetadataStartOffset > 0 {
		strippedHex := clean[: a.Metadata.MetadataStartOffset*2]
		a.AnalysisBytecodeHex = strippedHex
		if rawBytes, err := hexToBytes(strippedHex); err == nil {
			a.AnalysisHash = "0x" + keccak.HashHex(rawBytes)
		}
		strippedDisasm, err := disasm.Disassemble(strippedHex)
		if err == nil {
			a.Disasm = strippedDisasm
		}
	} else {
		a.AnalysisBytecodeHex = a.RuntimeBytecodeHex
		a.AnalysisHash = a.RuntimeHash
	}

	a.Selectors = selector.Extract(a.Disasm)
	selectorSet := map[string]struct{}{}
	rawSelectors := []string{}
	for _, s := range a.Selectors.Selectors {
		k := s.Selector
		if len(k) >= 2 && k[:2] == "0x" {
			k = k[2:]
		}
		selectorSet[k] = struct{}{}
		rawSelectors = append(rawSelectors, s.Selector)
	}
	a.Patterns = patterns.Detect(a.Disasm, a.AnalysisBytecodeHex, selectorSet)
	a.Resolved = resolver.ResolveAll(rawSelectors)

	if opts.NoBlocks || opts.EOFFormat || opts.ProxyShell {
		return a, nil
	}
	ba := blocks.Build(a.Disasm)
	a.Blocks = &ba

	if opts.NoDeep {
		return a, nil
	}
	a.Sim = stacksim.Simulate(ba, a.Disasm)
	cfgRes := cfg.Analyze(ba, a.Sim)
	a.CFG = &cfgRes
	sliceRes := slicer.Slice(ba, a.Selectors, a.Resolved)
	a.Slice = &sliceRes
	a.Storage = storage.Recover(a.Sim, a.Slice, a.Resolved)
	a.ABI = abi.Recover(a.Slice, ba, a.Sim)
	a.Semantic = semantic.Analyze(a.Slice, a.Storage, a.ABI, a.Sim, a.Resolved)
	return a, nil
}
