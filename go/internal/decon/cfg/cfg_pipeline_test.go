package cfg_test

import (
	"testing"

	"github.com/evm-auditor/evm-auditor/internal/decon/pipeline"
)

// CFG is exercised through the full pipeline; assert it builds for a
// dispatcher with branches.
func TestCFGViaPipeline(t *testing.T) {
	art, err := pipeline.Analyze("0x60003560e01c80638da5cb5b1461001257005b00", pipeline.Options{NoResolve: true})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if art.CFG == nil {
		t.Fatal("expected non-nil CFG")
	}
	if art.CFG.BlockTypes == nil || art.CFG.Reachable == nil {
		t.Errorf("expected populated CFG maps, got %+v", art.CFG)
	}
}
