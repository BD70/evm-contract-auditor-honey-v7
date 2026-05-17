package semantic_test

import (
	"testing"

	"github.com/evm-auditor/evm-auditor/internal/decon/pipeline"
)

func TestSemanticViaPipeline(t *testing.T) {
	// Ownable selectors → semantic analysis should run and classify a family.
	art, err := pipeline.Analyze("0x60003560e01c80638da5cb5b1461001257005b00", pipeline.Options{NoResolve: true})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if art.Semantic == nil {
		t.Fatal("expected non-nil semantic analysis")
	}
	if art.Semantic.ContractFamily == "" {
		t.Errorf("expected a contract family label (even 'Unknown')")
	}
}
