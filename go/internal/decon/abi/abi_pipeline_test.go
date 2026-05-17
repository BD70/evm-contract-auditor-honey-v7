package abi_test

import (
	"testing"

	"github.com/evm-auditor/evm-auditor/internal/decon/pipeline"
)

func TestABIViaPipeline(t *testing.T) {
	art, err := pipeline.Analyze("0x60003560e01c80638da5cb5b1461001257005b00", pipeline.Options{NoResolve: true})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	// ABI recovery must not panic and returns a (possibly empty) slice.
	if art.ABI == nil {
		t.Log("no ABI entries recovered for minimal dispatcher (acceptable)")
	}
	for _, r := range art.ABI {
		if r.Selector == "" {
			t.Errorf("recovered ABI entry with empty selector: %+v", r)
		}
	}
}
