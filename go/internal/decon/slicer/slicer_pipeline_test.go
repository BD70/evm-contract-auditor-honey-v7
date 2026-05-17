package slicer_test

import (
	"testing"

	"github.com/evm-auditor/evm-auditor/internal/decon/pipeline"
)

func TestSliceViaPipeline(t *testing.T) {
	art, err := pipeline.Analyze("0x60003560e01c80638da5cb5b1461001257005b00", pipeline.Options{NoResolve: true})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if art.Slice == nil {
		t.Fatal("expected non-nil slicer result")
	}
	if art.Slice.BlockToFunction == nil {
		t.Errorf("expected BlockToFunction map, got nil")
	}
}
