package storage_test

import (
	"testing"

	"github.com/evm-auditor/evm-auditor/internal/decon/pipeline"
)

func TestStorageViaPipeline(t *testing.T) {
	art, err := pipeline.Analyze("0x60003560e01c80638da5cb5b1461001257005b00", pipeline.Options{NoResolve: true})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if art.Storage == nil {
		t.Fatal("expected non-nil storage result")
	}
	if art.Storage.Slots == nil {
		t.Errorf("expected initialized Slots map")
	}
}
