package schema

import "testing"

func TestSchemaConstants(t *testing.T) {
	if BehaviorSchemaV2 == "" || StateModelSchemaV2 == "" {
		t.Fatal("schema id constants must be non-empty")
	}
	if len(ProofOrder) == 0 || len(ValidStatuses) == 0 {
		t.Fatal("schema policy maps must be populated")
	}
	if ProofOrder["P0"] != 0 || ProofOrder["P4"] != 4 {
		t.Errorf("ProofOrder mapping wrong: %v", ProofOrder)
	}
}
