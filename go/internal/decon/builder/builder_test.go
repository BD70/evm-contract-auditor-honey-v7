package builder

import (
	"testing"

	"github.com/evm-auditor/evm-auditor/internal/decon/pipeline"
)

func TestBuildStateModelComplete(t *testing.T) {
	// OZ Ownable2Step + AccessControl + ERC-1967 forwarding proxy.
	hex := "0x6080604052e30c397879ba50978da5cb5bf2fde38b91d148542f2ff15dd547741f" +
		"360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc" +
		"b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103" +
		"36363737f43d3d3e3d3d3dfd3df300"

	art, err := pipeline.Analyze(hex, pipeline.Options{NoResolve: true})
	if err != nil {
		t.Fatalf("pipeline: %v", err)
	}
	out := Build(art)

	sm, ok := out["state_model"].(map[string]any)
	if !ok {
		t.Fatal("state_model missing or wrong type")
	}
	for _, key := range []string{
		"storage_entities", "slot_index", "path_index", "guard_catalog",
		"call_index", "economic_index", "proxy_index", "initializer_index",
		"evidence_index", "library_fingerprints",
	} {
		if _, present := sm[key]; !present {
			t.Errorf("state_model.%s missing", key)
		}
	}

	lf, _ := sm["library_fingerprints"].([]any)
	if len(lf) == 0 {
		t.Fatal("library_fingerprints empty for OZ/ERC1967 bytecode")
	}
	ids := map[string]bool{}
	for _, e := range lf {
		if m, ok := e.(map[string]any); ok {
			ids[m["id"].(string)] = true
		}
	}
	for _, want := range []string{"ERC1967_PROXY", "OZ_OWNABLE", "OZ_OWNABLE2STEP", "OZ_ACCESS_CONTROL"} {
		if !ids[want] {
			t.Errorf("library_fingerprints missing %s; got %v", want, ids)
		}
	}

	// global_tags must include the merged fingerprint tokens.
	gt, _ := out["global_tags"].([]any)
	gset := map[string]bool{}
	for _, g := range gt {
		gset[g.(string)] = true
	}
	if !gset["OZ_OWNABLE2STEP"] || !gset["KNOWN_SAFE_PROXY_PATTERN"] {
		t.Errorf("global_tags missing merged fingerprint tokens: %v", gt)
	}

	fp, _ := out["bytecode_fingerprint"].(map[string]any)
	if fp == nil || fp["tags"] == nil {
		t.Fatal("bytecode_fingerprint.tags missing")
	}
}

func TestInitializerFallback(t *testing.T) {
	// Contains the OZ v5 Initializable slot constant → INITIALIZABLE fingerprint.
	hex := "0x6080604052f0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a0000"
	art, err := pipeline.Analyze(hex, pipeline.Options{NoResolve: true})
	if err != nil {
		t.Fatalf("pipeline: %v", err)
	}
	out := Build(art)
	sm := out["state_model"].(map[string]any)
	init, _ := sm["initializer_index"].([]any)
	if len(init) == 0 {
		t.Errorf("expected initializer_index fallback entry, got empty")
	}
}
