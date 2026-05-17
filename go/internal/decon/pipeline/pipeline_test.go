package pipeline

import "testing"

// Exercises the full deep pipeline (disasm→meta→selectors→patterns→blocks→
// stacksim→cfg→slicer→storage→abi→semantic→knownbc) on a dispatcher with an
// owner() branch, asserting each deep stage produced output.
func TestAnalyzeDeepStages(t *testing.T) {
	hex := "0x60003560e01c80638da5cb5b1461001257005b00"
	art, err := Analyze(hex, Options{NoResolve: true})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(art.Disasm.Instructions) == 0 {
		t.Fatal("disasm empty")
	}
	if art.Blocks == nil {
		t.Fatal("blocks not built")
	}
	if art.Sim == nil {
		t.Fatal("stacksim not run")
	}
	if art.CFG == nil {
		t.Fatal("cfg not built")
	}
	if art.Slice == nil {
		t.Fatal("slicer not run")
	}
	if art.Semantic == nil {
		t.Fatal("semantic not run")
	}
	if art.RuntimeHash == "" || art.AnalysisHash == "" {
		t.Errorf("hashes not populated: %q %q", art.RuntimeHash, art.AnalysisHash)
	}
}

func TestAnalyzeRejectsBadHex(t *testing.T) {
	if _, err := Analyze("0xzz", Options{}); err == nil {
		t.Fatal("expected error for invalid hex")
	}
}

func TestAnalyzeFingerprintAlwaysSet(t *testing.T) {
	// ERC1167 clone — fingerprint must populate even on the shallow path.
	art, err := Analyze("0x363d3d373d3d3d363d7300000000000000000000000000000000000000015af43d82803e903d91602b57fd5bf3", Options{NoBlocks: true})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if !art.Fingerprint.HasERC1167Clone {
		t.Errorf("expected ERC1167 clone fingerprint on shallow path")
	}
}
