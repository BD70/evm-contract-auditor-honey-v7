package blocks

import (
	"testing"

	"github.com/evm-auditor/evm-auditor/internal/decon/disasm"
)

func TestBuildSplitsOnJumpdest(t *testing.T) {
	// PUSH1 04 JUMP JUMPDEST STOP  → 6004 56 5b 00
	d, err := disasm.Disassemble("0x60045b5600")
	if err != nil {
		t.Fatalf("disasm: %v", err)
	}
	a := Build(d)
	if len(a.Blocks) == 0 {
		t.Fatal("expected at least one block")
	}
	if a.JumpdestSet == nil {
		t.Fatal("JumpdestSet nil")
	}
	if _, ok := a.JumpdestSet[2]; !ok {
		t.Errorf("expected JUMPDEST at offset 2, set=%v", a.JumpdestSet)
	}
	if a.OffsetToBlock == nil {
		t.Fatal("OffsetToBlock nil")
	}
}
