package selector

import (
	"testing"

	"github.com/evm-auditor/evm-auditor/internal/decon/disasm"
)

// Linear-switch dispatcher selecting owner() (0x8da5cb5b):
// PUSH1 00 CALLDATALOAD PUSH1 e0 SHR DUP1 PUSH4 8da5cb5b EQ PUSH2 0012 JUMPI
// STOP JUMPDEST STOP
func TestExtractLinearSwitch(t *testing.T) {
	d, err := disasm.Disassemble("0x60003560e01c80638da5cb5b1461001257005b00")
	if err != nil {
		t.Fatalf("disasm: %v", err)
	}
	r := Extract(d)
	found := false
	for _, s := range r.Selectors {
		if s.Selector == "0x8da5cb5b" {
			found = true
			if s.SelectorValue != 0x8da5cb5b {
				t.Errorf("SelectorValue = %#x, want 0x8da5cb5b", s.SelectorValue)
			}
		}
	}
	if !found {
		t.Errorf("did not extract 0x8da5cb5b; got %+v", r.Selectors)
	}
}
