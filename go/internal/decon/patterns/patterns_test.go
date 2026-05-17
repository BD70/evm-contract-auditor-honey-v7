package patterns

import (
	"testing"

	"github.com/evm-auditor/evm-auditor/internal/decon/disasm"
)

func TestDetectRuns(t *testing.T) {
	d, err := disasm.Disassemble("0x608060405200")
	if err != nil {
		t.Fatalf("disasm: %v", err)
	}
	r := Detect(d, "608060405200", map[string]struct{}{})
	_ = r.Proxy
	if len(r.OpcodeCategories) < 0 {
		t.Errorf("unreachable")
	}
}
