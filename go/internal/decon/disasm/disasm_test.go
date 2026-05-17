package disasm

import "testing"

func TestDisassembleBasic(t *testing.T) {
	// PUSH1 0x80 PUSH1 0x40 MSTORE STOP
	r, err := Disassemble("0x6080604052 00")
	if err == nil {
		// internal space should be rejected as invalid hex
		t.Fatalf("expected error for spaced hex, got %v", r)
	}
	r, err = Disassemble("0x608060405200")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"PUSH1", "PUSH1", "MSTORE", "STOP"}
	if len(r.Instructions) != len(want) {
		t.Fatalf("got %d instructions, want %d (%+v)", len(r.Instructions), len(want), r.Instructions)
	}
	for i, w := range want {
		if r.Instructions[i].Mnemonic != w {
			t.Errorf("instr[%d] = %s, want %s", i, r.Instructions[i].Mnemonic, w)
		}
	}
	if r.Instructions[0].Operand == nil || r.Instructions[0].Operand.Int64() != 0x80 {
		t.Errorf("PUSH1 operand = %v, want 128", r.Instructions[0].Operand)
	}
}

func TestDisassembleOddLength(t *testing.T) {
	if _, err := Disassemble("0x608"); err == nil {
		t.Fatal("expected odd-length error")
	}
}
