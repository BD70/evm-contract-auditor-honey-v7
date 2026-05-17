package stacksim

import (
	"fmt"
	"math/big"

	"github.com/evm-auditor/evm-auditor/internal/decon/disasm"
)

// inferConstantContext mirrors evm_decon.stack_sim._infer_constant_context.
func inferConstantContext(value *big.Int, ins disasm.Instruction, instructions []disasm.Instruction, idx int) string {
	nextOps := []string{}
	for i := 1; i < 4 && idx+i < len(instructions); i++ {
		nextOps = append(nextOps, instructions[idx+i].Mnemonic)
	}
	if len(nextOps) == 0 {
		return ""
	}
	nextOp := nextOps[0]

	if ins.Mnemonic == "PUSH4" && containsString(nextOps[:min(2, len(nextOps))], "EQ") {
		return fmt.Sprintf("function selector: 0x%08x", value.Uint64())
	}
	if nextOp == "JUMP" || nextOp == "JUMPI" {
		return fmt.Sprintf("jump target → 0x%04x", value.Uint64())
	}
	if value.Cmp(big.NewInt(0x40)) == 0 && (nextOp == "MLOAD" || nextOp == "MSTORE") {
		return "free memory pointer (0x40)"
	}
	if value.Cmp(big.NewInt(0x80)) == 0 {
		return "initial free memory value"
	}
	if nextOp == "RETURN" || (len(nextOps) >= 2 && nextOps[1] == "RETURN") {
		switch {
		case value.Cmp(big.NewInt(0x20)) == 0:
			return "return size: 32 bytes"
		case value.Cmp(big.NewInt(0x40)) == 0:
			return "return offset or size"
		}
		return fmt.Sprintf("return parameter: %s", value.String())
	}
	if containsString(nextOps[:min(2, len(nextOps))], "LT") || containsString(nextOps[:min(2, len(nextOps))], "GT") {
		return fmt.Sprintf("comparison bound: %s", value.String())
	}
	if nextOp == "MUL" {
		return fmt.Sprintf("multiplication factor: %s", value.String())
	}
	if nextOp == "DIV" {
		return fmt.Sprintf("division factor: %s", value.String())
	}
	if nextOp == "SHR" && value.Cmp(big.NewInt(0xe0)) == 0 {
		return "shift 224 bits (extract 4-byte selector)"
	}
	if nextOp == "SHL" || nextOp == "SHR" || nextOp == "SAR" {
		return fmt.Sprintf("shift amount: %s", value.String())
	}
	addrMask := new(big.Int)
	addrMask.SetString("ffffffffffffffffffffffffffffffffffffffff", 16)
	if value.Cmp(addrMask) == 0 {
		return "address mask (20 bytes)"
	}
	if nextOp == "ADD" && value.Cmp(big.NewInt(32)) <= 0 {
		return fmt.Sprintf("increment by %s", value.String())
	}
	return ""
}

func containsString(slice []string, target string) bool {
	for _, s := range slice {
		if s == target {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
