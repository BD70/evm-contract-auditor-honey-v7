package disasm

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// Instruction mirrors evm_decon.disassembler.Instruction.
type Instruction struct {
	Offset   int
	Opcode   int
	Mnemonic string
	Operand  *big.Int // PUSH operand value, nil for non-PUSH
	BodySize int      // 1 + DataBytes
	Category string
}

// Result mirrors evm_decon.disassembler.DisassemblyResult.
type Result struct {
	Instructions []Instruction
	BytecodeSize int
	Errors       []string
}

// Disassemble decodes a hex bytecode string into instructions.
// Mirrors evm_decon.disassembler.disassemble.
func Disassemble(bytecodeHex string) (Result, error) {
	clean := strings.TrimPrefix(strings.TrimSpace(bytecodeHex), "0x")
	if len(clean)%2 != 0 {
		return Result{}, fmt.Errorf("bytecode hex length must be even")
	}
	raw, err := hex.DecodeString(clean)
	if err != nil {
		return Result{}, fmt.Errorf("invalid hex: %w", err)
	}
	res := Result{BytecodeSize: len(raw)}
	pc := 0
	for pc < len(raw) {
		opcode := int(raw[pc])
		info := Lookup(opcode)
		instr := Instruction{
			Offset:   pc,
			Opcode:   opcode,
			Mnemonic: info.Mnemonic,
			BodySize: 1 + info.DataBytes,
			Category: info.Category,
		}
		if info.DataBytes > 0 {
			start := pc + 1
			end := start + info.DataBytes
			if end > len(raw) {
				instr.Operand = new(big.Int)
				if start < len(raw) {
					instr.Operand.SetBytes(raw[start:])
				}
				res.Errors = append(res.Errors, fmt.Sprintf("truncated PUSH at pc=%d", pc))
				res.Instructions = append(res.Instructions, instr)
				break
			}
			instr.Operand = new(big.Int).SetBytes(raw[start:end])
		}
		res.Instructions = append(res.Instructions, instr)
		pc += instr.BodySize
	}
	return res, nil
}
