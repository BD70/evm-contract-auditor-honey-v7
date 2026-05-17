// Package selector extracts function selectors from the dispatcher pattern in
// disassembled bytecode. Mirrors evm_decon/selectors.py.
package selector

import (
	"fmt"

	"github.com/evm-auditor/evm-auditor/internal/decon/disasm"
)

// FunctionEntry mirrors evm_decon.selectors.FunctionEntry.
type FunctionEntry struct {
	Selector          string // "0xa9059cbb"
	SelectorValue     uint32
	JumpTarget        int  // -1 if unresolved
	HasJumpTarget     bool
	InstructionOffset int
}

// DispatcherInfo mirrors evm_decon.selectors.DispatcherInfo.
type DispatcherInfo struct {
	Type           string // "linear_switch" | "binary_search" | "unknown"
	StartOffset    int
	EndOffset      int
	NumBranches    int
	HasFallback    bool
	FallbackOffset int
	HasFallbackPC  bool
	HasReceive     bool
}

// Result holds extracted selectors + dispatcher metadata.
type Result struct {
	Selectors  []FunctionEntry
	Dispatcher *DispatcherInfo
	Errors     []string
}

// Extract scans a disassembled instruction stream for the function selector
// dispatch pattern.
func Extract(d disasm.Result) Result {
	insts := d.Instructions
	out := []FunctionEntry{}
	seen := map[uint32]struct{}{}
	dispatcherStart := 0
	dispatcherEnd := 0
	hasFallback := false
	fallbackOffset := 0
	inDispatcher := false

	pushDest := func(idx int) (int, bool) {
		op := insts[idx].Mnemonic
		if op != "PUSH1" && op != "PUSH2" && op != "PUSH3" {
			return 0, false
		}
		if insts[idx].Operand == nil {
			return 0, false
		}
		return int(insts[idx].Operand.Int64()), true
	}

	addEntry := func(selVal uint32, dest int, instrOffset int) {
		if _, ok := seen[selVal]; ok {
			return
		}
		seen[selVal] = struct{}{}
		out = append(out, FunctionEntry{
			Selector:          fmt.Sprintf("0x%08x", selVal),
			SelectorValue:     selVal,
			JumpTarget:        dest,
			HasJumpTarget:     true,
			InstructionOffset: instrOffset,
		})
	}

	i := 0
	for i < len(insts) {
		ins := insts[i]
		// Pattern 1: DUP1 PUSH4 EQ PUSHn JUMPI
		if ins.Mnemonic == "DUP1" && i+4 < len(insts) &&
			insts[i+1].Mnemonic == "PUSH4" && insts[i+2].Mnemonic == "EQ" &&
			insts[i+4].Mnemonic == "JUMPI" {
			if dest, ok := pushDest(i + 3); ok && insts[i+1].Operand != nil {
				selVal := uint32(insts[i+1].Operand.Uint64())
				addEntry(selVal, dest, insts[i+1].Offset)
				if !inDispatcher {
					inDispatcher = true
					dispatcherStart = ins.Offset
				}
				dispatcherEnd = insts[i+4].Offset + insts[i+4].BodySize
				i += 5
				continue
			}
		}
		// Pattern 2: PUSH4 EQ PUSHn JUMPI
		if ins.Mnemonic == "PUSH4" && i+3 < len(insts) &&
			insts[i+1].Mnemonic == "EQ" && insts[i+3].Mnemonic == "JUMPI" {
			if dest, ok := pushDest(i + 2); ok && ins.Operand != nil {
				selVal := uint32(ins.Operand.Uint64())
				addEntry(selVal, dest, ins.Offset)
				if !inDispatcher {
					inDispatcher = true
					dispatcherStart = ins.Offset
				}
				dispatcherEnd = insts[i+3].Offset + insts[i+3].BodySize
				i += 4
				continue
			}
		}
		// Pattern 3: PUSH4 DUP2 EQ PUSHn JUMPI
		if ins.Mnemonic == "PUSH4" && i+4 < len(insts) &&
			insts[i+1].Mnemonic == "DUP2" && insts[i+2].Mnemonic == "EQ" &&
			insts[i+4].Mnemonic == "JUMPI" {
			if dest, ok := pushDest(i + 3); ok && ins.Operand != nil {
				selVal := uint32(ins.Operand.Uint64())
				addEntry(selVal, dest, ins.Offset)
				if !inDispatcher {
					inDispatcher = true
					dispatcherStart = ins.Offset
				}
				dispatcherEnd = insts[i+4].Offset + insts[i+4].BodySize
				i += 5
				continue
			}
		}

		if inDispatcher {
			switch ins.Mnemonic {
			case "JUMP":
				if i > 0 {
					prev := insts[i-1]
					if (prev.Mnemonic == "PUSH1" || prev.Mnemonic == "PUSH2") && prev.Operand != nil {
						fallbackOffset = int(prev.Operand.Int64())
						hasFallback = true
					}
				}
				inDispatcher = false
			case "STOP", "REVERT", "JUMPI":
				inDispatcher = false
			}
		}
		i++
	}

	hasReceive := false
	limit := 20
	if len(insts) < limit {
		limit = len(insts)
	}
	for j := 0; j < limit; j++ {
		if insts[j].Mnemonic == "CALLDATASIZE" && j+1 < len(insts) && insts[j+1].Mnemonic == "ISZERO" {
			hasReceive = true
			break
		}
	}

	var dispatcher *DispatcherInfo
	if len(out) > 0 {
		dispatcher = &DispatcherInfo{
			Type:           "linear_switch",
			StartOffset:    dispatcherStart,
			EndOffset:      dispatcherEnd,
			NumBranches:    len(out),
			HasFallback:    hasFallback,
			FallbackOffset: fallbackOffset,
			HasFallbackPC:  hasFallback,
			HasReceive:     hasReceive,
		}
	}
	return Result{Selectors: out, Dispatcher: dispatcher}
}
