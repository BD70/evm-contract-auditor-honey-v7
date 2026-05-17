// Package blocks splits an instruction stream into basic blocks.
// Mirrors evm_decon.blocks.
package blocks

import (
	"github.com/evm-auditor/evm-auditor/internal/decon/disasm"
)

// BasicBlock mirrors evm_decon.blocks.BasicBlock.
type BasicBlock struct {
	ID           int
	StartOffset  int
	Instructions []disasm.Instruction
	ExitsTo      []int  // successor block IDs (or -1 for unresolved)
	Terminator   string // mnemonic of last instruction
}

// Analysis mirrors evm_decon.blocks.BlockAnalysis.
type Analysis struct {
	Blocks         []BasicBlock
	JumpdestSet    map[int]struct{}
	EntryBlockID   int
	OffsetToBlock  map[int]int
}

// Build constructs a BlockAnalysis from a disassembly result.
func Build(res disasm.Result) Analysis {
	jumpdests := map[int]struct{}{}
	for _, ins := range res.Instructions {
		if ins.Mnemonic == "JUMPDEST" {
			jumpdests[ins.Offset] = struct{}{}
		}
	}

	blocks := []BasicBlock{}
	current := BasicBlock{ID: 0, StartOffset: 0}
	flush := func() {
		if len(current.Instructions) == 0 {
			return
		}
		current.ID = len(blocks)
		blocks = append(blocks, current)
	}

	for i, ins := range res.Instructions {
		// JUMPDEST starts a new block (unless current is empty).
		if ins.Mnemonic == "JUMPDEST" && len(current.Instructions) > 0 {
			flush()
			current = BasicBlock{StartOffset: ins.Offset}
		}
		current.Instructions = append(current.Instructions, ins)
		if _, isTerm := disasm.BlockTerminators[ins.Mnemonic]; isTerm {
			current.Terminator = ins.Mnemonic
			flush()
			// Next block starts after this terminator unless we hit EOF.
			if i+1 < len(res.Instructions) {
				next := res.Instructions[i+1]
				current = BasicBlock{StartOffset: next.Offset}
			} else {
				current = BasicBlock{}
			}
		}
	}
	flush()

	offsetToBlock := map[int]int{}
	for _, b := range blocks {
		offsetToBlock[b.StartOffset] = b.ID
	}

	// Resolve fall-through successors and conditional jumps.
	for i := range blocks {
		b := &blocks[i]
		switch b.Terminator {
		case "STOP", "RETURN", "REVERT", "INVALID", "SELFDESTRUCT":
			// no successor
		case "JUMP":
			b.ExitsTo = []int{-1} // dynamic target, resolved later by stack sim
		case "JUMPI":
			next := -1
			if i+1 < len(blocks) {
				next = blocks[i+1].ID
			}
			b.ExitsTo = []int{-1, next}
		default:
			// Fall-through (no explicit terminator).
			if i+1 < len(blocks) {
				b.ExitsTo = []int{blocks[i+1].ID}
			}
		}
	}

	entry := 0
	if len(blocks) > 0 {
		entry = blocks[0].ID
	}
	return Analysis{
		Blocks:        blocks,
		JumpdestSet:   jumpdests,
		EntryBlockID:  entry,
		OffsetToBlock: offsetToBlock,
	}
}
