// Package slicer ports evm_decon/function_slicer.py: split a contract into
// per-function analysis units.
package slicer

import (
	"sort"

	"github.com/evm-auditor/evm-auditor/internal/decon/blocks"
	"github.com/evm-auditor/evm-auditor/internal/decon/selector"
)

// FunctionUnit mirrors evm_decon.function_slicer.FunctionUnit.
type FunctionUnit struct {
	Selector       string
	Name           string
	EntryPC        int
	EntryBlockID   int
	HasEntryBlock  bool
	BodyBlocks     []int
	IsFallback     bool
	IsReceive      bool
	IsConstructor  bool
}

// Result mirrors evm_decon.function_slicer.FunctionSliceResult.
type Result struct {
	Functions        []FunctionUnit
	DispatcherBlocks []int
	SharedBlocks     []int
	BlockToFunction  map[int]string
}

// Slice mirrors evm_decon.function_slicer.slice_functions. resolved is a
// selector → text-signature map (e.g. "0xa9059cbb" → "transfer(address,uint256)").
func Slice(ba blocks.Analysis, sels selector.Result, resolved map[string]string) Result {
	if len(ba.Blocks) == 0 || len(sels.Selectors) == 0 {
		return Result{BlockToFunction: map[int]string{}}
	}

	successors := map[int][]int{}
	for _, b := range ba.Blocks {
		successors[b.ID] = append([]int(nil), b.ExitsTo...)
	}
	offsetToBlock := map[int]int{}
	for _, b := range ba.Blocks {
		offsetToBlock[b.StartOffset] = b.ID
	}
	resolveReturnAddressEdges(ba.Blocks, offsetToBlock, ba.JumpdestSet, successors)

	dispatcherIDs := findDispatcherBlocks(ba.Blocks, sels, successors)
	dispatcherSet := map[int]struct{}{}
	for _, id := range dispatcherIDs {
		dispatcherSet[id] = struct{}{}
	}

	functionReachable := map[string]map[int]struct{}{}
	for _, e := range sels.Selectors {
		if !e.HasJumpTarget {
			continue
		}
		bid, ok := offsetToBlock[e.JumpTarget]
		if !ok {
			continue
		}
		functionReachable[e.Selector] = bfsReachable(bid, successors, dispatcherSet, 500)
	}

	blockOwners := map[int][]string{}
	owners := make([]string, 0, len(functionReachable))
	for sel := range functionReachable {
		owners = append(owners, sel)
	}
	sort.Strings(owners)
	for _, sel := range owners {
		for bid := range functionReachable[sel] {
			blockOwners[bid] = append(blockOwners[bid], sel)
		}
	}

	shared := []int{}
	blockToFunction := map[int]string{}
	for bid, ownersList := range blockOwners {
		if len(ownersList) == 1 {
			blockToFunction[bid] = ownersList[0]
		} else {
			shared = append(shared, bid)
		}
	}
	sort.Ints(shared)

	functions := []FunctionUnit{}
	for _, e := range sels.Selectors {
		if !e.HasJumpTarget {
			continue
		}
		bid, ok := offsetToBlock[e.JumpTarget]
		if !ok {
			continue
		}
		reach := functionReachable[e.Selector]
		body := []int{}
		for b := range reach {
			if _, isDispatch := dispatcherSet[b]; isDispatch {
				continue
			}
			body = append(body, b)
		}
		sort.Ints(body)
		functions = append(functions, FunctionUnit{
			Selector:      e.Selector,
			Name:          resolved[e.Selector],
			EntryPC:       e.JumpTarget,
			EntryBlockID:  bid,
			HasEntryBlock: true,
			BodyBlocks:    body,
		})
	}
	sort.Slice(functions, func(i, j int) bool { return functions[i].Selector < functions[j].Selector })

	return Result{
		Functions:        functions,
		DispatcherBlocks: dispatcherIDs,
		SharedBlocks:     shared,
		BlockToFunction:  blockToFunction,
	}
}

func findDispatcherBlocks(bs []blocks.BasicBlock, sels selector.Result, successors map[int][]int) []int {
	if sels.Dispatcher == nil {
		return nil
	}
	dispatcher := map[int]struct{}{}
	functionEntryOffsets := map[int]struct{}{}
	for _, e := range sels.Selectors {
		if e.HasJumpTarget {
			functionEntryOffsets[e.JumpTarget] = struct{}{}
		}
	}
	blockByID := map[int]blocks.BasicBlock{}
	for _, b := range bs {
		blockByID[b.ID] = b
	}
	visited := map[int]struct{}{}
	queue := []int{0}
	for len(queue) > 0 {
		bid := queue[0]
		queue = queue[1:]
		if _, seen := visited[bid]; seen {
			continue
		}
		visited[bid] = struct{}{}
		block, ok := blockByID[bid]
		if !ok {
			continue
		}
		if _, isEntry := functionEntryOffsets[block.StartOffset]; isEntry && bid != 0 {
			continue
		}
		hasSelectorCmp := false
		for _, ins := range block.Instructions {
			if ins.Mnemonic == "PUSH4" || ins.Mnemonic == "CALLDATALOAD" || ins.Mnemonic == "CALLDATASIZE" {
				hasSelectorCmp = true
				break
			}
		}
		if bid == 0 || hasSelectorCmp || bid < len(bs)/4 {
			if block.StartOffset < sels.Dispatcher.EndOffset+0x100 {
				dispatcher[bid] = struct{}{}
				for _, s := range successors[bid] {
					if s < 0 {
						continue
					}
					if _, seen := visited[s]; !seen {
						queue = append(queue, s)
					}
				}
			}
		}
	}
	out := make([]int, 0, len(dispatcher))
	for k := range dispatcher {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

func resolveReturnAddressEdges(bs []blocks.BasicBlock, offsetToBlock map[int]int, jumpdests map[int]struct{}, successors map[int][]int) {
	for _, b := range bs {
		if len(b.Instructions) == 0 {
			continue
		}
		last := b.Instructions[len(b.Instructions)-1]
		if last.Mnemonic != "JUMP" {
			continue
		}
		pushVals := []int{}
		for _, ins := range b.Instructions {
			if len(ins.Mnemonic) >= 4 && ins.Mnemonic[:4] == "PUSH" && ins.Operand != nil {
				pushVals = append(pushVals, int(ins.Operand.Int64()))
			}
		}
		if len(pushVals) < 2 {
			continue
		}
		for _, val := range pushVals[:len(pushVals)-1] {
			if _, isDest := jumpdests[val]; !isDest {
				continue
			}
			target, ok := offsetToBlock[val]
			if !ok {
				continue
			}
			if !contains(successors[b.ID], target) {
				successors[b.ID] = append(successors[b.ID], target)
			}
		}
	}
}

func bfsReachable(start int, successors map[int][]int, exclude map[int]struct{}, maxBlocks int) map[int]struct{} {
	visited := map[int]struct{}{}
	queue := []int{start}
	for len(queue) > 0 && len(visited) < maxBlocks {
		bid := queue[0]
		queue = queue[1:]
		if _, seen := visited[bid]; seen {
			continue
		}
		if _, ex := exclude[bid]; ex {
			continue
		}
		visited[bid] = struct{}{}
		for _, s := range successors[bid] {
			if s < 0 {
				continue
			}
			if _, seen := visited[s]; seen {
				continue
			}
			if _, ex := exclude[s]; ex {
				continue
			}
			queue = append(queue, s)
		}
	}
	return visited
}

func contains(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
