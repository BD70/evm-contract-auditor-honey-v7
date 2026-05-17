// Package abi recovers per-function attributes (mutability, arg count, arg
// types, return type) from sim traces — port of evm_decon/abi_recovery.py.
package abi

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/evm-auditor/evm-auditor/internal/decon/blocks"
	"github.com/evm-auditor/evm-auditor/internal/decon/slicer"
	"github.com/evm-auditor/evm-auditor/internal/decon/stacksim"
)

const (
	maxSaneArgCount        = 32
	maxSaneCalldataOffset  = 4 + maxSaneArgCount*32
)

// Recovered mirrors evm_decon.abi_recovery.RecoveredABI.
type Recovered struct {
	Selector   string
	Name       string
	Mutability string // nonpayable | view | payable | pure
	ArgCount   int
	ArgTypes   []string
	ReturnType string
	HasReturn  bool
	Confidence float64
	Evidence   []string
}

var (
	hexNum    = regexp.MustCompile(`0x([0-9a-fA-F]+)`)
	calldataR = regexp.MustCompile(`calldata\[0x([0-9a-fA-F]+)\]`)
)

// Recover walks the slicer's functions and returns one Recovered per fn.
func Recover(slc *slicer.Result, ba blocks.Analysis, sim *stacksim.Result) []Recovered {
	if slc == nil {
		return nil
	}
	blockMap := map[int]blocks.BasicBlock{}
	for _, b := range ba.Blocks {
		blockMap[b.ID] = b
	}
	out := make([]Recovered, 0, len(slc.Functions))
	for i := range slc.Functions {
		out = append(out, recoverOne(&slc.Functions[i], blockMap, sim))
	}
	return out
}

func recoverOne(fn *slicer.FunctionUnit, blockMap map[int]blocks.BasicBlock, sim *stacksim.Result) Recovered {
	evidence := []string{}
	hasSstore, hasSload, hasLog := false, false, false
	hasCallValue, hasCallvalueCheck, hasReturn := false, false, false
	maxCdsCheck := 0
	cdLoadOffsets := map[int]struct{}{}
	addrMaskedOffsets := map[int]struct{}{}

	for _, bid := range fn.BodyBlocks {
		b, ok := blockMap[bid]
		if !ok {
			continue
		}
		for _, ins := range b.Instructions {
			switch ins.Mnemonic {
			case "SSTORE":
				hasSstore = true
			case "SLOAD":
				hasSload = true
			case "RETURN":
				hasReturn = true
			case "CALLVALUE":
				hasCallvalueCheck = true
			default:
				if strings.HasPrefix(ins.Mnemonic, "LOG") {
					hasLog = true
				}
			}
		}
		if sim == nil {
			continue
		}
		tr, ok := sim.Traces[bid]
		if !ok {
			continue
		}
		for _, op := range tr.Operations {
			d := strings.ToLower(op.Description)
			if strings.Contains(d, "call") && strings.Contains(d, "value") {
				hasCallValue = true
			}
		}
		if tr.BranchCondition != nil {
			cond := tr.BranchCondition.String()
			if strings.Contains(cond, "calldatasize") {
				if m := hexNum.FindStringSubmatch(cond); m != nil {
					if n, err := strconv.ParseInt(m[1], 16, 64); err == nil {
						if int(n) > maxCdsCheck && int(n) <= maxSaneCalldataOffset {
							maxCdsCheck = int(n)
						}
					}
				}
			}
		}
		for _, ann := range tr.StackAnnotations {
			for _, m := range calldataR.FindAllStringSubmatch(ann, -1) {
				n, err := strconv.ParseInt(m[1], 16, 64)
				if err == nil && n <= maxSaneCalldataOffset {
					cdLoadOffsets[int(n)] = struct{}{}
				}
			}
			if strings.Contains(ann, "ffffffffffffffffffffffffffffffffffffffff") && strings.Contains(ann, "calldata[") {
				for _, m := range calldataR.FindAllStringSubmatch(ann, -1) {
					n, err := strconv.ParseInt(m[1], 16, 64)
					if err == nil {
						addrMaskedOffsets[int(n)] = struct{}{}
					}
				}
			}
		}
	}

	mutability := "nonpayable"
	if hasCallvalueCheck {
		// Without per-block branch_condition normalization we default nonpayable
		// when CALLVALUE is observed; payable detection via branch text is
		// inexact but matches Python's heuristic intent.
		if sim != nil {
			tr := sim.Traces[fn.EntryBlockID]
			if tr != nil && tr.BranchCondition != nil {
				cond := strings.ReplaceAll(tr.BranchCondition.String(), " ", "")
				if strings.Contains(cond, "msg.value") && (strings.Contains(cond, "!") || strings.Contains(cond, "==0")) {
					evidence = append(evidence, "CALLVALUE check reverts on non-zero → nonpayable")
				} else if strings.Contains(cond, "msg.value") {
					mutability = "payable"
					evidence = append(evidence, "CALLVALUE used without revert → payable")
				}
			}
		}
	} else if !hasSstore && !hasLog && !hasCallValue {
		if hasSload || hasReturn {
			mutability = "view"
			evidence = append(evidence, "no SSTORE/LOG, has SLOAD → view")
			if !hasSload {
				mutability = "pure"
			}
		}
	} else {
		evidence = append(evidence, "has SSTORE or LOG → state-changing")
	}

	argCount := 0
	if maxCdsCheck > 4 {
		argCount = (maxCdsCheck - 4) / 32
		if argCount > maxSaneArgCount {
			argCount = maxSaneArgCount
		}
		evidence = append(evidence, "calldatasize check → "+strconv.Itoa(argCount)+" args")
	} else if len(cdLoadOffsets) > 0 {
		maxOff := 0
		for o := range cdLoadOffsets {
			if o > maxOff {
				maxOff = o
			}
		}
		if maxOff >= 4 {
			argCount = (maxOff-4)/32 + 1
			if argCount > maxSaneArgCount {
				argCount = maxSaneArgCount
			}
		}
	}

	argTypes := make([]string, 0, argCount)
	for i := 0; i < argCount; i++ {
		off := 0x04 + i*0x20
		if _, masked := addrMaskedOffsets[off]; masked {
			argTypes = append(argTypes, "address")
		} else {
			argTypes = append(argTypes, "uint256")
		}
	}

	confidence := 0.5
	if len(evidence) > 0 {
		c := 0.5 + float64(len(evidence))*0.1
		if c > 0.95 {
			c = 0.95
		}
		confidence = c
	}

	return Recovered{
		Selector:   fn.Selector,
		Name:       fn.Name,
		Mutability: mutability,
		ArgCount:   argCount,
		ArgTypes:   argTypes,
		HasReturn:  hasReturn,
		Confidence: confidence,
		Evidence:   evidence,
	}
}
