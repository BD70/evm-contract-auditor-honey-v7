package stacksim

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/evm-auditor/evm-auditor/internal/decon/blocks"
	"github.com/evm-auditor/evm-auditor/internal/decon/disasm"
)

// Simulate mirrors evm_decon.stack_sim.simulate.
func Simulate(ba blocks.Analysis, _ disasm.Result) *Result {
	res := &Result{
		Traces:    map[int]*BlockTrace{},
		Constants: []ConstantRecord{},
	}
	entryStacks := map[int][]Value{0: nil}
	for _, b := range ba.Blocks {
		entry := entryStacks[b.ID]
		trace := simulateBlock(b, append([]Value(nil), entry...), &res.Constants)
		res.Traces[b.ID] = trace
		for _, succ := range b.ExitsTo {
			if succ < 0 {
				continue
			}
			if _, ok := entryStacks[succ]; !ok {
				entryStacks[succ] = append([]Value(nil), trace.ExitStack...)
			}
		}
	}
	return res
}

func simulateBlock(block blocks.BasicBlock, stack []Value, constants *[]ConstantRecord) *BlockTrace {
	entry := append([]Value(nil), stack...)
	tr := &BlockTrace{
		BlockID:          block.ID,
		EntryStack:       entry,
		StackAnnotations: map[int]string{},
	}

	for idx, ins := range block.Instructions {
		off := ins.Offset
		op := ins.Mnemonic

		switch {
		case strings.HasPrefix(op, "PUSH"):
			val := big.NewInt(0)
			if ins.Operand != nil {
				val = new(big.Int).Set(ins.Operand)
			}
			sv := Const(val, off)
			stack = append(stack, sv)
			ctx := inferConstantContext(val, ins, block.Instructions, idx)
			recordConstant(constants, val, off, ctx)
			if ctx != "" {
				tr.StackAnnotations[off] = ctx
			}

		case strings.HasPrefix(op, "DUP"):
			n := opIndex(op, 3)
			if len(stack) >= n {
				src := stack[len(stack)-n]
				dup := src
				dup.SourceOffset = off
				stack = append(stack, dup)
			} else {
				stack = append(stack, Unknown(off))
			}

		case strings.HasPrefix(op, "SWAP"):
			n := opIndex(op, 4)
			if len(stack) >= n+1 {
				top := len(stack) - 1
				other := len(stack) - 1 - n
				stack[top], stack[other] = stack[other], stack[top]
			}

		case op == "POP":
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}

		case op == "ADD":
			if len(stack) >= 2 {
				b, a := pop2(&stack)
				r := binop(a, b, "+", func(x, y *big.Int) *big.Int { return new(big.Int).Add(x, y) }, true)
				stack = append(stack, r)
				tr.Operations = append(tr.Operations, OperationRecord{Offset: off, Description: r.String(), Category: "assign"})
				tr.StackAnnotations[off] = fmt.Sprintf("%s + %s", a, b)
			}
		case op == "SUB":
			if len(stack) >= 2 {
				b, a := pop2(&stack)
				r := binop(a, b, "-", func(x, y *big.Int) *big.Int { return new(big.Int).Sub(x, y) }, true)
				stack = append(stack, r)
				tr.StackAnnotations[off] = fmt.Sprintf("%s - %s", a, b)
			}
		case op == "MUL":
			if len(stack) >= 2 {
				b, a := pop2(&stack)
				r := binop(a, b, "*", func(x, y *big.Int) *big.Int { return new(big.Int).Mul(x, y) }, true)
				stack = append(stack, r)
				tr.Operations = append(tr.Operations, OperationRecord{Offset: off, Description: fmt.Sprintf("%s * %s", a, b), Category: "assign"})
				tr.StackAnnotations[off] = fmt.Sprintf("%s * %s", a, b)
			}
		case op == "DIV":
			if len(stack) >= 2 {
				b, a := pop2(&stack)
				r := binop(a, b, "/", func(x, y *big.Int) *big.Int {
					if y.Sign() == 0 {
						return big.NewInt(0)
					}
					return new(big.Int).Quo(x, y)
				}, true)
				stack = append(stack, r)
				tr.StackAnnotations[off] = fmt.Sprintf("%s / %s", a, b)
			}
		case op == "MOD":
			if len(stack) >= 2 {
				b, a := pop2(&stack)
				r := binop(a, b, "%", func(x, y *big.Int) *big.Int {
					if y.Sign() == 0 {
						return big.NewInt(0)
					}
					return new(big.Int).Mod(x, y)
				}, true)
				stack = append(stack, r)
			}
		case op == "EXP":
			if len(stack) >= 2 {
				b, a := pop2(&stack)
				r := binop(a, b, "**", func(x, y *big.Int) *big.Int {
					mod := new(big.Int).Lsh(big.NewInt(1), 256)
					return new(big.Int).Exp(x, y, mod)
				}, false)
				stack = append(stack, r)
				tr.StackAnnotations[off] = fmt.Sprintf("%s ** %s", a, b)
			}
		case op == "ADDMOD":
			if len(stack) >= 3 {
				n, b, a := pop3(&stack)
				stack = append(stack, Expr(fmt.Sprintf("(%s + %s) %% %s", a, b, n), off))
			}
		case op == "MULMOD":
			if len(stack) >= 3 {
				n, b, a := pop3(&stack)
				stack = append(stack, Expr(fmt.Sprintf("(%s * %s) %% %s", a, b, n), off))
			}
		case op == "SIGNEXTEND":
			if len(stack) >= 2 {
				b, a := pop2(&stack)
				stack = append(stack, Expr(fmt.Sprintf("signext(%s, %s)", a, b), off))
			}

		case op == "LT":
			if len(stack) >= 2 {
				a, b := pop2Reversed(&stack)
				r := compare(a, b, "<")
				stack = append(stack, r)
				tr.StackAnnotations[off] = fmt.Sprintf("%s < %s", a, b)
			}
		case op == "GT":
			if len(stack) >= 2 {
				a, b := pop2Reversed(&stack)
				r := compare(a, b, ">")
				stack = append(stack, r)
				tr.StackAnnotations[off] = fmt.Sprintf("%s > %s", a, b)
			}
		case op == "SLT":
			if len(stack) >= 2 {
				a, b := pop2Reversed(&stack)
				stack = append(stack, compare(a, b, "<s"))
			}
		case op == "SGT":
			if len(stack) >= 2 {
				a, b := pop2Reversed(&stack)
				stack = append(stack, compare(a, b, ">s"))
			}
		case op == "EQ":
			if len(stack) >= 2 {
				a, b := pop2Reversed(&stack)
				r := compare(a, b, "==")
				stack = append(stack, r)
				tr.StackAnnotations[off] = fmt.Sprintf("%s == %s", a, b)
			}
		case op == "ISZERO":
			if len(stack) >= 1 {
				a := pop1(&stack)
				if a.IsConst() {
					if a.Const.Sign() == 0 {
						stack = append(stack, ConstU64(1, off))
					} else {
						stack = append(stack, ConstU64(0, off))
					}
				} else {
					stack = append(stack, Expr(fmt.Sprintf("!%s", a), off))
				}
				tr.StackAnnotations[off] = fmt.Sprintf("!%s", a)
			}

		case op == "AND":
			if len(stack) >= 2 {
				b, a := pop2(&stack)
				r := binop(a, b, "&", func(x, y *big.Int) *big.Int { return new(big.Int).And(x, y) }, true)
				stack = append(stack, r)
			}
		case op == "OR":
			if len(stack) >= 2 {
				b, a := pop2(&stack)
				r := binop(a, b, "|", func(x, y *big.Int) *big.Int { return new(big.Int).Or(x, y) }, true)
				stack = append(stack, r)
			}
		case op == "XOR":
			if len(stack) >= 2 {
				b, a := pop2(&stack)
				r := binop(a, b, "^", func(x, y *big.Int) *big.Int { return new(big.Int).Xor(x, y) }, true)
				stack = append(stack, r)
			}
		case op == "NOT":
			if len(stack) >= 1 {
				a := pop1(&stack)
				if a.IsConst() {
					stack = append(stack, Const(wrap256(new(big.Int).Not(a.Const)), off))
				} else {
					stack = append(stack, Expr(fmt.Sprintf("~%s", a), off))
				}
			}
		case op == "BYTE":
			if len(stack) >= 2 {
				b, a := pop2(&stack)
				stack = append(stack, Expr(fmt.Sprintf("byte(%s, %s)", a, b), off))
			}
		case op == "SHL":
			if len(stack) >= 2 {
				b, a := pop2(&stack)
				stack = append(stack, shl(a, b, off))
			}
		case op == "SHR":
			if len(stack) >= 2 {
				b, a := pop2(&stack)
				r := shr(a, b, off)
				stack = append(stack, r)
				if a.IsConst() && a.Const.Cmp(big.NewInt(0xe0)) == 0 {
					tr.StackAnnotations[off] = "extract function selector (>> 224)"
				}
			}
		case op == "SAR":
			if len(stack) >= 2 {
				b, a := pop2(&stack)
				stack = append(stack, Expr(fmt.Sprintf("sar(%s, %s)", b, a), off))
			}

		case op == "KECCAK256":
			if len(stack) >= 2 {
				length, ofs := pop2(&stack)
				stack = append(stack, Expr(fmt.Sprintf("keccak256(mem[%s:%s+%s])", ofs, ofs, length), off))
			}

		case op == "ADDRESS":
			stack = append(stack, Expr("address(this)", off))
		case op == "BALANCE":
			if len(stack) >= 1 {
				addr := pop1(&stack)
				stack = append(stack, Expr(fmt.Sprintf("balance(%s)", addr), off))
			}
		case op == "ORIGIN":
			stack = append(stack, Expr("tx.origin", off))
		case op == "CALLER":
			stack = append(stack, Expr("msg.sender", off))
		case op == "CALLVALUE":
			stack = append(stack, Expr("msg.value", off))
		case op == "CALLDATALOAD":
			if len(stack) >= 1 {
				ofs := pop1(&stack)
				stack = append(stack, Expr(fmt.Sprintf("calldata[%s]", ofs), off))
				tr.StackAnnotations[off] = fmt.Sprintf("load calldata[%s]", ofs)
			}
		case op == "CALLDATASIZE":
			stack = append(stack, Expr("calldatasize", off))
		case op == "CALLDATACOPY":
			if len(stack) >= 3 {
				stack = stack[:len(stack)-3]
			}
		case op == "CODESIZE":
			stack = append(stack, Expr("codesize", off))
		case op == "CODECOPY":
			if len(stack) >= 3 {
				stack = stack[:len(stack)-3]
			}
		case op == "GASPRICE":
			stack = append(stack, Expr("gasprice", off))
		case op == "EXTCODESIZE":
			if len(stack) >= 1 {
				addr := pop1(&stack)
				stack = append(stack, Expr(fmt.Sprintf("extcodesize(%s)", addr), off))
			}
		case op == "EXTCODECOPY":
			if len(stack) >= 4 {
				stack = stack[:len(stack)-4]
			}
		case op == "RETURNDATASIZE":
			stack = append(stack, Expr("returndatasize", off))
		case op == "RETURNDATACOPY":
			if len(stack) >= 3 {
				stack = stack[:len(stack)-3]
			}
		case op == "EXTCODEHASH":
			if len(stack) >= 1 {
				addr := pop1(&stack)
				stack = append(stack, Expr(fmt.Sprintf("extcodehash(%s)", addr), off))
			}

		case op == "BLOCKHASH":
			if len(stack) >= 1 {
				n := pop1(&stack)
				stack = append(stack, Expr(fmt.Sprintf("blockhash(%s)", n), off))
			}
		case op == "COINBASE":
			stack = append(stack, Expr("block.coinbase", off))
		case op == "TIMESTAMP":
			stack = append(stack, Expr("block.timestamp", off))
		case op == "NUMBER":
			stack = append(stack, Expr("block.number", off))
		case op == "PREVRANDAO":
			stack = append(stack, Expr("block.prevrandao", off))
		case op == "GASLIMIT":
			stack = append(stack, Expr("block.gaslimit", off))
		case op == "CHAINID":
			stack = append(stack, Expr("chainid", off))
		case op == "SELFBALANCE":
			stack = append(stack, Expr("selfbalance", off))
		case op == "BASEFEE":
			stack = append(stack, Expr("block.basefee", off))
		case op == "GAS":
			stack = append(stack, Expr("gasleft()", off))

		case op == "MLOAD":
			if len(stack) >= 1 {
				addr := pop1(&stack)
				stack = append(stack, Expr(fmt.Sprintf("memory[%s]", addr), off))
				tr.MemoryOps = append(tr.MemoryOps, MemoryOp{OffsetInCode: off, Address: addr, OpType: "read"})
			}
		case op == "MSTORE":
			if len(stack) >= 2 {
				val, addr := pop2(&stack)
				v := val
				tr.MemoryOps = append(tr.MemoryOps, MemoryOp{OffsetInCode: off, Address: addr, Value: &v, OpType: "write"})
				tr.Operations = append(tr.Operations, OperationRecord{Offset: off, Description: fmt.Sprintf("memory[%s] = %s", addr, val), Category: "memory"})
				tr.StackAnnotations[off] = fmt.Sprintf("memory[%s] = %s", addr, val)
			}
		case op == "MSTORE8":
			if len(stack) >= 2 {
				val, addr := pop2(&stack)
				v := val
				tr.MemoryOps = append(tr.MemoryOps, MemoryOp{OffsetInCode: off, Address: addr, Value: &v, OpType: "write"})
			}
		case op == "MSIZE":
			stack = append(stack, Expr("msize", off))

		case op == "SLOAD":
			if len(stack) >= 1 {
				slot := pop1(&stack)
				stack = append(stack, Expr(fmt.Sprintf("storage[%s]", slot), off))
				tr.StorageOps = append(tr.StorageOps, StorageOp{OffsetInCode: off, Slot: slot, OpType: "read"})
				tr.StackAnnotations[off] = fmt.Sprintf("read storage[%s]", slot)
			}
		case op == "SSTORE":
			if len(stack) >= 2 {
				val, slot := pop2(&stack)
				v := val
				tr.StorageOps = append(tr.StorageOps, StorageOp{OffsetInCode: off, Slot: slot, Value: &v, OpType: "write"})
				tr.Operations = append(tr.Operations, OperationRecord{Offset: off, Description: fmt.Sprintf("storage[%s] = %s", slot, val), Category: "storage"})
				tr.StackAnnotations[off] = fmt.Sprintf("storage[%s] = %s", slot, val)
			}
		case op == "TLOAD":
			if len(stack) >= 1 {
				slot := pop1(&stack)
				stack = append(stack, Expr(fmt.Sprintf("transient[%s]", slot), off))
			}
		case op == "TSTORE":
			if len(stack) >= 2 {
				val, slot := pop2(&stack)
				tr.Operations = append(tr.Operations, OperationRecord{Offset: off, Description: fmt.Sprintf("transient[%s] = %s", slot, val), Category: "storage"})
			}

		case op == "JUMP":
			if len(stack) >= 1 {
				dest := pop1(&stack)
				if dest.IsConst() {
					tr.BranchTrueTarget = int(dest.Const.Int64())
					tr.HasBranchTrue = true
				}
			}
		case op == "JUMPI":
			if len(stack) >= 2 {
				dest := pop1(&stack)
				cond := pop1(&stack)
				condCopy := cond
				tr.BranchCondition = &condCopy
				if dest.IsConst() {
					tr.BranchTrueTarget = int(dest.Const.Int64())
					tr.HasBranchTrue = true
				}
				if idx+1 < len(block.Instructions) {
					tr.BranchFalseTarget = block.Instructions[idx+1].Offset
					tr.HasBranchFalse = true
				}
				destStr := dest.String()
				if dest.IsConst() {
					destStr = fmt.Sprintf("0x%04x", dest.Const.Uint64())
				}
				tr.StackAnnotations[off] = fmt.Sprintf("if (%s) goto %s", cond, destStr)
			}
		case op == "JUMPDEST":
			// no-op
		case op == "PC":
			stack = append(stack, ConstU64(uint64(off), off))

		case op == "RETURN":
			if len(stack) >= 2 {
				length, ofs := pop2(&stack)
				tr.Operations = append(tr.Operations, OperationRecord{Offset: off, Description: fmt.Sprintf("return memory[%s..%s+%s]", ofs, ofs, length), Category: "flow"})
				tr.StackAnnotations[off] = fmt.Sprintf("return memory[%s..+%s]", ofs, length)
			}
		case op == "REVERT":
			if len(stack) >= 2 {
				length, ofs := pop2(&stack)
				tr.Operations = append(tr.Operations, OperationRecord{Offset: off, Description: fmt.Sprintf("revert memory[%s..%s+%s]", ofs, ofs, length), Category: "flow"})
			}
		case op == "STOP":
			tr.Operations = append(tr.Operations, OperationRecord{Offset: off, Description: "stop", Category: "flow"})
		case op == "SELFDESTRUCT":
			if len(stack) >= 1 {
				addr := pop1(&stack)
				tr.Operations = append(tr.Operations, OperationRecord{Offset: off, Description: fmt.Sprintf("selfdestruct(%s)", addr), Category: "flow"})
			}
		case op == "CALL":
			if len(stack) >= 7 {
				args := popN(&stack, 7)
				stack = append(stack, Expr("call_success", off))
				tr.Operations = append(tr.Operations, OperationRecord{Offset: off, Description: fmt.Sprintf("call(gas=%s, to=%s, value=%s)", args[0], args[1], args[2]), Category: "call"})
			}
		case op == "STATICCALL":
			if len(stack) >= 6 {
				args := popN(&stack, 6)
				stack = append(stack, Expr("staticcall_success", off))
				tr.Operations = append(tr.Operations, OperationRecord{Offset: off, Description: fmt.Sprintf("staticcall(gas=%s, to=%s)", args[0], args[1]), Category: "call"})
			}
		case op == "DELEGATECALL":
			if len(stack) >= 6 {
				args := popN(&stack, 6)
				stack = append(stack, Expr("delegatecall_success", off))
				tr.Operations = append(tr.Operations, OperationRecord{Offset: off, Description: fmt.Sprintf("delegatecall(to=%s)", args[1]), Category: "call"})
			}
		case op == "CREATE":
			if len(stack) >= 3 {
				args := popN(&stack, 3)
				stack = append(stack, Expr("new_address", off))
				tr.Operations = append(tr.Operations, OperationRecord{Offset: off, Description: fmt.Sprintf("create(value=%s, offset=%s, size=%s)", args[0], args[1], args[2]), Category: "call"})
			}
		case op == "CREATE2":
			if len(stack) >= 4 {
				args := popN(&stack, 4)
				stack = append(stack, Expr("new_address_create2", off))
				tr.Operations = append(tr.Operations, OperationRecord{Offset: off, Description: fmt.Sprintf("create2(value=%s, offset=%s, size=%s, salt=%s)", args[0], args[1], args[2], args[3]), Category: "call"})
			}
		case strings.HasPrefix(op, "LOG"):
			n := opIndex(op, 3)
			pops := n + 2
			if pops > len(stack) {
				pops = len(stack)
			}
			stack = stack[:len(stack)-pops]
		case op == "INVALID" || strings.HasPrefix(op, "UNKNOWN"):
			// no stack change
		case op == "MCOPY":
			if len(stack) >= 3 {
				stack = stack[:len(stack)-3]
			}
		default:
			info := disasm.Lookup(ins.Opcode)
			pops := info.StackIn
			if pops > len(stack) {
				pops = len(stack)
			}
			stack = stack[:len(stack)-pops]
			for i := 0; i < info.StackOut; i++ {
				stack = append(stack, Unknown(off))
			}
		}
	}

	tr.ExitStack = append([]Value(nil), stack...)
	return tr
}

func recordConstant(constants *[]ConstantRecord, val *big.Int, off int, ctx string) {
	hexStr := "0x" + val.Text(16)
	if val.Sign() < 0 {
		hexStr = val.String()
	}
	v := Const(val, off)
	*constants = append(*constants, ConstantRecord{
		Value:   &v,
		HexStr:  hexStr,
		Offset:  fmt.Sprintf("0x%04x", off),
		Context: ctx,
	})
}

func opIndex(op string, prefixLen int) int {
	if len(op) <= prefixLen {
		return 0
	}
	n := 0
	for _, c := range op[prefixLen:] {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func pop1(stack *[]Value) Value {
	s := *stack
	v := s[len(s)-1]
	*stack = s[:len(s)-1]
	return v
}

// pop2 pops [b, a] mirroring Python `b, a = stack.pop(), stack.pop()`.
func pop2(stack *[]Value) (Value, Value) {
	b := pop1(stack)
	a := pop1(stack)
	return b, a
}

// pop2Reversed mirrors comparison opcodes that read [a=top, b=second].
func pop2Reversed(stack *[]Value) (Value, Value) {
	a := pop1(stack)
	b := pop1(stack)
	return a, b
}

func pop3(stack *[]Value) (Value, Value, Value) {
	c := pop1(stack)
	b := pop1(stack)
	a := pop1(stack)
	return c, b, a
}

func popN(stack *[]Value, n int) []Value {
	out := make([]Value, n)
	for i := 0; i < n; i++ {
		out[i] = pop1(stack)
	}
	return out
}

// binop evaluates a constant-folded binary op or returns an expression.
// wrap controls whether the result is masked to 256 bits.
func binop(a, b Value, sym string, fn func(x, y *big.Int) *big.Int, wrap bool) Value {
	if a.IsConst() && b.IsConst() {
		r := fn(a.Const, b.Const)
		if wrap {
			r = wrap256(r)
		}
		return Const(r, 0)
	}
	return Expr(fmt.Sprintf("(%s %s %s)", a, sym, b), 0)
}

func compare(a, b Value, sym string) Value {
	if a.IsConst() && b.IsConst() {
		var hit bool
		switch sym {
		case "<":
			hit = a.Const.Cmp(b.Const) < 0
		case ">":
			hit = a.Const.Cmp(b.Const) > 0
		case "==":
			hit = a.Const.Cmp(b.Const) == 0
		}
		if hit {
			return ConstU64(1, 0)
		}
		return ConstU64(0, 0)
	}
	return Expr(fmt.Sprintf("(%s %s %s)", a, sym, b), 0)
}

func shl(value, shift Value, off int) Value {
	if shift.IsConst() && value.IsConst() {
		if shift.Const.Cmp(big.NewInt(256)) >= 0 {
			return ConstU64(0, off)
		}
		r := new(big.Int).Lsh(value.Const, uint(shift.Const.Int64()))
		return Const(wrap256(r), off)
	}
	return Expr(fmt.Sprintf("(%s << %s)", value, shift), off)
}

func shr(value, shift Value, off int) Value {
	if shift.IsConst() && value.IsConst() {
		if shift.Const.Cmp(big.NewInt(256)) >= 0 {
			return ConstU64(0, off)
		}
		r := new(big.Int).Rsh(value.Const, uint(shift.Const.Int64()))
		return Const(r, off)
	}
	return Expr(fmt.Sprintf("(%s >> %s)", value, shift), off)
}
