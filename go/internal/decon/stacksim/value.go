// Package stacksim ports evm_decon/stack_sim.py: lightweight EVM stack
// simulator with constant propagation. Single forward pass, no branch forking.
package stacksim

import (
	"fmt"
	"hash/crc32"
	"math/big"
)

// Kind is the abstract value tag.
type Kind uint8

const (
	KindUnknown Kind = iota
	KindConst
	KindExpr
)

// Value is a single abstract stack slot.
type Value struct {
	Kind         Kind
	Const        *big.Int // populated when Kind == KindConst
	Expr         string   // populated when Kind == KindExpr
	SourceOffset int
	HasOffset    bool
}

// Const constructs a constant Value.
func Const(v *big.Int, off int) Value {
	c := new(big.Int).Set(v)
	return Value{Kind: KindConst, Const: c, SourceOffset: off, HasOffset: true}
}

// ConstU64 is a small-int helper.
func ConstU64(v uint64, off int) Value {
	return Value{Kind: KindConst, Const: new(big.Int).SetUint64(v), SourceOffset: off, HasOffset: true}
}

// maxExprLen caps symbolic expression strings to prevent exponential growth.
// In contracts like Uniswap V3's mulDiv, each non-const binop nests operand
// strings, doubling length per level. 20-30 chained ops produce multi-GB
// strings. Truncating to 1KB with a CRC32 hash preserves identity for
// downstream equality checks while capping per-Value memory.
const maxExprLen = 1024

// Expr constructs an expression Value with a string description.
func Expr(desc string, off int) Value {
	if len(desc) > maxExprLen {
		h := crc32.ChecksumIEEE([]byte(desc))
		desc = fmt.Sprintf("<sym:%08x>", h)
	}
	return Value{Kind: KindExpr, Expr: desc, SourceOffset: off, HasOffset: true}
}

// Unknown constructs an opaque Value.
func Unknown(off int) Value {
	return Value{Kind: KindUnknown, SourceOffset: off, HasOffset: true}
}

// IsConst reports whether v carries a concrete integer.
func (v Value) IsConst() bool { return v.Kind == KindConst && v.Const != nil }

// String mirrors evm_decon.stack_sim.StackValue.__repr__ exactly: hex-formatted
// constants with width chosen by magnitude.
func (v Value) String() string {
	switch v.Kind {
	case KindConst:
		if v.Const == nil {
			return "?"
		}
		if v.Const.Sign() < 0 {
			return v.Const.String()
		}
		// Pick width buckets matching Python.
		switch {
		case v.Const.Cmp(big.NewInt(0xff)) <= 0:
			return fmt.Sprintf("0x%02x", v.Const.Uint64())
		case v.Const.Cmp(big.NewInt(0xffff)) <= 0:
			return fmt.Sprintf("0x%04x", v.Const.Uint64())
		case v.Const.Cmp(big.NewInt(0xffffffff)) <= 0:
			return fmt.Sprintf("0x%08x", v.Const.Uint64())
		default:
			return "0x" + v.Const.Text(16)
		}
	case KindExpr:
		return v.Expr
	}
	return "?"
}

// mask256 = 2^256 - 1.
var mask256 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

func wrap256(v *big.Int) *big.Int {
	return new(big.Int).And(v, mask256)
}
