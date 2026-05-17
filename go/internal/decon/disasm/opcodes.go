// Package disasm holds the EVM opcode table, instruction stream, and
// disassembler. Mirrors evm_decon/opcodes.py + disassembler.py.
package disasm

import "fmt"

// OpcodeInfo mirrors evm_decon.opcodes.OpcodeInfo.
type OpcodeInfo struct {
	Hex         int
	Mnemonic    string
	StackIn     int
	StackOut    int
	DataBytes   int // PUSH1..PUSH32 carry inline data
	Description string
	Category    string
}

// Opcodes table indexed by byte value. Covers Shanghai/Cancun.
var Opcodes = map[int]OpcodeInfo{}

func op(h int, name string, si, so, db int, desc, cat string) {
	Opcodes[h] = OpcodeInfo{Hex: h, Mnemonic: name, StackIn: si, StackOut: so, DataBytes: db, Description: desc, Category: cat}
}

func init() {
	op(0x00, "STOP", 0, 0, 0, "Halts execution", "flow")
	op(0x01, "ADD", 2, 1, 0, "Addition", "arithmetic")
	op(0x02, "MUL", 2, 1, 0, "Multiplication", "arithmetic")
	op(0x03, "SUB", 2, 1, 0, "Subtraction", "arithmetic")
	op(0x04, "DIV", 2, 1, 0, "Integer division", "arithmetic")
	op(0x05, "SDIV", 2, 1, 0, "Signed integer division", "arithmetic")
	op(0x06, "MOD", 2, 1, 0, "Modulo remainder", "arithmetic")
	op(0x07, "SMOD", 2, 1, 0, "Signed modulo remainder", "arithmetic")
	op(0x08, "ADDMOD", 3, 1, 0, "Modular addition", "arithmetic")
	op(0x09, "MULMOD", 3, 1, 0, "Modular multiplication", "arithmetic")
	op(0x0A, "EXP", 2, 1, 0, "Exponentiation", "arithmetic")
	op(0x0B, "SIGNEXTEND", 2, 1, 0, "Extend length of signed integer", "arithmetic")

	op(0x10, "LT", 2, 1, 0, "Less-than comparison", "comparison")
	op(0x11, "GT", 2, 1, 0, "Greater-than comparison", "comparison")
	op(0x12, "SLT", 2, 1, 0, "Signed less-than", "comparison")
	op(0x13, "SGT", 2, 1, 0, "Signed greater-than", "comparison")
	op(0x14, "EQ", 2, 1, 0, "Equality check", "comparison")
	op(0x15, "ISZERO", 1, 1, 0, "Is zero", "comparison")
	op(0x16, "AND", 2, 1, 0, "Bitwise AND", "bitwise")
	op(0x17, "OR", 2, 1, 0, "Bitwise OR", "bitwise")
	op(0x18, "XOR", 2, 1, 0, "Bitwise XOR", "bitwise")
	op(0x19, "NOT", 1, 1, 0, "Bitwise NOT", "bitwise")
	op(0x1A, "BYTE", 2, 1, 0, "Retrieve single byte from word", "bitwise")
	op(0x1B, "SHL", 2, 1, 0, "Shift left", "bitwise")
	op(0x1C, "SHR", 2, 1, 0, "Logical shift right", "bitwise")
	op(0x1D, "SAR", 2, 1, 0, "Arithmetic shift right", "bitwise")

	op(0x20, "KECCAK256", 2, 1, 0, "Compute Keccak-256 hash", "crypto")

	op(0x30, "ADDRESS", 0, 1, 0, "Get address of current contract", "env")
	op(0x31, "BALANCE", 1, 1, 0, "Get balance of account", "env")
	op(0x32, "ORIGIN", 0, 1, 0, "Get execution origination address (tx.origin)", "env")
	op(0x33, "CALLER", 0, 1, 0, "Get caller address (msg.sender)", "env")
	op(0x34, "CALLVALUE", 0, 1, 0, "Get deposited value (msg.value)", "env")
	op(0x35, "CALLDATALOAD", 1, 1, 0, "Load input data (calldata)", "env")
	op(0x36, "CALLDATASIZE", 0, 1, 0, "Get size of input data", "env")
	op(0x37, "CALLDATACOPY", 3, 0, 0, "Copy input data to memory", "env")
	op(0x38, "CODESIZE", 0, 1, 0, "Get size of code", "env")
	op(0x39, "CODECOPY", 3, 0, 0, "Copy code to memory", "env")
	op(0x3A, "GASPRICE", 0, 1, 0, "Get gas price", "env")
	op(0x3B, "EXTCODESIZE", 1, 1, 0, "Get size of external code", "env")
	op(0x3C, "EXTCODECOPY", 4, 0, 0, "Copy external code to memory", "env")
	op(0x3D, "RETURNDATASIZE", 0, 1, 0, "Get size of return data", "env")
	op(0x3E, "RETURNDATACOPY", 3, 0, 0, "Copy return data to memory", "env")
	op(0x3F, "EXTCODEHASH", 1, 1, 0, "Get hash of external code", "env")

	op(0x40, "BLOCKHASH", 1, 1, 0, "Get block hash", "block")
	op(0x41, "COINBASE", 0, 1, 0, "Get block's beneficiary address", "block")
	op(0x42, "TIMESTAMP", 0, 1, 0, "Get block's timestamp", "block")
	op(0x43, "NUMBER", 0, 1, 0, "Get block's number", "block")
	op(0x44, "PREVRANDAO", 0, 1, 0, "Get previous RANDAO value (was DIFFICULTY)", "block")
	op(0x45, "GASLIMIT", 0, 1, 0, "Get block's gas limit", "block")
	op(0x46, "CHAINID", 0, 1, 0, "Get chain ID", "block")
	op(0x47, "SELFBALANCE", 0, 1, 0, "Get balance of current contract", "block")
	op(0x48, "BASEFEE", 0, 1, 0, "Get block's base fee", "block")
	op(0x49, "BLOBHASH", 1, 1, 0, "Get versioned hash of blob (Cancun)", "block")
	op(0x4A, "BLOBBASEFEE", 0, 1, 0, "Get blob base fee (Cancun)", "block")

	op(0x50, "POP", 1, 0, 0, "Remove item from stack", "stack")
	op(0x51, "MLOAD", 1, 1, 0, "Load word from memory", "memory")
	op(0x52, "MSTORE", 2, 0, 0, "Store word to memory", "memory")
	op(0x53, "MSTORE8", 2, 0, 0, "Store byte to memory", "memory")
	op(0x54, "SLOAD", 1, 1, 0, "Load word from storage", "storage")
	op(0x55, "SSTORE", 2, 0, 0, "Store word to storage", "storage")
	op(0x56, "JUMP", 1, 0, 0, "Unconditional jump", "flow")
	op(0x57, "JUMPI", 2, 0, 0, "Conditional jump", "flow")
	op(0x58, "PC", 0, 1, 0, "Get program counter", "flow")
	op(0x59, "MSIZE", 0, 1, 0, "Get size of active memory", "memory")
	op(0x5A, "GAS", 0, 1, 0, "Get remaining gas", "env")
	op(0x5B, "JUMPDEST", 0, 0, 0, "Mark valid jump destination", "flow")
	op(0x5C, "TLOAD", 1, 1, 0, "Load from transient storage (Cancun)", "storage")
	op(0x5D, "TSTORE", 2, 0, 0, "Store to transient storage (Cancun)", "storage")
	op(0x5E, "MCOPY", 3, 0, 0, "Copy memory areas (Cancun)", "memory")

	op(0x5F, "PUSH0", 0, 1, 0, "Push zero onto stack (Shanghai)", "push")
	for i := 1; i <= 32; i++ {
		op(0x5F+i, fmt.Sprintf("PUSH%d", i), 0, 1, i, fmt.Sprintf("Push %d-byte value onto stack", i), "push")
	}
	for i := 1; i <= 16; i++ {
		op(0x7F+i, fmt.Sprintf("DUP%d", i), i, i+1, 0, fmt.Sprintf("Duplicate %dth stack item", i), "dup")
	}
	for i := 1; i <= 16; i++ {
		op(0x8F+i, fmt.Sprintf("SWAP%d", i), i+1, i+1, 0, fmt.Sprintf("Swap top with %dth stack item", i+1), "swap")
	}
	for i := 0; i < 5; i++ {
		op(0xA0+i, fmt.Sprintf("LOG%d", i), i+2, 0, 0, fmt.Sprintf("Append log record with %d topics", i), "log")
	}

	op(0xF0, "CREATE", 3, 1, 0, "Create a new contract", "system")
	op(0xF1, "CALL", 7, 1, 0, "Message-call into an account", "system")
	op(0xF2, "CALLCODE", 7, 1, 0, "Message-call with another account's code", "system")
	op(0xF3, "RETURN", 2, 0, 0, "Halt execution returning data", "flow")
	op(0xF4, "DELEGATECALL", 6, 1, 0, "Delegate call (preserves sender/value)", "system")
	op(0xF5, "CREATE2", 4, 1, 0, "Create contract with deterministic address", "system")
	op(0xFA, "STATICCALL", 6, 1, 0, "Static message-call (read-only)", "system")
	op(0xFD, "REVERT", 2, 0, 0, "Halt execution, revert state changes", "flow")
	op(0xFE, "INVALID", 0, 0, 0, "Designated invalid instruction", "flow")
	op(0xFF, "SELFDESTRUCT", 1, 0, 0, "Halt and register for deletion", "system")
}

// Lookup returns OpcodeInfo for a byte. Unknown opcodes get an UNKNOWN_0xXX
// stub mirroring the Python lookup() helper.
func Lookup(b int) OpcodeInfo {
	if info, ok := Opcodes[b]; ok {
		return info
	}
	return OpcodeInfo{
		Hex:         b,
		Mnemonic:    fmt.Sprintf("UNKNOWN_0x%02x", b),
		Description: fmt.Sprintf("Unknown opcode 0x%02x", b),
		Category:    "unknown",
	}
}

// BlockTerminators marks opcodes that end a basic block.
var BlockTerminators = map[string]struct{}{
	"STOP": {}, "JUMP": {}, "JUMPI": {}, "RETURN": {}, "REVERT": {},
	"INVALID": {}, "SELFDESTRUCT": {},
}

// BlockEntries marks opcodes that begin a basic block.
var BlockEntries = map[string]struct{}{"JUMPDEST": {}}
