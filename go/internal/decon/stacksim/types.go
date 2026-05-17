package stacksim

// MemoryOp records an MLOAD / MSTORE / MSTORE8.
type MemoryOp struct {
	OffsetInCode int
	Address      Value
	Value        *Value // nil for reads
	OpType       string // "read" | "write"
}

// StorageOp records an SLOAD / SSTORE.
type StorageOp struct {
	OffsetInCode int
	Slot         Value
	Value        *Value // nil for reads
	OpType       string
}

// OperationRecord is a human-readable trace entry.
type OperationRecord struct {
	Offset      int
	Description string
	Category    string // "assign" | "compare" | "memory" | "storage" | "call" | "flow"
}

// BlockTrace mirrors evm_decon.stack_sim.BlockTrace.
type BlockTrace struct {
	BlockID            int
	EntryStack         []Value
	ExitStack          []Value
	BranchCondition    *Value
	BranchTrueTarget   int
	HasBranchTrue      bool
	BranchFalseTarget  int
	HasBranchFalse     bool
	MemoryOps          []MemoryOp
	StorageOps         []StorageOp
	Operations         []OperationRecord
	StackAnnotations   map[int]string
}

// ConstantRecord captures every PUSH constant the simulator observed.
type ConstantRecord struct {
	Value   *Value
	HexStr  string
	Offset  string
	Context string
}

// Result mirrors evm_decon.stack_sim.SimulationResult.
type Result struct {
	Traces    map[int]*BlockTrace
	Errors    []string
	Constants []ConstantRecord
}
