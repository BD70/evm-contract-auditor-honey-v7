"""
Lightweight EVM stack simulator with constant propagation.

Simulates the EVM stack through each basic block, tracking concrete values
(from PUSH) and symbolic expressions (from arithmetic). Does NOT fork on
branches — single forward pass with constant folding.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, Any
from .disassembler import Instruction, DisassemblyResult
from .blocks import BasicBlock, BlockAnalysis


# ── Abstract Values ──────────────────────────────────────────────

@dataclass
class StackValue:
    """A value on the abstract EVM stack."""
    kind: str           # "const", "expr", "unknown"
    value: Any = None   # int for const, str for expr description
    source_offset: Optional[int] = None  # instruction that produced this

    def __repr__(self):
        if self.kind == "const":
            if isinstance(self.value, int) and self.value >= 0:
                if self.value <= 0xff:
                    return f"0x{self.value:02x}"
                elif self.value <= 0xffff:
                    return f"0x{self.value:04x}"
                elif self.value <= 0xffffffff:
                    return f"0x{self.value:08x}"
                else:
                    return f"0x{self.value:x}"
            return str(self.value)
        elif self.kind == "expr":
            return str(self.value)
        return "?"

    @staticmethod
    def const(value: int, offset: int = None) -> StackValue:
        return StackValue("const", value, offset)

    @staticmethod
    def expr(description: str, offset: int = None) -> StackValue:
        return StackValue("expr", description, offset)

    @staticmethod
    def unknown(offset: int = None) -> StackValue:
        return StackValue("unknown", None, offset)

    @property
    def is_const(self) -> bool:
        return self.kind == "const"

    @property
    def const_value(self) -> Optional[int]:
        return self.value if self.kind == "const" else None


def _binop(a: StackValue, b: StackValue, op: str, py_op) -> StackValue:
    """Apply a binary operation to two stack values."""
    if a.is_const and b.is_const:
        try:
            result = py_op(a.value, b.value)
            if isinstance(result, int):
                result = result & ((1 << 256) - 1)  # 256-bit wrap
            return StackValue.const(int(result))
        except (ZeroDivisionError, ValueError, OverflowError):
            pass
    return StackValue.expr(f"({a} {op} {b})")


def _compare(a: StackValue, b: StackValue, op: str) -> StackValue:
    """Create a comparison expression."""
    if a.is_const and b.is_const:
        ops = {"<": lambda x, y: x < y, ">": lambda x, y: x > y,
               "==": lambda x, y: x == y}
        if op in ops:
            return StackValue.const(1 if ops[op](a.value, b.value) else 0)
    return StackValue.expr(f"({a} {op} {b})")


def _shl(shift: StackValue, value: StackValue) -> StackValue:
    """Apply EVM SHL semantics without creating pathological Python bigints."""
    if shift.is_const and value.is_const:
        if shift.value >= 256:
            return StackValue.const(0)
        return StackValue.const((value.value << shift.value) & ((1 << 256) - 1))
    return StackValue.expr(f"({value} << {shift})")


def _shr(shift: StackValue, value: StackValue) -> StackValue:
    """Apply EVM SHR semantics without creating pathological Python bigints."""
    if shift.is_const and value.is_const:
        if shift.value >= 256:
            return StackValue.const(0)
        return StackValue.const(value.value >> shift.value)
    return StackValue.expr(f"({value} >> {shift})")


# ── Memory / Storage Operations ──────────────────────────────────

@dataclass
class MemoryOp:
    offset_in_code: int       # bytecode offset of the instruction
    address: StackValue       # memory address
    value: Optional[StackValue]  # value written (None for reads)
    op_type: str              # "write" or "read"

    def __repr__(self):
        if self.op_type == "write":
            return f"memory[{self.address}] = {self.value}"
        return f"memory[{self.address}]"


@dataclass
class StorageOp:
    offset_in_code: int
    slot: StackValue
    value: Optional[StackValue]
    op_type: str  # "read" or "write"

    def __repr__(self):
        if self.op_type == "write":
            return f"storage[{self.slot}] = {self.value}"
        return f"storage[{self.slot}]"


@dataclass
class OperationRecord:
    """Human-readable record of a significant operation in a block."""
    offset: int
    description: str
    category: str  # "assign", "compare", "memory", "storage", "call", "flow"


# ── Block Trace ──────────────────────────────────────────────────

@dataclass
class BlockTrace:
    block_id: int
    entry_stack: list[StackValue]
    exit_stack: list[StackValue]
    branch_condition: Optional[StackValue] = None
    branch_true_target: Optional[int] = None
    branch_false_target: Optional[int] = None
    memory_ops: list[MemoryOp] = field(default_factory=list)
    storage_ops: list[StorageOp] = field(default_factory=list)
    operations: list[OperationRecord] = field(default_factory=list)
    stack_annotations: dict[int, str] = field(default_factory=dict)  # offset → annotation


@dataclass
class SimulationResult:
    traces: dict[int, BlockTrace]  # block_id → trace
    errors: list[str] = field(default_factory=list)
    constants: list[dict] = field(default_factory=list)  # all pushed constants with context


# ── Simulator ────────────────────────────────────────────────────

def simulate(block_analysis: BlockAnalysis, disasm: DisassemblyResult) -> SimulationResult:
    """
    Simulate the EVM stack through all basic blocks.
    Does a forward pass following the block order, propagating
    stack states across edges.
    """
    traces: dict[int, BlockTrace] = {}
    errors: list[str] = []
    all_constants: list[dict] = []

    # Build block_id → block map
    block_map: dict[int, BasicBlock] = {b.id: b for b in block_analysis.blocks}

    # Entry stack for block 0 is empty
    entry_stacks: dict[int, list[StackValue]] = {0: []}

    # Process blocks in order (topological-ish — blocks are already in offset order)
    for block in block_analysis.blocks:
        entry = entry_stacks.get(block.id, [])
        trace = _simulate_block(block, list(entry), all_constants)
        traces[block.id] = trace

        # Propagate exit stack to successors
        for succ_id in block.exits_to:
            if succ_id not in entry_stacks:
                entry_stacks[succ_id] = list(trace.exit_stack)
            # If already has entry (merge point), we keep the first one
            # (simplified — full analysis would merge/widen)

    return SimulationResult(traces=traces, errors=errors, constants=all_constants)


def _simulate_block(
    block: BasicBlock,
    stack: list[StackValue],
    all_constants: list[dict],
) -> BlockTrace:
    """Simulate a single basic block."""

    entry_stack = list(stack)
    memory_ops: list[MemoryOp] = []
    storage_ops: list[StorageOp] = []
    operations: list[OperationRecord] = []
    stack_annotations: dict[int, str] = {}
    branch_condition = None
    branch_true = None
    branch_false = None

    instructions = block.instructions

    for idx, inst in enumerate(instructions):
        off = inst.offset
        op = inst.opcode

        try:
            # ── PUSH ──────────────────────────────────────
            if op.startswith("PUSH"):
                val = inst.operand_value if inst.operand_value is not None else 0
                sv = StackValue.const(val, off)
                stack.append(sv)

                # Record constant with context
                context = _infer_constant_context(val, inst, instructions, idx)
                all_constants.append({
                    "value": val,
                    "hex": f"0x{val:x}" if val >= 0 else str(val),
                    "offset": f"0x{off:04x}",
                    "context": context,
                })
                if context:
                    stack_annotations[off] = context

            # ── DUP ───────────────────────────────────────
            elif op.startswith("DUP"):
                n = int(op[3:])
                if len(stack) >= n:
                    stack.append(StackValue(stack[-n].kind, stack[-n].value, off))
                else:
                    stack.append(StackValue.unknown(off))

            # ── SWAP ──────────────────────────────────────
            elif op.startswith("SWAP"):
                n = int(op[4:])
                if len(stack) >= n + 1:
                    stack[-1], stack[-(n + 1)] = stack[-(n + 1)], stack[-1]

            # ── POP ───────────────────────────────────────
            elif op == "POP":
                if stack:
                    stack.pop()

            # ── Arithmetic ────────────────────────────────
            elif op == "ADD" and len(stack) >= 2:
                b, a = stack.pop(), stack.pop()
                result = _binop(a, b, "+", lambda x, y: x + y)
                stack.append(result)
                operations.append(OperationRecord(off, f"{result}", "assign"))
                stack_annotations[off] = f"{a} + {b}"

            elif op == "SUB" and len(stack) >= 2:
                b, a = stack.pop(), stack.pop()
                result = _binop(a, b, "-", lambda x, y: x - y)
                stack.append(result)
                stack_annotations[off] = f"{a} - {b}"

            elif op == "MUL" and len(stack) >= 2:
                b, a = stack.pop(), stack.pop()
                result = _binop(a, b, "*", lambda x, y: x * y)
                stack.append(result)
                operations.append(OperationRecord(off, f"{a} * {b}", "assign"))
                stack_annotations[off] = f"{a} * {b}"

            elif op == "DIV" and len(stack) >= 2:
                b, a = stack.pop(), stack.pop()
                result = _binop(a, b, "/", lambda x, y: x // y if y != 0 else 0)
                stack.append(result)
                stack_annotations[off] = f"{a} / {b}"

            elif op == "MOD" and len(stack) >= 2:
                b, a = stack.pop(), stack.pop()
                result = _binop(a, b, "%", lambda x, y: x % y if y != 0 else 0)
                stack.append(result)

            elif op == "EXP" and len(stack) >= 2:
                b, a = stack.pop(), stack.pop()
                result = _binop(a, b, "**", lambda x, y: pow(x, y, (1 << 256)))
                stack.append(result)
                stack_annotations[off] = f"{a} ** {b}"

            elif op == "ADDMOD" and len(stack) >= 3:
                n, b, a = stack.pop(), stack.pop(), stack.pop()
                stack.append(StackValue.expr(f"({a} + {b}) % {n}", off))

            elif op == "MULMOD" and len(stack) >= 3:
                n, b, a = stack.pop(), stack.pop(), stack.pop()
                stack.append(StackValue.expr(f"({a} * {b}) % {n}", off))

            elif op == "SIGNEXTEND" and len(stack) >= 2:
                b, a = stack.pop(), stack.pop()
                stack.append(StackValue.expr(f"signext({a}, {b})", off))

            # ── Comparison ────────────────────────────────
            elif op == "LT" and len(stack) >= 2:
                # EVM: a=top, b=second → push(a < b)
                a = stack.pop()
                b = stack.pop()
                result = _compare(a, b, "<")
                stack.append(result)
                stack_annotations[off] = f"{a} < {b}"

            elif op == "GT" and len(stack) >= 2:
                a = stack.pop()
                b = stack.pop()
                result = _compare(a, b, ">")
                stack.append(result)
                stack_annotations[off] = f"{a} > {b}"

            elif op == "SLT" and len(stack) >= 2:
                a = stack.pop()
                b = stack.pop()
                result = _compare(a, b, "<s")
                stack.append(result)

            elif op == "SGT" and len(stack) >= 2:
                a = stack.pop()
                b = stack.pop()
                result = _compare(a, b, ">s")
                stack.append(result)

            elif op == "EQ" and len(stack) >= 2:
                a = stack.pop()
                b = stack.pop()
                result = _compare(a, b, "==")
                stack.append(result)
                stack_annotations[off] = f"{a} == {b}"

            elif op == "ISZERO" and len(stack) >= 1:
                a = stack.pop()
                if a.is_const:
                    stack.append(StackValue.const(1 if a.value == 0 else 0, off))
                else:
                    stack.append(StackValue.expr(f"!{a}", off))
                stack_annotations[off] = f"!{a}"

            # ── Bitwise ───────────────────────────────────
            elif op == "AND" and len(stack) >= 2:
                b, a = stack.pop(), stack.pop()
                result = _binop(a, b, "&", lambda x, y: x & y)
                stack.append(result)

            elif op == "OR" and len(stack) >= 2:
                b, a = stack.pop(), stack.pop()
                result = _binop(a, b, "|", lambda x, y: x | y)
                stack.append(result)

            elif op == "XOR" and len(stack) >= 2:
                b, a = stack.pop(), stack.pop()
                result = _binop(a, b, "^", lambda x, y: x ^ y)
                stack.append(result)

            elif op == "NOT" and len(stack) >= 1:
                a = stack.pop()
                if a.is_const:
                    stack.append(StackValue.const(~a.value & ((1 << 256) - 1), off))
                else:
                    stack.append(StackValue.expr(f"~{a}", off))

            elif op == "BYTE" and len(stack) >= 2:
                b, a = stack.pop(), stack.pop()
                stack.append(StackValue.expr(f"byte({a}, {b})", off))

            elif op == "SHL" and len(stack) >= 2:
                b, a = stack.pop(), stack.pop()
                result = _shl(a, b)
                stack.append(result)

            elif op == "SHR" and len(stack) >= 2:
                b, a = stack.pop(), stack.pop()
                result = _shr(a, b)
                stack.append(result)
                if a.is_const and a.value == 0xe0:
                    stack_annotations[off] = "extract function selector (>> 224)"

            elif op == "SAR" and len(stack) >= 2:
                b, a = stack.pop(), stack.pop()
                stack.append(StackValue.expr(f"sar({b}, {a})", off))

            # ── Keccak ────────────────────────────────────
            elif op == "KECCAK256" and len(stack) >= 2:
                length, offset_val = stack.pop(), stack.pop()
                stack.append(StackValue.expr(f"keccak256(mem[{offset_val}:{offset_val}+{length}])", off))

            # ── Environment ───────────────────────────────
            elif op == "ADDRESS":
                stack.append(StackValue.expr("address(this)", off))
            elif op == "BALANCE" and len(stack) >= 1:
                addr = stack.pop()
                stack.append(StackValue.expr(f"balance({addr})", off))
            elif op == "ORIGIN":
                stack.append(StackValue.expr("tx.origin", off))
            elif op == "CALLER":
                stack.append(StackValue.expr("msg.sender", off))
            elif op == "CALLVALUE":
                stack.append(StackValue.expr("msg.value", off))
            elif op == "CALLDATALOAD" and len(stack) >= 1:
                offset_val = stack.pop()
                stack.append(StackValue.expr(f"calldata[{offset_val}]", off))
                stack_annotations[off] = f"load calldata[{offset_val}]"
            elif op == "CALLDATASIZE":
                stack.append(StackValue.expr("calldatasize", off))
            elif op == "CALLDATACOPY" and len(stack) >= 3:
                stack.pop(); stack.pop(); stack.pop()
            elif op == "CODESIZE":
                stack.append(StackValue.expr("codesize", off))
            elif op == "CODECOPY" and len(stack) >= 3:
                stack.pop(); stack.pop(); stack.pop()
            elif op == "GASPRICE":
                stack.append(StackValue.expr("gasprice", off))
            elif op == "EXTCODESIZE" and len(stack) >= 1:
                addr = stack.pop()
                stack.append(StackValue.expr(f"extcodesize({addr})", off))
            elif op == "EXTCODECOPY" and len(stack) >= 4:
                for _ in range(4): stack.pop()
            elif op == "RETURNDATASIZE":
                stack.append(StackValue.expr("returndatasize", off))
            elif op == "RETURNDATACOPY" and len(stack) >= 3:
                stack.pop(); stack.pop(); stack.pop()
            elif op == "EXTCODEHASH" and len(stack) >= 1:
                addr = stack.pop()
                stack.append(StackValue.expr(f"extcodehash({addr})", off))

            # ── Block Info ────────────────────────────────
            elif op == "BLOCKHASH" and len(stack) >= 1:
                n = stack.pop()
                stack.append(StackValue.expr(f"blockhash({n})", off))
            elif op == "COINBASE":
                stack.append(StackValue.expr("block.coinbase", off))
            elif op == "TIMESTAMP":
                stack.append(StackValue.expr("block.timestamp", off))
            elif op == "NUMBER":
                stack.append(StackValue.expr("block.number", off))
            elif op == "PREVRANDAO":
                stack.append(StackValue.expr("block.prevrandao", off))
            elif op == "GASLIMIT":
                stack.append(StackValue.expr("block.gaslimit", off))
            elif op == "CHAINID":
                stack.append(StackValue.expr("chainid", off))
            elif op == "SELFBALANCE":
                stack.append(StackValue.expr("selfbalance", off))
            elif op == "BASEFEE":
                stack.append(StackValue.expr("block.basefee", off))
            elif op == "GAS":
                stack.append(StackValue.expr("gasleft()", off))

            # ── Memory ───────────────────────────────────
            elif op == "MLOAD" and len(stack) >= 1:
                addr = stack.pop()
                stack.append(StackValue.expr(f"memory[{addr}]", off))
                memory_ops.append(MemoryOp(off, addr, None, "read"))

            elif op == "MSTORE" and len(stack) >= 2:
                val, addr = stack.pop(), stack.pop()
                memory_ops.append(MemoryOp(off, addr, val, "write"))
                operations.append(OperationRecord(off, f"memory[{addr}] = {val}", "memory"))
                stack_annotations[off] = f"memory[{addr}] = {val}"

            elif op == "MSTORE8" and len(stack) >= 2:
                val, addr = stack.pop(), stack.pop()
                memory_ops.append(MemoryOp(off, addr, val, "write"))

            elif op == "MSIZE":
                stack.append(StackValue.expr("msize", off))

            # ── Storage ──────────────────────────────────
            elif op == "SLOAD" and len(stack) >= 1:
                slot = stack.pop()
                result = StackValue.expr(f"storage[{slot}]", off)
                stack.append(result)
                storage_ops.append(StorageOp(off, slot, None, "read"))
                stack_annotations[off] = f"read storage[{slot}]"

            elif op == "SSTORE" and len(stack) >= 2:
                val, slot = stack.pop(), stack.pop()
                storage_ops.append(StorageOp(off, slot, val, "write"))
                operations.append(OperationRecord(off, f"storage[{slot}] = {val}", "storage"))
                stack_annotations[off] = f"storage[{slot}] = {val}"

            elif op == "TLOAD" and len(stack) >= 1:
                slot = stack.pop()
                stack.append(StackValue.expr(f"transient[{slot}]", off))

            elif op == "TSTORE" and len(stack) >= 2:
                val, slot = stack.pop(), stack.pop()
                operations.append(OperationRecord(off, f"transient[{slot}] = {val}", "storage"))

            # ── Flow Control ────────────────────────────
            elif op == "JUMP":
                if stack:
                    dest = stack.pop()
                    branch_true = dest.const_value

            elif op == "JUMPI":
                if len(stack) >= 2:
                    # EVM spec: JUMPI pops dest (top), then cond (second)
                    # Stack before: [..., cond, dest]
                    dest = stack.pop()     # jump destination (top of stack)
                    cond = stack.pop()     # condition (second from top)
                    branch_condition = cond
                    branch_true = dest.const_value
                    # false = next instruction (fallthrough)
                    if idx + 1 < len(instructions):
                        branch_false = instructions[idx + 1].offset
                    cond_str = str(cond)
                    dest_str = f"0x{dest.const_value:04x}" if dest.is_const else str(dest)
                    stack_annotations[off] = f"if ({cond_str}) goto {dest_str}"

            elif op == "JUMPDEST":
                pass  # no-op

            elif op == "PC":
                stack.append(StackValue.const(off, off))

            # ── System ────────────────────────────────────
            elif op == "RETURN" and len(stack) >= 2:
                length, offset_val = stack.pop(), stack.pop()
                operations.append(OperationRecord(
                    off, f"return memory[{offset_val}..{offset_val}+{length}]", "flow"
                ))
                stack_annotations[off] = f"return memory[{offset_val}..+{length}]"

            elif op == "REVERT" and len(stack) >= 2:
                length, offset_val = stack.pop(), stack.pop()
                operations.append(OperationRecord(
                    off, f"revert memory[{offset_val}..{offset_val}+{length}]", "flow"
                ))

            elif op == "STOP":
                operations.append(OperationRecord(off, "stop", "flow"))

            elif op == "SELFDESTRUCT" and len(stack) >= 1:
                addr = stack.pop()
                operations.append(OperationRecord(off, f"selfdestruct({addr})", "flow"))

            elif op == "CALL" and len(stack) >= 7:
                args = [stack.pop() for _ in range(7)]
                stack.append(StackValue.expr("call_success", off))
                operations.append(OperationRecord(off, f"call(gas={args[0]}, to={args[1]}, value={args[2]})", "call"))

            elif op == "STATICCALL" and len(stack) >= 6:
                args = [stack.pop() for _ in range(6)]
                stack.append(StackValue.expr("staticcall_success", off))
                operations.append(OperationRecord(off, f"staticcall(gas={args[0]}, to={args[1]})", "call"))

            elif op == "DELEGATECALL" and len(stack) >= 6:
                args = [stack.pop() for _ in range(6)]
                stack.append(StackValue.expr("delegatecall_success", off))
                operations.append(OperationRecord(off, f"delegatecall(to={args[1]})", "call"))

            elif op == "CREATE" and len(stack) >= 3:
                args = [stack.pop() for _ in range(3)]
                stack.append(StackValue.expr("new_address", off))
                operations.append(OperationRecord(off, f"create(value={args[0]}, offset={args[1]}, size={args[2]})", "call"))

            elif op == "CREATE2" and len(stack) >= 4:
                args = [stack.pop() for _ in range(4)]
                stack.append(StackValue.expr("new_address_create2", off))
                operations.append(OperationRecord(off, f"create2(value={args[0]}, offset={args[1]}, size={args[2]}, salt={args[3]})", "call"))

            # ── LOG ────────────────────────────────────────
            elif op.startswith("LOG"):
                n = int(op[3:])
                num_pops = n + 2  # offset, length, + n topics
                for _ in range(min(num_pops, len(stack))):
                    stack.pop()

            # ── Catch unknown (don't crash) ───────────────
            elif op == "INVALID" or op.startswith("UNKNOWN"):
                pass  # unknown opcode, leave stack as-is

            elif op == "MCOPY" and len(stack) >= 3:
                stack.pop(); stack.pop(); stack.pop()

            else:
                # Unknown instruction — check if it pops/pushes via opcode info
                info = inst.info
                pops = min(info.stack_in, len(stack))
                for _ in range(pops):
                    stack.pop()
                for _ in range(info.stack_out):
                    stack.append(StackValue.unknown(off))

        except (IndexError, ValueError):
            # Stack underflow or other error — continue
            pass

    return BlockTrace(
        block_id=block.id,
        entry_stack=entry_stack,
        exit_stack=list(stack),
        branch_condition=branch_condition,
        branch_true_target=branch_true,
        branch_false_target=branch_false,
        memory_ops=memory_ops,
        storage_ops=storage_ops,
        operations=operations,
        stack_annotations=stack_annotations,
    )


def _infer_constant_context(value: int, inst: Instruction, instructions: list[Instruction], idx: int) -> str:
    """Infer what a pushed constant is used for by looking at the next instruction(s)."""

    # Look ahead at next 1-3 instructions
    next_ops = []
    for i in range(1, min(4, len(instructions) - idx)):
        next_ops.append(instructions[idx + i].opcode)

    if not next_ops:
        return ""

    next_op = next_ops[0]

    # Function selector (4 bytes pushed before EQ)
    if inst.opcode == "PUSH4" and "EQ" in next_ops[:2]:
        return f"function selector: 0x{value:08x}"

    # Jump target
    if next_op in ("JUMP", "JUMPI"):
        return f"jump target → 0x{value:04x}"

    # Memory pointer
    if value == 0x40 and next_op in ("MLOAD", "MSTORE"):
        return "free memory pointer (0x40)"

    if value == 0x80:
        return "initial free memory value"

    # Return/revert size
    if next_op == "RETURN" or (len(next_ops) >= 2 and next_ops[1] == "RETURN"):
        if value == 0x20:
            return "return size: 32 bytes"
        elif value == 0x40:
            return "return offset or size"
        return f"return parameter: {value}"

    # Comparison bound (pushed before LT/GT/EQ in loop context)
    if "LT" in next_ops[:2] or "GT" in next_ops[:2]:
        return f"comparison bound: {value}"

    # Multiplication/division factor
    if next_op == "MUL":
        return f"multiplication factor: {value}"
    if next_op == "DIV":
        return f"division factor: {value}"

    # Shift amount
    if next_op == "SHR" and value == 0xe0:
        return "shift 224 bits (extract 4-byte selector)"
    if next_op in ("SHL", "SHR", "SAR"):
        return f"shift amount: {value}"

    # Address mask
    if value == 0xffffffffffffffffffffffffffffffffffffffff:
        return "address mask (20 bytes)"

    # Small values in arithmetic context
    if next_op == "ADD" and value <= 32:
        return f"increment by {value}"

    return ""
