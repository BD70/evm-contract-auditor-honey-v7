"""
Expression IR (Intermediate Representation) for semantic recovery.

Provides a structured AST for EVM expressions instead of raw strings.
Every node is pattern-matchable, simplifiable, and can be rendered
to human-readable form. This is the bridge between low-level stack
simulation and high-level semantic analysis.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, Any, Union
import copy


# ── Base ─────────────────────────────────────────────────────────

@dataclass
class Expr:
    """Base expression node."""
    source_offset: Optional[int] = None   # bytecode offset that produced this

    def children(self) -> list[Expr]:
        """Return child expressions for tree walking."""
        return []

    def substitute(self, old: Expr, new: Expr) -> Expr:
        """Replace occurrences of `old` with `new`."""
        if _expr_eq(self, old):
            return copy.deepcopy(new)
        return self

    def walk(self):
        """Yield all nodes in the expression tree (pre-order)."""
        yield self
        for child in self.children():
            yield from child.walk()


# ── Leaf nodes ───────────────────────────────────────────────────

@dataclass
class Const(Expr):
    """Literal constant value."""
    value: int = 0

    def __repr__(self):
        if self.value < 0:
            return str(self.value)
        if self.value <= 0xff:
            return f"0x{self.value:02x}"
        elif self.value <= 0xffff:
            return f"0x{self.value:04x}"
        elif self.value <= 0xffffffff:
            return f"0x{self.value:08x}"
        else:
            return f"0x{self.value:x}"


@dataclass
class MsgSender(Expr):
    """msg.sender"""
    def __repr__(self):
        return "msg.sender"


@dataclass
class MsgValue(Expr):
    """msg.value"""
    def __repr__(self):
        return "msg.value"


@dataclass
class MsgSig(Expr):
    """msg.sig — the 4-byte function selector from calldata[0:4]"""
    def __repr__(self):
        return "msg.sig"


@dataclass
class CalldataSize(Expr):
    """calldatasize"""
    def __repr__(self):
        return "calldatasize"


@dataclass
class GasLeft(Expr):
    """gasleft()"""
    def __repr__(self):
        return "gasleft()"


@dataclass
class ThisAddress(Expr):
    """address(this)"""
    def __repr__(self):
        return "address(this)"


@dataclass
class TxOrigin(Expr):
    """tx.origin"""
    def __repr__(self):
        return "tx.origin"


@dataclass
class BlockTimestamp(Expr):
    """block.timestamp"""
    def __repr__(self):
        return "block.timestamp"


@dataclass
class BlockNumber(Expr):
    """block.number"""
    def __repr__(self):
        return "block.number"


@dataclass
class Unknown(Expr):
    """Value whose origin cannot be determined."""
    label: str = "?"

    def __repr__(self):
        return self.label


@dataclass
class RawExpr(Expr):
    """
    Legacy raw string expression — bridge from old stack_sim StackValue.
    Will be progressively replaced by structured nodes.
    """
    text: str = ""

    def __repr__(self):
        return self.text


# ── Calldata Access ──────────────────────────────────────────────

@dataclass
class CalldataArg(Expr):
    """
    A decoded calldata argument.
    arg_index=0 means first argument (calldata offset 0x04),
    arg_index=1 means second argument (calldata offset 0x24), etc.
    """
    arg_index: int = 0
    arg_type: Optional[str] = None    # "address", "uint256", "bool", None if unknown
    raw_offset: Optional[int] = None  # original calldata byte offset (0x04, 0x24, ...)

    def __repr__(self):
        type_str = f": {self.arg_type}" if self.arg_type else ""
        return f"arg{self.arg_index}{type_str}"


@dataclass
class CalldataLoad(Expr):
    """Raw calldata load at an offset (before arg decoding)."""
    offset: Expr = None

    def __post_init__(self):
        if self.offset is None:
            self.offset = Const(0)

    def children(self) -> list[Expr]:
        return [self.offset]

    def __repr__(self):
        return f"calldata[{self.offset}]"


# ── Storage Access ───────────────────────────────────────────────

@dataclass
class StorageSlot(Expr):
    """
    Direct storage slot access: storage[slot].
    For packed slots, includes offset and width.
    """
    slot: int = 0
    bit_offset: int = 0       # for packed slots
    bit_width: int = 256      # 256 = full slot, 160 = address, 8 = bool
    inferred_name: Optional[str] = None
    inferred_type: Optional[str] = None

    def __repr__(self):
        if self.inferred_name:
            return self.inferred_name
        if self.bit_width == 256:
            return f"storage[{self.slot}]"
        return f"storage[{self.slot}][{self.bit_offset}:{self.bit_offset + self.bit_width}]"


@dataclass
class MappingAccess(Expr):
    """
    Access into a Solidity mapping: mapping[key] or mapping[key1][key2].
    """
    base_slot: int = 0
    keys: list = field(default_factory=list)  # list[Expr]
    inferred_name: Optional[str] = None
    value_type: Optional[str] = None
    confidence: float = 0.0

    def children(self) -> list[Expr]:
        return list(self.keys)

    def __repr__(self):
        name = self.inferred_name or f"mapping_{self.base_slot}"
        keys_str = "][".join(repr(k) for k in self.keys)
        return f"{name}[{keys_str}]"


@dataclass
class StorageLoad(Expr):
    """Raw storage load — before layout recovery resolves it."""
    slot_expr: Expr = None

    def __post_init__(self):
        if self.slot_expr is None:
            self.slot_expr = Const(0)

    def children(self) -> list[Expr]:
        return [self.slot_expr]

    def __repr__(self):
        return f"storage[{self.slot_expr}]"


@dataclass
class StorageStore(Expr):
    """Storage write operation."""
    slot_expr: Expr = None
    value: Expr = None

    def __post_init__(self):
        if self.slot_expr is None:
            self.slot_expr = Const(0)
        if self.value is None:
            self.value = Unknown()

    def children(self) -> list[Expr]:
        return [self.slot_expr, self.value]

    def __repr__(self):
        return f"storage[{self.slot_expr}] = {self.value}"


# ── Memory Access ────────────────────────────────────────────────

@dataclass
class MemoryLoad(Expr):
    """Memory read."""
    address: Expr = None

    def __post_init__(self):
        if self.address is None:
            self.address = Const(0)

    def children(self) -> list[Expr]:
        return [self.address]

    def __repr__(self):
        return f"memory[{self.address}]"


@dataclass
class FreeMemPtr(Expr):
    """The free memory pointer (memory[0x40]) — compiler boilerplate."""
    def __repr__(self):
        return "free_mem_ptr"


# ── Arithmetic / Logic ──────────────────────────────────────────

@dataclass
class BinOp(Expr):
    """Binary operation: a op b."""
    op: str = "+"             # "+", "-", "*", "/", "%", "**", "&", "|", "^", "<<", ">>"
    left: Expr = None
    right: Expr = None

    def __post_init__(self):
        if self.left is None:
            self.left = Const(0)
        if self.right is None:
            self.right = Const(0)

    def children(self) -> list[Expr]:
        return [self.left, self.right]

    def __repr__(self):
        return f"({self.left} {self.op} {self.right})"


@dataclass
class UnaryOp(Expr):
    """Unary operation: !a, ~a."""
    op: str = "!"             # "!", "~"
    operand: Expr = None

    def __post_init__(self):
        if self.operand is None:
            self.operand = Const(0)

    def children(self) -> list[Expr]:
        return [self.operand]

    def __repr__(self):
        return f"{self.op}{self.operand}"


@dataclass
class Compare(Expr):
    """Comparison: a < b, a > b, a == b."""
    op: str = "=="            # "==", "!=", "<", ">", "<=", ">="
    left: Expr = None
    right: Expr = None

    def __post_init__(self):
        if self.left is None:
            self.left = Const(0)
        if self.right is None:
            self.right = Const(0)

    def children(self) -> list[Expr]:
        return [self.left, self.right]

    def __repr__(self):
        return f"({self.left} {self.op} {self.right})"


@dataclass
class Keccak256(Expr):
    """keccak256 hash — may be a mapping key derivation."""
    mem_offset: Expr = None
    mem_length: Expr = None

    def __post_init__(self):
        if self.mem_offset is None:
            self.mem_offset = Const(0)
        if self.mem_length is None:
            self.mem_length = Const(0)

    def children(self) -> list[Expr]:
        return [self.mem_offset, self.mem_length]

    def __repr__(self):
        return f"keccak256(mem[{self.mem_offset}:{self.mem_offset}+{self.mem_length}])"


# ── High-level semantic nodes ────────────────────────────────────

@dataclass
class Require(Expr):
    """require(condition) — a guard check that reverts on failure."""
    condition: Expr = None
    message: Optional[str] = None

    def __post_init__(self):
        if self.condition is None:
            self.condition = Const(0)

    def children(self) -> list[Expr]:
        return [self.condition]

    def __repr__(self):
        msg = f', "{self.message}"' if self.message else ""
        return f"require({self.condition}{msg})"


@dataclass
class ExternalCall(Expr):
    """External call to another contract."""
    call_type: str = "call"       # "call", "staticcall", "delegatecall"
    target: Expr = None
    selector: Optional[str] = None  # 4-byte selector if known
    selector_name: Optional[str] = None  # resolved name
    args: list = field(default_factory=list)  # list[Expr]
    value: Optional[Expr] = None   # ETH value sent
    gas: Optional[Expr] = None

    def __post_init__(self):
        if self.target is None:
            self.target = Unknown()

    def children(self) -> list[Expr]:
        result = [self.target]
        result.extend(self.args)
        if self.value:
            result.append(self.value)
        return result

    def __repr__(self):
        name = self.selector_name or self.selector or "?"
        args_str = ", ".join(repr(a) for a in self.args)
        if self.call_type == "delegatecall":
            return f"delegatecall({self.target}.{name}({args_str}))"
        return f"{self.target}.{name}({args_str})"


@dataclass
class EventEmit(Expr):
    """Emit an event (LOG0-LOG4)."""
    topic_count: int = 0
    topics: list = field(default_factory=list)     # list[Expr] — topic hashes
    topic_names: list = field(default_factory=list) # resolved event names
    data_offset: Optional[Expr] = None
    data_length: Optional[Expr] = None

    def children(self) -> list[Expr]:
        result = list(self.topics)
        if self.data_offset:
            result.append(self.data_offset)
        return result

    def __repr__(self):
        if self.topic_names:
            return f"emit {self.topic_names[0]}"
        if self.topics:
            return f"emit Event({self.topics[0]})"
        return "emit Event()"


@dataclass
class ReturnData(Expr):
    """return(offset, length)"""
    offset: Expr = None
    length: Expr = None

    def children(self) -> list[Expr]:
        result = []
        if self.offset:
            result.append(self.offset)
        if self.length:
            result.append(self.length)
        return result

    def __repr__(self):
        return "return"


@dataclass
class Revert(Expr):
    """revert(offset, length) or revert with reason."""
    reason: Optional[str] = None

    def __repr__(self):
        if self.reason:
            return f'revert("{self.reason}")'
        return "revert()"


@dataclass
class Balance(Expr):
    """balance(address)"""
    address: Expr = None

    def __post_init__(self):
        if self.address is None:
            self.address = Unknown()

    def children(self) -> list[Expr]:
        return [self.address]

    def __repr__(self):
        return f"balance({self.address})"


@dataclass
class ExtCodeSize(Expr):
    """extcodesize(address)"""
    address: Expr = None

    def __post_init__(self):
        if self.address is None:
            self.address = Unknown()

    def children(self) -> list[Expr]:
        return [self.address]

    def __repr__(self):
        return f"extcodesize({self.address})"


# ── Helpers ──────────────────────────────────────────────────────

# Common constants for pattern matching
ADDRESS_MASK = (1 << 160) - 1    # 0xffffffffffffffffffffffffffffffffffffffff
UINT256_MAX = (1 << 256) - 1
SELECTOR_MASK = 0xFFFFFFFF
SELECTOR_DIVISOR = 1 << 224       # 0x100...000 (29 bytes)

# Well-known constants
WELL_KNOWN_CONSTANTS = {
    ADDRESS_MASK: "ADDRESS_MASK",
    UINT256_MAX: "MAX_UINT256",
    SELECTOR_DIVISOR: "SELECTOR_SHIFT",
    0x40: "FREE_MEM_PTR_SLOT",
    0x80: "INITIAL_FREE_MEM",
    0x20: "WORD_SIZE",
    0x04: "SELECTOR_SIZE",
    0xE0: "SELECTOR_SHIFT_BITS",
}


def _expr_eq(a: Expr, b: Expr) -> bool:
    """Structural equality check for expressions."""
    if type(a) != type(b):
        return False
    if isinstance(a, Const) and isinstance(b, Const):
        return a.value == b.value
    if isinstance(a, MsgSender) and isinstance(b, MsgSender):
        return True
    if isinstance(a, MsgValue) and isinstance(b, MsgValue):
        return True
    if isinstance(a, MsgSig) and isinstance(b, MsgSig):
        return True
    if isinstance(a, RawExpr) and isinstance(b, RawExpr):
        return a.text == b.text
    return repr(a) == repr(b)


def is_const(expr: Expr, value: int = None) -> bool:
    """Check if an expression is a constant, optionally with a specific value."""
    if not isinstance(expr, Const):
        return False
    if value is not None:
        return expr.value == value
    return True


def const_value(expr: Expr) -> Optional[int]:
    """Extract constant value from an expression, or None."""
    if isinstance(expr, Const):
        return expr.value
    return None


def from_legacy_repr(text: str, offset: int = None) -> Expr:
    """Convert a legacy StackValue repr string to an Expr node."""
    # Try to parse well-known patterns
    if text == "msg.sender":
        return MsgSender(source_offset=offset)
    if text == "msg.value":
        return MsgValue(source_offset=offset)
    if text == "calldatasize":
        return CalldataSize(source_offset=offset)
    if text == "tx.origin":
        return TxOrigin(source_offset=offset)
    if text == "address(this)":
        return ThisAddress(source_offset=offset)
    if text == "block.timestamp":
        return BlockTimestamp(source_offset=offset)
    if text == "block.number":
        return BlockNumber(source_offset=offset)
    if text == "gasleft()":
        return GasLeft(source_offset=offset)
    if text == "?":
        return Unknown(source_offset=offset)

    # Try to parse hex constant
    if text.startswith("0x"):
        try:
            return Const(value=int(text, 16), source_offset=offset)
        except ValueError:
            pass

    # Try to parse decimal constant
    try:
        return Const(value=int(text), source_offset=offset)
    except ValueError:
        pass

    # Fallback to raw
    return RawExpr(text=text, source_offset=offset)
