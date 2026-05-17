"""
Expression simplifier / normalizer.

Applies rewrite passes to transform raw stack expressions into
canonical, human-readable forms. Eliminates EVM implementation noise
like address masks, double negations, selector extraction boilerplate,
and zero multiplications.

Each pass is idempotent — running them multiple times converges.
"""

from __future__ import annotations
from typing import Optional
import re

from .expr_ir import (
    Expr, Const, BinOp, UnaryOp, Compare, RawExpr, Unknown,
    MsgSender, MsgValue, MsgSig, CalldataArg, CalldataLoad, CalldataSize,
    StorageSlot, StorageLoad, MappingAccess, MemoryLoad, FreeMemPtr,
    Keccak256, Require, ExternalCall, EventEmit, Balance, ExtCodeSize,
    ADDRESS_MASK, UINT256_MAX, SELECTOR_DIVISOR, SELECTOR_MASK,
    is_const, const_value,
)


# ── Main entry point ─────────────────────────────────────────────

def simplify(expr: Expr, max_passes: int = 5) -> Expr:
    """
    Apply all simplification passes to an expression.
    Repeats until fixed point or max_passes.
    """
    for _ in range(max_passes):
        before = repr(expr)
        expr = _apply_all_passes(expr)
        after = repr(expr)
        if before == after:
            break
    return expr


def simplify_text(text: str) -> str:
    """
    Simplify a raw text expression (from legacy StackValue repr).
    Returns cleaned-up text. This is the lightweight path for
    quickly cleaning up pseudocode strings without full IR parsing.
    """
    result = text

    # Guard: for extremely long expressions, skip regex-heavy passes
    if len(result) > 2000:
        # Just do the safe string replacements
        result = result.replace("!!!", "!")
        result = result.replace("!!", "")
        result = result.replace("memory[0x40]", "free_mem_ptr")
        result = result.replace("memory[0x00]", "scratch")
        return result

    # ── Double/triple negation ───────────────────────────────
    # !!!!!x → !x, !!!!x → x, !!!x → !x, !!x → x
    while "!!!!" in result:
        result = result.replace("!!!!", "")
    result = result.replace("!!!", "!")
    result = result.replace("!!", "")

    # ── Selector extraction boilerplate ──────────────────────
    # (0x100000000000000000000000000000000000000000000000000000000 / calldata[0x00]) & 0xffffffff
    # → msg.sig
    selector_pattern = (
        r'\(\s*0x0*1' + r'0{56}' +
        r'\s*/\s*calldata\[0x00\]\s*\)\s*&\s*0x0*ffffffff'
    )
    result = re.sub(selector_pattern, 'msg.sig', result)

    # Simpler variant: just the huge hex / calldata[0x00]
    result = re.sub(
        r'0x0*1' + r'0{50,58}' + r'\s*/\s*calldata\[0x00\]',
        'msg.sig_raw',
        result
    )

    # ── Address mask ─────────────────────────────────────────
    # (X & 0xffffffffffffffffffffffffffffffffffffffff) → X (when X is already address-typed)
    addr_mask = "0xffffffffffffffffffffffffffffffffffffffff"
    # Remove redundant nested address masks (max 5 iterations to prevent hangs)
    for _guard in range(5):
        if f"& {addr_mask})" not in result or result.count(addr_mask) <= 1:
            break
        old = result
        # Remove innermost redundant mask
        result = re.sub(
            r'\(([^()]+)\s*&\s*0xffffffffffffffffffffffffffffffffffffffff\)\s*&\s*0xffffffffffffffffffffffffffffffffffffffff',
            r'(\1 & 0xffffffffffffffffffffffffffffffffffffffff)',
            result,
            count=1,  # only one replacement per iteration
        )
        if result == old:
            break  # no change, stop

    # (msg.sender & 0xfff...fff) → msg.sender
    result = re.sub(
        r'\(msg\.sender\s*&\s*0xffffffffffffffffffffffffffffffffffffffff\)',
        'msg.sender',
        result
    )

    # (calldata[0x04] & 0xfff...fff) → arg0
    result = re.sub(
        r'\(calldata\[0x04\]\s*&\s*0xffffffffffffffffffffffffffffffffffffffff\)',
        'arg0',
        result
    )
    result = re.sub(
        r'\(calldata\[0x24\]\s*&\s*0xffffffffffffffffffffffffffffffffffffffff\)',
        'arg1',
        result
    )
    result = re.sub(
        r'\(calldata\[0x44\]\s*&\s*0xffffffffffffffffffffffffffffffffffffffff\)',
        'arg2',
        result
    )

    # Generic calldata address mask
    result = re.sub(
        r'\(calldata\[(0x[0-9a-f]+)\]\s*&\s*0xffffffffffffffffffffffffffffffffffffffff\)',
        r'calldata[\1]:address',
        result
    )

    # ── Zero multiplication ──────────────────────────────────
    result = re.sub(r'0x00\s*\*\s*[^\s)]+', '0', result)
    result = re.sub(r'[^\s(]+\s*\*\s*0x00', '0', result)

    # ── Paused/deprecated bool extraction ────────────────────
    # (0x00 / storage[X]) & 0xff → storage[X].bool (packed bool at high byte)
    result = re.sub(
        r'\(0x00\s*/\s*storage\[([^\]]+)\]\)\s*&\s*0xff',
        r'storage[\1].packed_bool',
        result
    )

    # ── Owner extraction ─────────────────────────────────────
    # (0x00 / storage[0x00]) & 0xfff...fff → owner
    result = re.sub(
        r'\(\s*0x00\s*/\s*storage\[0x00\]\s*\)\s*&\s*0xffffffffffffffffffffffffffffffffffffffff',
        'owner',
        result
    )
    # nested: ((0x00 / storage[0x00]) & mask) & mask → owner
    result = re.sub(
        r'\(\s*owner\s*\)\s*&\s*0xffffffffffffffffffffffffffffffffffffffff',
        'owner',
        result
    )
    result = re.sub(
        r'\(\s*owner\s*&\s*0xffffffffffffffffffffffffffffffffffffffff\)',
        'owner',
        result
    )

    # ── Comparison normalization ─────────────────────────────
    # !(X < Y) → X >= Y
    result = re.sub(r'!\(([^()]+)\s*<\s*([^()]+)\)', r'(\1 >= \2)', result)
    # !(X > Y) → X <= Y
    result = re.sub(r'!\(([^()]+)\s*>\s*([^()]+)\)', r'(\1 <= \2)', result)
    # !(X == Y) → X != Y
    result = re.sub(r'!\(([^()]+)\s*==\s*([^()]+)\)', r'(\1 != \2)', result)

    # ── msg.value check ──────────────────────────────────────
    # !msg.value → msg.value == 0 (non-payable check)
    result = result.replace("!msg.value", "(msg.value == 0)")

    # ── Memory pointer boilerplate ───────────────────────────
    result = result.replace("memory[0x40]", "free_mem_ptr")
    result = result.replace("memory[0x60]", "free_mem_ptr_init")
    result = result.replace("memory[0x00]", "scratch")

    # ── Calldata selector check ──────────────────────────────
    # (0xNNNNNNNN == msg.sig) → match selector 0xNNNNNNNN
    # This is now handled at a higher level (dispatcher extraction)

    # ── Result pointer boilerplate ───────────────────────────
    result = result.replace("result_ptr", "return_data")

    # ── Clean up whitespace ──────────────────────────────────
    result = re.sub(r'\s+', ' ', result).strip()

    return result


# ── Structured IR passes ─────────────────────────────────────────

def _apply_all_passes(expr: Expr) -> Expr:
    """Apply all structured simplification passes."""
    expr = _pass_constant_fold(expr)
    expr = _pass_double_negation(expr)
    expr = _pass_zero_multiplication(expr)
    expr = _pass_address_mask(expr)
    expr = _pass_selector_extraction(expr)
    expr = _pass_calldata_args(expr)
    expr = _pass_comparison_normalize(expr)
    expr = _pass_memory_boilerplate(expr)
    return expr


def _pass_constant_fold(expr: Expr) -> Expr:
    """Fold constant arithmetic."""
    if isinstance(expr, BinOp):
        left = _pass_constant_fold(expr.left)
        right = _pass_constant_fold(expr.right)

        lv = const_value(left)
        rv = const_value(right)

        if lv is not None and rv is not None:
            try:
                if expr.op == "+":
                    return Const(value=(lv + rv) & UINT256_MAX)
                elif expr.op == "-":
                    return Const(value=(lv - rv) & UINT256_MAX)
                elif expr.op == "*":
                    return Const(value=(lv * rv) & UINT256_MAX)
                elif expr.op == "/":
                    if rv != 0:
                        return Const(value=lv // rv)
                elif expr.op == "%":
                    if rv != 0:
                        return Const(value=lv % rv)
                elif expr.op == "&":
                    return Const(value=lv & rv)
                elif expr.op == "|":
                    return Const(value=lv | rv)
                elif expr.op == "^":
                    return Const(value=lv ^ rv)
                elif expr.op == "<<":
                    return Const(value=(lv << rv) & UINT256_MAX)
                elif expr.op == ">>":
                    return Const(value=lv >> rv)
            except (OverflowError, ValueError):
                pass

        return BinOp(op=expr.op, left=left, right=right, source_offset=expr.source_offset)

    if isinstance(expr, UnaryOp):
        operand = _pass_constant_fold(expr.operand)
        v = const_value(operand)
        if v is not None:
            if expr.op == "!":
                return Const(value=1 if v == 0 else 0)
            elif expr.op == "~":
                return Const(value=(~v) & UINT256_MAX)
        return UnaryOp(op=expr.op, operand=operand, source_offset=expr.source_offset)

    return expr


def _pass_double_negation(expr: Expr) -> Expr:
    """Remove double negation: !!x → x, !!!x → !x."""
    if isinstance(expr, UnaryOp) and expr.op == "!":
        inner = _pass_double_negation(expr.operand)
        if isinstance(inner, UnaryOp) and inner.op == "!":
            return _pass_double_negation(inner.operand)
        return UnaryOp(op="!", operand=inner, source_offset=expr.source_offset)

    # Recurse into children
    if isinstance(expr, BinOp):
        return BinOp(
            op=expr.op,
            left=_pass_double_negation(expr.left),
            right=_pass_double_negation(expr.right),
            source_offset=expr.source_offset,
        )
    if isinstance(expr, Compare):
        return Compare(
            op=expr.op,
            left=_pass_double_negation(expr.left),
            right=_pass_double_negation(expr.right),
            source_offset=expr.source_offset,
        )

    return expr


def _pass_zero_multiplication(expr: Expr) -> Expr:
    """0 * x → 0, x * 0 → 0."""
    if isinstance(expr, BinOp) and expr.op == "*":
        left = _pass_zero_multiplication(expr.left)
        right = _pass_zero_multiplication(expr.right)
        if is_const(left, 0) or is_const(right, 0):
            return Const(value=0)
        return BinOp(op="*", left=left, right=right, source_offset=expr.source_offset)

    if isinstance(expr, BinOp):
        return BinOp(
            op=expr.op,
            left=_pass_zero_multiplication(expr.left),
            right=_pass_zero_multiplication(expr.right),
            source_offset=expr.source_offset,
        )

    return expr


def _pass_address_mask(expr: Expr) -> Expr:
    """(x & ADDRESS_MASK) → x when x is already address-typed."""
    if isinstance(expr, BinOp) and expr.op == "&":
        left = _pass_address_mask(expr.left)
        right = _pass_address_mask(expr.right)

        # Check if either side is the address mask
        if is_const(right, ADDRESS_MASK):
            if isinstance(left, (MsgSender, CalldataArg)):
                return left
            # Nested mask: (x & mask) & mask → x & mask
            if isinstance(left, BinOp) and left.op == "&" and is_const(left.right, ADDRESS_MASK):
                return left
        if is_const(left, ADDRESS_MASK):
            if isinstance(right, (MsgSender, CalldataArg)):
                return right

        return BinOp(op="&", left=left, right=right, source_offset=expr.source_offset)

    if isinstance(expr, BinOp):
        return BinOp(
            op=expr.op,
            left=_pass_address_mask(expr.left),
            right=_pass_address_mask(expr.right),
            source_offset=expr.source_offset,
        )

    return expr


def _pass_selector_extraction(expr: Expr) -> Expr:
    """(SELECTOR_DIVISOR / calldata[0]) & SELECTOR_MASK → msg.sig."""
    if isinstance(expr, BinOp) and expr.op == "&":
        left = _pass_selector_extraction(expr.left)
        right = _pass_selector_extraction(expr.right)

        # Check for (big_const / calldata[0]) & 0xffffffff
        if is_const(right, SELECTOR_MASK):
            if isinstance(left, BinOp) and left.op == "/":
                if is_const(left.left, SELECTOR_DIVISOR):
                    return MsgSig(source_offset=expr.source_offset)
        if is_const(left, SELECTOR_MASK):
            if isinstance(right, BinOp) and right.op == "/":
                if is_const(right.left, SELECTOR_DIVISOR):
                    return MsgSig(source_offset=expr.source_offset)

        return BinOp(op="&", left=left, right=right, source_offset=expr.source_offset)

    if isinstance(expr, BinOp):
        return BinOp(
            op=expr.op,
            left=_pass_selector_extraction(expr.left),
            right=_pass_selector_extraction(expr.right),
            source_offset=expr.source_offset,
        )

    return expr


def _pass_calldata_args(expr: Expr) -> Expr:
    """
    Recognize calldata argument patterns:
    calldata[0x04] & ADDRESS_MASK → arg0: address
    calldata[0x04] (raw) → arg0
    calldata[0x24] → arg1
    etc.
    """
    if isinstance(expr, BinOp) and expr.op == "&":
        left = _pass_calldata_args(expr.left)
        right = _pass_calldata_args(expr.right)

        # calldata[offset] & ADDRESS_MASK → argN: address
        if is_const(right, ADDRESS_MASK) and isinstance(left, CalldataLoad):
            idx = _calldata_offset_to_arg_index(left.offset)
            if idx is not None:
                return CalldataArg(arg_index=idx, arg_type="address",
                                   raw_offset=const_value(left.offset),
                                   source_offset=expr.source_offset)

        return BinOp(op="&", left=left, right=right, source_offset=expr.source_offset)

    return expr


def _pass_comparison_normalize(expr: Expr) -> Expr:
    """
    Normalize comparisons:
    !(a < b) → a >= b
    !(a == b) → a != b
    """
    if isinstance(expr, UnaryOp) and expr.op == "!":
        inner = expr.operand
        if isinstance(inner, Compare):
            inverse = {"<": ">=", ">": "<=", "==": "!=", "!=": "==", ">=": "<", "<=": ">"}
            if inner.op in inverse:
                return Compare(
                    op=inverse[inner.op],
                    left=inner.left,
                    right=inner.right,
                    source_offset=expr.source_offset,
                )
    return expr


def _pass_memory_boilerplate(expr: Expr) -> Expr:
    """Replace memory[0x40] with FreeMemPtr."""
    if isinstance(expr, MemoryLoad):
        if is_const(expr.address, 0x40):
            return FreeMemPtr(source_offset=expr.source_offset)
    return expr


# ── Helpers ──────────────────────────────────────────────────────

def _calldata_offset_to_arg_index(offset_expr: Expr) -> Optional[int]:
    """Convert calldata byte offset to argument index."""
    v = const_value(offset_expr)
    if v is None:
        return None
    if v < 4:
        return None  # selector bytes
    arg_offset = v - 4
    if arg_offset % 32 != 0:
        return None
    return arg_offset // 32


# ── Text-based simplification for legacy pseudocode ──────────────

def simplify_condition(cond_text: str) -> str:
    """
    Simplify a branch condition text for pseudocode display.
    This operates on the string representation from StackValue.
    """
    result = simplify_text(cond_text)

    # Pattern: (0xSELECTOR == msg.sig) → just note it's a selector check
    # This is handled at the function slicer level

    # Pattern: msg.sender == owner → onlyOwner guard
    if "msg.sender" in result and "owner" in result and "==" in result:
        result = "msg.sender == owner  /* onlyOwner */"

    # Pattern: storage[0x00].packed_bool → paused check
    if "storage[0x00].packed_bool" in result:
        result = result.replace("storage[0x00].packed_bool", "paused")

    # Pattern: storage[0x0a].packed_bool → deprecated check
    if "storage[0x0a].packed_bool" in result:
        result = result.replace("storage[0x0a].packed_bool", "deprecated")

    return result
