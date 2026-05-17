from __future__ import annotations

import unittest

from evm_decon.pipeline import (
    BytecodeInputError,
    MAX_INPUT_BYTECODE_BYTES,
    analyze_bytecode,
    validate_hex_bytecode,
)


class BytecodeValidationTests(unittest.TestCase):
    def test_rejects_non_hex_input(self):
        with self.assertRaises(BytecodeInputError):
            validate_hex_bytecode("0xzz")

    def test_rejects_odd_length_hex_input(self):
        with self.assertRaises(BytecodeInputError):
            validate_hex_bytecode("0x123")

    def test_rejects_oversized_input(self):
        oversized = "aa" * (MAX_INPUT_BYTECODE_BYTES + 1)
        with self.assertRaises(BytecodeInputError):
            analyze_bytecode(oversized)
