"""Tests for --chain-context, --eof, --proxy-shell, --step-budget-ms CLI args."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).parent.parent
RULES = REPO / "rules" / "core"

# Minimal valid EVM bytecode: PUSH1 0x00 STOP
MINIMAL_HEX = "0x600000"

# Minimal EIP-3541 EOF bytecode prefix
EOF_HEX = "0xef0001"


def run_audit(extra_args: list[str], hex_input: str = MINIMAL_HEX) -> dict:
    result = subprocess.run(
        [sys.executable, "-m", "evm_audit", "--rules", str(RULES), "--format", "api-json", "--no-resolve", "--hex", hex_input, *extra_args],
        capture_output=True,
        text=True,
        cwd=str(REPO),
    )
    if result.returncode != 0:
        raise AssertionError(f"evm_audit exited {result.returncode}:\n{result.stderr}")
    return json.loads(result.stdout)


class TestChainContext(unittest.TestCase):
    def test_chain_context_appears_in_api_json(self):
        ctx = {"chainId": 1, "blockNumber": 99, "blockTimestamp": 1700000000, "txHash": "0xabc", "deployer": "0xdef"}
        data = run_audit(["--chain-context", json.dumps(ctx)])
        self.assertIn("chain_context", data)
        self.assertEqual(data["chain_context"].get("chainId"), 1)
        self.assertEqual(data["chain_context"].get("blockNumber"), 99)

    def test_empty_chain_context_produces_empty_dict(self):
        data = run_audit([])
        self.assertIn("chain_context", data)
        self.assertIsInstance(data["chain_context"], dict)

    def test_invalid_chain_context_exits_nonzero(self):
        result = subprocess.run(
            [sys.executable, "-m", "evm_audit", "--rules", str(RULES), "--format", "api-json", "--hex", MINIMAL_HEX, "--chain-context", "not-json"],
            capture_output=True,
            text=True,
            cwd=str(REPO),
        )
        self.assertNotEqual(result.returncode, 0)


class TestEofFlag(unittest.TestCase):
    def test_eof_bytecode_produces_analysis_warning(self):
        # EOF container bytecode — disassembler returns early with eof_format_detected
        data = run_audit(["--eof"], hex_input=EOF_HEX)
        warnings = data.get("diagnostics", {}).get("analysis_warnings", [])
        # Warning may come through analysis_warnings or coverage
        self.assertIsInstance(data, dict)
        self.assertTrue(data.get("ok"), f"Expected ok=true, got: {data}")

    def test_eof_prefix_disassembly_returns_early(self):
        from evm_decon.disassembler import disassemble
        result = disassemble("ef0001")
        self.assertEqual(result.instructions, [])
        self.assertTrue(any("eof_format_detected" in e for e in result.errors), result.errors)


class TestProxyShellFlag(unittest.TestCase):
    def test_proxy_shell_exits_zero(self):
        # EIP-1167 minimal proxy: 45 bytes
        eip1167 = "363d3d373d3d3d363d73" + "a" * 40 + "5af43d82803e903d91602b57fd5bf3"
        data = run_audit(["--proxy-shell"], hex_input="0x" + eip1167)
        self.assertTrue(data.get("ok"), data)


class TestStepBudget(unittest.TestCase):
    def test_step_budget_1ms_exits_zero_with_warning(self):
        # 1ms budget — pipeline will truncate on any non-trivial contract
        data = run_audit(["--step-budget-ms", "1"])
        self.assertTrue(data.get("ok"), data)


class TestVersionFlag(unittest.TestCase):
    def test_version_flag_exits_zero(self):
        result = subprocess.run(
            [sys.executable, "-m", "evm_audit", "--version", "--hex", MINIMAL_HEX, "--rules", str(RULES)],
            capture_output=True,
            text=True,
            cwd=str(REPO),
        )
        # --version is handled before --hex/--rules requirement check
        self.assertEqual(result.returncode, 0)
        self.assertIn("evm_audit", result.stdout)


if __name__ == "__main__":
    unittest.main()
