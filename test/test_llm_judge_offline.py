"""Offline tests for the LLM judge — no real API calls.

All openai client interactions are monkeypatched with a fake implementation
so this test file runs without the openai package installed and without any
running model server.
"""

from __future__ import annotations

import json
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Inject a minimal fake `openai` package so the module can be imported
# without the real package installed.
# ---------------------------------------------------------------------------

def _make_fake_openai():
    openai_mod = types.ModuleType("openai")

    class FakeChoice:
        def __init__(self, content):
            self.message = MagicMock(content=content)

    class FakeResponse:
        def __init__(self, content):
            self.choices = [FakeChoice(content)]

    class FakeCompletions:
        def __init__(self, content):
            self._content = content

        def create(self, **kwargs):
            return FakeResponse(self._content)

    class FakeChat:
        def __init__(self, content):
            self.completions = FakeCompletions(content)

    class FakeOpenAI:
        def __init__(self, **kwargs):
            self._content = _CURRENT_VERDICT

        @property
        def chat(self):
            return FakeChat(self._content)

    openai_mod.OpenAI = FakeOpenAI
    return openai_mod


_CURRENT_VERDICT = json.dumps({"verdict": "valid", "rationale": "genuine", "confidence": 0.9})

_fake_openai = _make_fake_openai()
sys.modules.setdefault("openai", _fake_openai)


# ---------------------------------------------------------------------------
# Now import the module under test
# ---------------------------------------------------------------------------
from evm_check.llm_judge import (  # noqa: E402
    VERDICT_FALSE_POSITIVE,
    VERDICT_NEEDS_HUMAN,
    VERDICT_VALID,
    JudgeConfig,
    JudgeResult,
    apply_judge_result,
    cache_key,
    is_available,
    judge_finding,
    run_judge_pass,
    _parse_verdict,
    _CACHE_DIR,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

MINIMAL_AUDIT = {
    "schema": "evm-audit.behavior",
    "schema_version": "2.0.0",
    "bytecode_identity": {"keccak256": "0xabc123"},
    "functions": [],
    "state_model": {"slot_index": []},
}

PROBABLE_FINDING = {
    "rule_id": "test.rule",
    "status": "probable_vulnerability",
    "witness_status": "not_attempted",
    "technical_summary": "a technical summary",
    "exploit_narrative": "an exploit scenario",
    "evidence": {"details": {"bindings": {"slot": "0x01"}}},
}

SUSPICIOUS_FINDING = {
    "rule_id": "test.rule",
    "status": "suspicious_behavior",
    "witness_status": "not_attempted",
    "technical_summary": "low confidence finding",
    "exploit_narrative": "speculative",
    "evidence": {"details": {"bindings": {}}},
}

SUPPRESSED_FINDING = {
    "rule_id": "test.rule",
    "status": "suppressed_by_counter_evidence",
    "witness_status": "suppressed_by_counter_evidence",
}

MINIMAL_RULE = {
    "rule": {"id": "test.rule"},
    "intent": {"vulnerability_class": "test_class", "attack_thesis": "test"},
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCacheKey(unittest.TestCase):
    def test_same_inputs_produce_same_key(self):
        k1 = cache_key("0xabc", "rule.id", "{}")
        k2 = cache_key("0xabc", "rule.id", "{}")
        self.assertEqual(k1, k2)

    def test_different_bytecode_produces_different_key(self):
        k1 = cache_key("0xaaa", "rule.id", "{}")
        k2 = cache_key("0xbbb", "rule.id", "{}")
        self.assertNotEqual(k1, k2)

    def test_different_rule_produces_different_key(self):
        k1 = cache_key("0xabc", "rule.a", "{}")
        k2 = cache_key("0xabc", "rule.b", "{}")
        self.assertNotEqual(k1, k2)


class TestParseVerdict(unittest.TestCase):
    def test_valid_verdict(self):
        raw = json.dumps({"verdict": "valid", "rationale": "ok", "confidence": 0.9})
        result = _parse_verdict(raw, "key")
        self.assertIsNotNone(result)
        self.assertEqual(result.verdict, VERDICT_VALID)
        self.assertAlmostEqual(result.confidence, 0.9)

    def test_false_positive_verdict(self):
        raw = json.dumps({"verdict": "false_positive", "rationale": "no real risk", "confidence": 0.8})
        result = _parse_verdict(raw, "key")
        self.assertEqual(result.verdict, VERDICT_FALSE_POSITIVE)

    def test_needs_human_verdict(self):
        raw = json.dumps({"verdict": "needs_human", "rationale": "unclear", "confidence": 0.5})
        result = _parse_verdict(raw, "key")
        self.assertEqual(result.verdict, VERDICT_NEEDS_HUMAN)

    def test_invalid_json_returns_none(self):
        result = _parse_verdict("not json at all", "key")
        self.assertIsNone(result)

    def test_unknown_verdict_becomes_needs_human(self):
        raw = json.dumps({"verdict": "maybe", "rationale": "?", "confidence": 0.5})
        result = _parse_verdict(raw, "key")
        self.assertEqual(result.verdict, VERDICT_NEEDS_HUMAN)

    def test_markdown_fences_stripped(self):
        raw = "```json\n" + json.dumps({"verdict": "valid", "rationale": "ok", "confidence": 0.85}) + "\n```"
        result = _parse_verdict(raw, "key")
        self.assertIsNotNone(result)
        self.assertEqual(result.verdict, VERDICT_VALID)

    def test_confidence_clamped(self):
        raw = json.dumps({"verdict": "valid", "rationale": "ok", "confidence": 99.0})
        result = _parse_verdict(raw, "key")
        self.assertLessEqual(result.confidence, 1.0)


class TestApplyJudgeResult(unittest.TestCase):
    def test_probable_false_positive_becomes_inconclusive(self):
        result = JudgeResult(verdict=VERDICT_FALSE_POSITIVE, rationale="nope", confidence=0.8)
        out = apply_judge_result(dict(PROBABLE_FINDING), result)
        self.assertEqual(out["status"], "analysis_inconclusive")
        self.assertEqual(out["witness_status"], "analysis_inconclusive")
        self.assertEqual(out["judged_by"], "llm")

    def test_suspicious_false_positive_becomes_suppressed(self):
        result = JudgeResult(verdict=VERDICT_FALSE_POSITIVE, rationale="nope", confidence=0.8)
        out = apply_judge_result(dict(SUSPICIOUS_FINDING), result)
        self.assertEqual(out["status"], "suppressed_by_counter_evidence")
        self.assertEqual(out["witness_status"], "suppressed_by_counter_evidence")

    def test_valid_verdict_does_not_change_status(self):
        result = JudgeResult(verdict=VERDICT_VALID, rationale="real", confidence=0.9)
        out = apply_judge_result(dict(PROBABLE_FINDING), result)
        self.assertEqual(out["status"], "probable_vulnerability")

    def test_needs_human_sets_manual_review_flag(self):
        result = JudgeResult(verdict=VERDICT_NEEDS_HUMAN, rationale="unclear", confidence=0.5)
        out = apply_judge_result(dict(PROBABLE_FINDING), result)
        self.assertTrue(out.get("requires_manual_review"))
        self.assertEqual(out["status"], "probable_vulnerability")

    def test_judge_fields_always_set(self):
        result = JudgeResult(verdict=VERDICT_VALID, rationale="genuine", confidence=0.95)
        out = apply_judge_result(dict(PROBABLE_FINDING), result)
        self.assertEqual(out["judged_by"], "llm")
        self.assertEqual(out["judge_verdict"], VERDICT_VALID)
        self.assertIn("judge_rationale", out)
        self.assertIn("judge_confidence", out)


class TestRunJudgePass(unittest.TestCase):
    def _make_cfg(self):
        cfg = JudgeConfig(refresh_cache=True)
        cfg.base_url = "http://localhost:11434/v1"
        return cfg

    def test_suppressed_findings_skipped(self):
        global _CURRENT_VERDICT
        _CURRENT_VERDICT = json.dumps({"verdict": "valid", "rationale": "real", "confidence": 0.9})
        _fake_openai.OpenAI = _make_fake_openai().OpenAI

        findings = [dict(SUPPRESSED_FINDING)]
        out = run_judge_pass(findings, MINIMAL_AUDIT, {"test.rule": MINIMAL_RULE}, self._make_cfg())
        self.assertEqual(len(out), 1)
        self.assertNotIn("judged_by", out[0])

    def test_probable_finding_judged(self):
        global _CURRENT_VERDICT
        _CURRENT_VERDICT = json.dumps({"verdict": "valid", "rationale": "genuine", "confidence": 0.9})
        _fake_openai.OpenAI = _make_fake_openai().OpenAI

        findings = [dict(PROBABLE_FINDING)]
        with patch("evm_check.llm_judge.is_available", return_value=True):
            out = run_judge_pass(findings, MINIMAL_AUDIT, {"test.rule": MINIMAL_RULE}, self._make_cfg())
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].get("judge_verdict"), VERDICT_VALID)

    def test_false_positive_verdict_downgrades(self):
        global _CURRENT_VERDICT
        _CURRENT_VERDICT = json.dumps({"verdict": "false_positive", "rationale": "no risk", "confidence": 0.85})
        _fake_openai.OpenAI = _make_fake_openai().OpenAI

        findings = [dict(PROBABLE_FINDING)]
        with patch("evm_check.llm_judge.is_available", return_value=True):
            out = run_judge_pass(findings, MINIMAL_AUDIT, {"test.rule": MINIMAL_RULE}, self._make_cfg())
        self.assertEqual(out[0]["status"], "analysis_inconclusive")


class TestCacheRoundtrip(unittest.TestCase):
    def test_cache_write_and_read(self):
        from evm_check.llm_judge import _write_cache, _read_cache
        import tempfile, os

        key = "test_cache_key_roundtrip_xyz"
        original = JudgeResult(verdict=VERDICT_VALID, rationale="test rationale", confidence=0.77)

        with patch("evm_check.llm_judge._CACHE_DIR", Path(tempfile.mkdtemp())):
            from evm_check import llm_judge
            cache_dir_backup = llm_judge._CACHE_DIR
            llm_judge._CACHE_DIR = Path(tempfile.mkdtemp())
            try:
                _write_cache(key, original)
                recovered = _read_cache(key)
                self.assertIsNotNone(recovered)
                self.assertEqual(recovered.verdict, VERDICT_VALID)
                self.assertAlmostEqual(recovered.confidence, 0.77, places=2)
                self.assertTrue(recovered.cached)
            finally:
                llm_judge._CACHE_DIR = cache_dir_backup

    def test_cache_miss_returns_none(self):
        from evm_check.llm_judge import _read_cache
        import tempfile
        from evm_check import llm_judge
        cache_dir_backup = llm_judge._CACHE_DIR
        llm_judge._CACHE_DIR = Path(tempfile.mkdtemp())
        try:
            result = _read_cache("nonexistent_key_abc123")
            self.assertIsNone(result)
        finally:
            llm_judge._CACHE_DIR = cache_dir_backup


class TestIsAvailableWithoutOpenai(unittest.TestCase):
    def test_returns_false_when_openai_import_fails(self):
        with patch.dict(sys.modules, {"openai": None}):
            cfg = JudgeConfig()
            self.assertFalse(is_available(cfg))


if __name__ == "__main__":
    unittest.main()
