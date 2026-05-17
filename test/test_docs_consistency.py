"""Consistency regression test: docs, schema constants, and rule files stay in sync."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

REPO = Path(__file__).parent.parent
RULES_DIR = REPO / "rules" / "core"
README = REPO / "README.md"
BEHAVIOR_SCHEMA_DOC = REPO / "docs" / "BEHAVIOR_SCHEMA.md"
DETECTOR_SPEC_DOC = REPO / "docs" / "DETECTOR_SPEC_V1.md"
COUNTER_EVIDENCE_DOC = REPO / "docs" / "COUNTER_EVIDENCE.md"


def _load_rule_ids() -> list[str]:
    ids = []
    for path in sorted(RULES_DIR.glob("*.json")):
        data = json.loads(path.read_text())
        rule_id = data.get("rule", {}).get("id")
        if rule_id:
            ids.append(rule_id)
    return ids


class TestDetectorCount(unittest.TestCase):
    def test_readme_claims_correct_detector_count(self):
        """README heading must state the actual rule count."""
        rule_ids = _load_rule_ids()
        actual = len(rule_ids)
        text = README.read_text()
        # Accept "N total" where N matches actual count
        match = re.search(r"\((\d+)\s+total\)", text)
        self.assertIsNotNone(match, "README should contain '(N total)' detector count marker")
        claimed = int(match.group(1))
        self.assertEqual(
            claimed,
            actual,
            f"README claims {claimed} detectors but found {actual} in {RULES_DIR}",
        )

    def test_all_rule_ids_mentioned_in_readme(self):
        """Every rule id must appear at least once in README."""
        text = README.read_text()
        missing = [rid for rid in _load_rule_ids() if rid not in text]
        self.assertFalse(
            missing,
            f"Rule IDs missing from README: {missing}",
        )


class TestSchemaVersions(unittest.TestCase):
    def test_behavior_schema_doc_states_v2(self):
        text = BEHAVIOR_SCHEMA_DOC.read_text()
        self.assertIn("2.0.0", text, "BEHAVIOR_SCHEMA.md should reference behavior schema version 2.0.0")

    def test_behavior_schema_doc_states_state_model_v2(self):
        text = BEHAVIOR_SCHEMA_DOC.read_text()
        self.assertIn("2.1.0", text, "BEHAVIOR_SCHEMA.md should reference state model version 2.1.0")

    def test_detector_spec_doc_states_v1_1(self):
        text = DETECTOR_SPEC_DOC.read_text()
        self.assertIn("1.1.0", text, "DETECTOR_SPEC_V1.md should document schema v1.1.0")

    def test_evm_core_schemas_match_docs(self):
        """evm_core/schemas.py version constants must align with what docs claim."""
        import importlib.util
        schemas_path = REPO / "evm_core" / "schemas.py"
        if not schemas_path.exists():
            self.skipTest("evm_core/schemas.py not found")
        spec = importlib.util.spec_from_file_location("evm_core.schemas", schemas_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        if hasattr(mod, "STATE_MODEL_SCHEMA_VERSION"):
            self.assertEqual(mod.STATE_MODEL_SCHEMA_VERSION, "2.1.0")
        if hasattr(mod, "DETECTOR_SCHEMA_VERSION"):
            self.assertEqual(mod.DETECTOR_SCHEMA_VERSION, "1.1.0")


class TestDetectorSchemas(unittest.TestCase):
    def test_all_rules_have_valid_schema_version(self):
        """Every rule JSON must declare schema_version 1.0.0 or 1.1.0."""
        supported = {"1.0.0", "1.1.0"}
        bad = []
        for path in sorted(RULES_DIR.glob("*.json")):
            data = json.loads(path.read_text())
            version = data.get("schema_version")
            if version not in supported:
                bad.append(f"{path.name}: {version!r}")
        self.assertFalse(bad, f"Rules with unsupported schema_version: {bad}")

    def test_all_rules_have_witness_goal(self):
        """Every rule at schema v1.1.0 must include a witness_goal block."""
        missing = []
        for path in sorted(RULES_DIR.glob("*.json")):
            data = json.loads(path.read_text())
            if data.get("schema_version") == "1.1.0" and "witness_goal" not in data:
                missing.append(path.name)
        self.assertFalse(missing, f"v1.1.0 rules missing witness_goal: {missing}")

    def test_all_rules_disallow_name_and_selector_primary_evidence(self):
        """Every rule must disallow function_name and selector as primary evidence."""
        bad = []
        for path in sorted(RULES_DIR.glob("*.json")):
            data = json.loads(path.read_text())
            disallowed = set(data.get("rule", {}).get("disallow_primary_evidence", []))
            if not {"function_name", "selector"} <= disallowed:
                bad.append(path.name)
        self.assertFalse(bad, f"Rules missing disallow_primary_evidence: {bad}")

    def test_all_rules_have_require_usable_primary_evidence(self):
        """Every rule must set require_usable_primary_evidence in analysis_requirements."""
        missing = []
        for path in sorted(RULES_DIR.glob("*.json")):
            data = json.loads(path.read_text())
            ar = data.get("analysis_requirements", {})
            if "require_usable_primary_evidence" not in ar:
                missing.append(path.name)
        self.assertFalse(missing, f"Rules missing require_usable_primary_evidence: {missing}")

    def test_high_severity_rules_have_p3_or_higher_proof(self):
        """High-severity rules must require at least P3 proof level."""
        proof_order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
        bad = []
        for path in sorted(RULES_DIR.glob("*.json")):
            data = json.loads(path.read_text())
            sev = data.get("rule", {}).get("severity", "")
            lvl = data.get("proof", {}).get("min_level", "P0")
            if sev == "high" and proof_order.get(lvl, -1) < proof_order["P3"]:
                bad.append(f"{path.name} ({lvl})")
        self.assertFalse(bad, f"High-severity rules with proof below P3: {bad}")

    def test_all_rules_have_declared_corpus_directory(self):
        """Every rule must declare fixture_requirements.corpus pointing to an existing directory."""
        missing = []
        for path in sorted(RULES_DIR.glob("*.json")):
            data = json.loads(path.read_text())
            corpus_rel = data.get("fixture_requirements", {}).get("corpus", "")
            if not corpus_rel:
                missing.append(f"{path.name}: no corpus declared")
                continue
            corpus_path = REPO / corpus_rel
            if not corpus_path.exists():
                missing.append(f"{path.name}: corpus dir {corpus_rel!r} missing")
        self.assertFalse(missing, f"Corpus issues: {missing}")

    def test_all_rules_have_nonzero_inconclusive_fixtures_min(self):
        """Every rule must require at least 1 inconclusive fixture."""
        bad = []
        for path in sorted(RULES_DIR.glob("*.json")):
            data = json.loads(path.read_text())
            n = data.get("fixture_requirements", {}).get("inconclusive_fixtures_min", 0)
            if n < 1:
                bad.append(path.name)
        self.assertFalse(bad, f"Rules with inconclusive_fixtures_min < 1: {bad}")


class TestCounterEvidenceDoc(unittest.TestCase):
    def test_counter_evidence_doc_exists(self):
        self.assertTrue(COUNTER_EVIDENCE_DOC.exists(), "docs/COUNTER_EVIDENCE.md must exist")

    def test_counter_evidence_doc_lists_oz_tokens(self):
        text = COUNTER_EVIDENCE_DOC.read_text()
        expected_tokens = [
            "OZ_REENTRANCY_GUARD",
            "SAFE_ERC20_USAGE",
            "OZ_OWNABLE2STEP",
            "OZ_ACCESS_CONTROL",
            "OZ_TIMELOCK_CONTROLLER",
        ]
        missing = [t for t in expected_tokens if t not in text]
        self.assertFalse(missing, f"COUNTER_EVIDENCE.md missing tokens: {missing}")


if __name__ == "__main__":
    unittest.main()
