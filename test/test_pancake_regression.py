from __future__ import annotations

import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path

from evm_check.engine import check_audit, load_rules


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "test" / "pancake_contract" / "runtime_code.txt"
FROST_RUNTIME = ROOT / "test" / "FROST" / "deployed_code.hex"
PEPE_RUNTIME = ROOT / "test" / "RwaVault" / "deployed_bytecode.hex"


def run_cli(fmt: str) -> dict:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "evm_decon",
            "--file",
            str(RUNTIME),
            "--format",
            fmt,
            "--no-resolve",
            "--no-assembly",
            "--profiles-dir",
            str(ROOT / "contract_profiles"),
        ],
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return json.loads(proc.stdout)


class PancakePairRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.audit = run_cli("json")

    def test_audit_json_shape(self):
        self.assertEqual(self.audit["schema"], "evm-audit.behavior.v2")
        self.assertEqual(self.audit["schema_version"], "2.0.0")
        self.assertIn("state_model", self.audit)
        self.assertEqual(self.audit["state_model"]["schema"], "evm-audit.state_model.v2")
        self.assertIn("slot_index", self.audit["state_model"])
        self.assertIn("path_index", self.audit["state_model"])
        self.assertIn("guard_catalog", self.audit["state_model"])
        self.assertIn("analysis_context", self.audit)
        self.assertIn("diagnostics", self.audit)
        self.assertIn("timings", self.audit)

    def test_removed_public_formats(self):
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "evm_decon",
                "--file",
                str(RUNTIME),
                "--format",
                "facts",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertNotEqual(proc.returncode, 0)

    def test_fixture_profile_is_not_first_party_engine_support(self):
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "evm_decon",
                "--file",
                str(RUNTIME),
                "--format",
                "json",
                "--no-resolve",
                "--no-assembly",
                "--no-profiles",
            ],
            cwd=ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        audit = json.loads(proc.stdout)
        self.assertNotIn("fixture:PancakePair", set(audit["contract"]["protocol_roles"]))

    def test_protocol_roles_and_storage(self):
        roles = set(self.audit["contract"]["protocol_roles"])
        self.assertIn("fixture:PancakePair", roles)
        self.assertIn("ERC20", roles)
        slots = {str(s["slot"]): s for s in self.audit["state_model"]["slot_index"]}
        self.assertTrue(slots)
        self.assertTrue(any(slot["semantic_role"] in {"balance", "reserve", "accounting"} for slot in slots.values()))

    def test_behavior_json_contains_actions_flows_and_state_model_indexes(self):
        funcs = {f["identity"]["name"]: f for f in self.audit["functions"] if f["identity"]["name"]}
        swap = funcs["swap(uint256,uint256,address,bytes)"]
        self.assertTrue(swap["actions"])
        self.assertIn("flows", swap)
        self.assertIn("external_calls", swap)
        self.assertTrue(self.audit["state_model"]["path_index"])
        self.assertTrue(self.audit["state_model"]["evidence_index"])

    def test_random_runtime_with_large_shift_completes(self):
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "evm_decon",
                "--file",
                str(PEPE_RUNTIME),
                "--format",
                "json",
                "--no-resolve",
                "--no-assembly",
                "--profiles-dir",
                str(ROOT / "contract_profiles"),
            ],
            cwd=ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
        )
        audit = json.loads(proc.stdout)
        self.assertEqual(audit["schema"], "evm-audit.behavior.v2")
        self.assertIn("functions", audit)


class RandomTokenRegressionTests(unittest.TestCase):
    def test_pepe_runtime_does_not_inherit_frost_transfer_semantics(self):
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "evm_audit",
                "--file",
                str(PEPE_RUNTIME),
                "--rules",
                "rules/core/token.transfer.sender_debit_credit_mismatch.json",
                "--format",
                "api-json",
                "--no-resolve",
                "--profiles-dir",
                str(ROOT / "contract_profiles"),
            ],
            cwd=ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        result = json.loads(proc.stdout)
        self.assertEqual(result["analysis"]["raw_match_count"], 0)
        self.assertEqual(result["analysis"]["finding_count"], 0)

    def test_pepe_runtime_proxy_shell_does_not_inherit_profile_transfer_semantics(self):
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "evm_decon",
                "--file",
                str(PEPE_RUNTIME),
                "--format",
                "json",
                "--no-resolve",
                "--no-assembly",
                "--profiles-dir",
                str(ROOT / "contract_profiles"),
            ],
            cwd=ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        audit = json.loads(proc.stdout)
        self.assertTrue(audit["proxy_analysis"]["is_proxy"])
        self.assertEqual(audit["proxy_analysis"]["proxy_standard"], "EIP-1967")
        function_names = {fn["identity"].get("name") for fn in audit["functions"] if fn["identity"].get("name")}
        self.assertFalse({"transfer(address,uint256)", "transferFrom(address,address,uint256)"} & function_names)
        self.assertNotIn("yieldcore_rwa_vault", set(audit["contract"]["protocol_roles"]))
        self.assertEqual(
            function_names,
            {"upgradeTo(address)", "upgradeToAndCall(address,bytes)", "implementation()", "changeAdmin(address)", "admin()"},
        )


class CheckerRegressionTests(unittest.TestCase):
    def test_builtin_corpora(self):
        corpora = [
            ("rules/core/init.public_initializer_takeover.json", "corpus/init"),
            ("rules/core/access.public_privileged_slot_poisoning.json", "corpus/access_slot_poisoning"),
            ("rules/core/auth.authorization_predicate_poisoning.json", "corpus/auth_predicate_poisoning"),
            ("rules/core/proxy.unprotected_implementation_upgrade.json", "corpus/proxy_upgrade"),
            ("rules/core/delegatecall.storage_controlled_target.json", "corpus/delegatecall_target"),
            ("rules/core/defi.rounding.assumed_actual_balance_mismatch.json", "corpus/rounding"),
            ("rules/core/token.transfer.sender_debit_credit_mismatch.json", "corpus/frost_transfer_inflation"),
        ]
        for rule_path, corpus_path in corpora:
            proc = subprocess.run(
                [sys.executable, "-m", "evm_rule", "test", rule_path, corpus_path],
                cwd=ROOT,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            result = json.loads(proc.stdout)
            self.assertTrue(result["ok"], msg=rule_path)

    def test_rounding_finding_has_required_evidence(self):
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "evm_check",
                "--facts",
                "corpus/rounding/positive_balancer_like.audit.json",
                "--rules",
                "rules/core/defi.rounding.assumed_actual_balance_mismatch.json",
            ],
            cwd=ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        result = json.loads(proc.stdout)
        finding = result["findings"][0]
        self.assertEqual(finding["rule_id"], "defi.rounding.assumed_actual_balance_mismatch")
        self.assertEqual(finding["proof_level"], "P4")
        self.assertIn("actions", finding["evidence"])
        self.assertIn("flows", finding["evidence"])
        self.assertIn("arithmetic", finding["evidence"])
        self.assertEqual(finding["proof"]["required_witness"], "deterministic_arithmetic_witness")
        witness = finding["proof"]["witness"]
        self.assertEqual(witness["kind"], "deterministic_arithmetic_witness")
        self.assertTrue(witness["witness_id"])
        self.assertIn("arithmetic_fact", witness["evidence_refs"])

    def test_checker_downgrades_when_coverage_gate_fails(self):
        from evm_check.engine import check_audit, load_rules

        with open(ROOT / "corpus" / "rounding" / "positive_balancer_like.audit.json") as f:
            audit = json.load(f)
        rule = load_rules(ROOT / "rules" / "core" / "defi.rounding.assumed_actual_balance_mismatch.json")[0]
        rule["analysis_requirements"]["min_function_coverage"] = 0.99
        result = check_audit(audit, [rule])
        finding = result["findings"][0]
        self.assertEqual(finding["status"], "analysis_inconclusive")
        self.assertEqual(finding["severity"], "medium")

    def test_stateful_sequence_witness_exposes_trace_fields(self):
        rule = load_rules(ROOT / "rules" / "core" / "access.public_privileged_slot_poisoning.json")[0]
        audit = load_json(ROOT / "corpus" / "access_slot_poisoning" / "positive_owner.audit.json")
        result = check_audit(audit, [rule])
        finding = result["findings"][0]
        witness = finding["proof"]["witness"]
        self.assertEqual(witness["kind"], "transaction_sequence")
        self.assertTrue(witness["witness_id"])
        self.assertTrue(witness["steps"])
        self.assertTrue(witness["evidence_refs"])

    def test_validate_detector_rejects_shallow_sequence(self):
        from evm_check.schema import validate_rule

        rule = load_json(ROOT / "rules" / "core" / "access.public_privileged_slot_poisoning.json")
        shallow = copy.deepcopy(rule)
        shallow["requires"]["sequence"][0].pop("bind")
        result = validate_rule(shallow)
        self.assertFalse(result["ok"])
        self.assertTrue(any("bind" in err or "binding" in err for err in result["errors"]))

    def test_validate_detector_rejects_disabled_analysis_thresholds(self):
        from evm_check.schema import validate_rule

        rule = load_json(ROOT / "rules" / "core" / "access.public_privileged_slot_poisoning.json")
        bad = copy.deepcopy(rule)
        bad["analysis_requirements"]["max_unknown_action_expression_count"] = 1_000_000
        result = validate_rule(bad)
        self.assertFalse(result["ok"])
        self.assertTrue(any("too permissive" in err for err in result["errors"]))

    def test_validate_audit_requires_state_model(self):
        from evm_check.schema import validate_audit

        audit = load_json(ROOT / "corpus" / "init" / "positive_owner.audit.json")
        bad = copy.deepcopy(audit)
        bad.pop("state_model")
        errors = validate_audit(bad)
        self.assertTrue(any("state_model" in err for err in errors))

    def test_rule_doctor_flags_shallow_detector(self):
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "evm_rule",
                "doctor",
                "rules/core/access.public_privileged_slot_poisoning.json",
            ],
            cwd=ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        result = json.loads(proc.stdout)
        self.assertEqual(result["issues"], [])

    def test_validate_detector_rejects_required_confidence_inputs_without_policy(self):
        from evm_check.schema import validate_rule

        rule = load_json(ROOT / "rules" / "core" / "token.transfer.sender_debit_credit_mismatch.json")
        bad = copy.deepcopy(rule)
        bad["rule"].pop("confidence_cap_policy")
        result = validate_rule(bad)
        self.assertFalse(result["ok"])
        self.assertTrue(any("required_confidence_inputs requires" in err for err in result["errors"]))

    def test_high_and_critical_builtin_rules_use_confidence_caps(self):
        for path in sorted((ROOT / "rules" / "core").glob("*.json")):
            rule = load_json(path)
            severity = rule["rule"]["severity"]
            if severity not in {"high", "critical"}:
                continue
            self.assertEqual(rule["rule"].get("confidence_cap_policy"), "min_required_input", msg=path.name)
            self.assertTrue(rule["rule"].get("required_confidence_inputs"), msg=path.name)

    def test_builtin_rules_require_usable_primary_evidence(self):
        for path in sorted((ROOT / "rules" / "core").glob("*.json")):
            rule = load_json(path)
            self.assertTrue(
                rule["analysis_requirements"].get("require_usable_primary_evidence"),
                msg=path.name,
            )


class FrostRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "evm_decon",
                "--file",
                str(FROST_RUNTIME),
                "--format",
                "json",
                "--no-resolve",
                "--no-assembly",
                "--profiles-dir",
                str(ROOT / "contract_profiles"),
            ],
            cwd=ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        cls.audit = json.loads(proc.stdout)

    def test_frost_profile_marks_fixture_family(self):
        self.assertIn("fixture:FROST", set(self.audit["contract"]["protocol_roles"]))

    def test_frost_transfer_detector_fires_on_real_runtime(self):
        rule = load_rules(ROOT / "rules" / "core" / "token.transfer.sender_debit_credit_mismatch.json")[0]
        result = check_audit(self.audit, [rule])
        findings = [f for f in result["findings"] if f["rule_id"] == "token.transfer.sender_debit_credit_mismatch"]
        selectors = {finding["function"]["selector"] for finding in findings}
        self.assertIn("0xa9059cbb", selectors)
        self.assertIn("0x23b872dd", selectors)
        for finding in findings:
            self.assertEqual(finding["status"], "probable_vulnerability")
            self.assertEqual(finding["severity"], "critical")
            self.assertEqual(finding["proof"]["required_witness"], "deterministic_accounting_witness")
            witness = finding["proof"]["witness"]
            self.assertEqual(witness["kind"], "deterministic_accounting_witness")
            self.assertEqual(witness["mismatch_amount"], "transferFeeAmount")
            self.assertEqual(witness["gross_amount"], "amount")
            self.assertEqual(witness["proved_relation"], "tokensToTransfer = amount - transferFeeAmount")
            self.assertEqual(witness["balance_sum_delta"], "transferFeeAmount")
            self.assertIn("sender_debit_action", witness["evidence_refs"])
            self.assertTrue(witness["evidence_refs"]["total_supply_nonwrite_proof"])
            self.assertEqual(
                finding["confidence"],
                min(
                    self.audit["coverage"]["function_coverage"],
                    self.audit["coverage"]["storage_role_confidence"],
                    self.audit["coverage"]["path_reachability_confidence"],
                ),
            )

    def test_frost_api_output_collapses_raw_matches_and_keeps_trace(self):
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "evm_audit",
                "--file",
                str(FROST_RUNTIME),
                "--rules",
                "rules/core",
                "--format",
                "api-json",
                "--no-resolve",
                "--profiles-dir",
                str(ROOT / "contract_profiles"),
            ],
            cwd=ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        result = json.loads(proc.stdout)
        self.assertEqual(result["analysis"]["finding_count"], 1)
        self.assertEqual(result["analysis"]["raw_match_count"], 2)
        finding = result["findings"][0]
        self.assertEqual(finding["rule_id"], "token.transfer.sender_debit_credit_mismatch")
        self.assertEqual(finding["match_count"], 2)
        self.assertEqual(len(finding["raw_matches"]), 2)
        selectors = {entry["function"]["selector"] for entry in finding["raw_matches"]}
        self.assertEqual(selectors, {"0xa9059cbb", "0x23b872dd"})
        for raw in finding["raw_matches"]:
            self.assertTrue(raw["path_id"])
            self.assertTrue(raw["witness_id"])
            self.assertTrue(raw["evidence_refs"]["sender_debit_action"])
            self.assertTrue(raw["evidence_refs"]["recipient_credit_action"])

    def test_frost_api_and_sarif_have_rule_and_severity_parity(self):
        api_proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "evm_audit",
                "--file",
                str(FROST_RUNTIME),
                "--rules",
                "rules/core",
                "--format",
                "api-json",
                "--no-resolve",
                "--profiles-dir",
                str(ROOT / "contract_profiles"),
            ],
            cwd=ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        sarif_proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "evm_audit",
                "--file",
                str(FROST_RUNTIME),
                "--rules",
                "rules/core",
                "--format",
                "sarif",
                "--no-resolve",
                "--profiles-dir",
                str(ROOT / "contract_profiles"),
            ],
            cwd=ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        api = json.loads(api_proc.stdout)
        sarif = json.loads(sarif_proc.stdout)
        api_finding = api["findings"][0]
        sarif_results = [row for row in sarif["runs"][0]["results"] if row["ruleId"] == api_finding["rule_id"]]
        self.assertEqual(len(sarif_results), 2)
        for result in sarif_results:
            self.assertEqual(result["properties"]["severity"], api_finding["severity"])
            self.assertEqual(result["properties"]["internal_name"], api_finding["internal_name"])
            self.assertEqual(result["properties"]["witness"]["proved_relation"], api_finding["witness"]["proved_relation"])
            self.assertTrue(result["properties"]["witness"]["evidence_refs"]["total_supply_nonwrite_proof"])


def load_json(path: Path) -> dict:
    return json.loads(path.read_text())


if __name__ == "__main__":
    unittest.main()
