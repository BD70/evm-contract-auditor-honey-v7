// Package schema holds versioned schema identifiers and validation constants
// used across all evm-auditor binaries. Mirrors evm_check/schema.py and
// evm_core/schemas.
package schema

const (
	BehaviorSchemaV2       = "evm-audit.behavior.v2"
	BehaviorSchemaVersion  = "2.0.0"
	StateModelSchemaV2     = "evm-audit.state_model.v2"
	DetectorSchema         = "evm-audit.detector.v1"
	SupportedDetectorVer   = "1.0.0"
	CorpusSchema           = "evm-audit.corpus.v1"
	SupportedCorpusVer     = "1.0.0"
	CheckerSchema          = "evm-audit.checker"
	CheckerSchemaVer       = "1.0.0"
	RuleValidationSchema   = "evm-audit.detector_validation"
	APISchema              = "evm-audit.api.v2"
	APISchemaVer           = "2.0.0"
	DiffSchema             = "evm-audit.diff"
)

// LegacyBehaviorSchemas is the set of behavior schema identifiers accepted by
// validate_audit (mirrors evm_check.schema.LEGACY_BEHAVIOR_SCHEMAS).
var LegacyBehaviorSchemas = map[string]struct{}{
	"evm-audit.behavior": {},
	BehaviorSchemaV2:     {},
}

var LegacyStateModelSchemas = map[string]struct{}{
	"evm-audit.state_model.v1": {},
	StateModelSchemaV2:         {},
}

// ProofOrder maps proof level identifiers to a comparable rank.
var ProofOrder = map[string]int{"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}

// SeverityMinProof maps a finding severity to the minimum acceptable proof level.
var SeverityMinProof = map[string]string{
	"critical":      "P4",
	"high":          "P3",
	"medium":        "P2",
	"low":           "P1",
	"info":          "P0",
	"informational": "P0",
}

var ValidScopes = map[string]struct{}{
	"function":       {},
	"contract":       {},
	"cross_function": {},
	"multi_tx":       {},
	"protocol":       {},
}

var ValidStatuses = map[string]struct{}{
	"confirmed_vulnerability":         {},
	"probable_vulnerability":          {},
	"suspicious_behavior":             {},
	"expected_protocol_behavior":      {},
	"informational_observation":       {},
	"suppressed_by_counter_evidence":  {},
	"analysis_inconclusive":           {},
}

var ValidWitnesses = map[string]struct{}{
	"none":                             {},
	"dataflow_trace":                   {},
	"reachable_path":                   {},
	"invariant_argument":               {},
	"symbolic_counterexample":          {},
	"fuzz_counterexample":              {},
	"transaction_sequence":             {},
	"deterministic_arithmetic_witness": {},
	"deterministic_accounting_witness": {},
}

var ValidConfidenceCapPolicies = map[string]struct{}{
	"min_required_input": {},
}

var ValidConfidenceInputs = map[string]struct{}{
	"function_coverage":                   {},
	"storage_role_confidence":             {},
	"path_reachability_confidence":        {},
	"external_call_resolution_confidence": {},
}

// RequiredAuditFields mirrors REQUIRED_AUDIT_FIELDS.
var RequiredAuditFields = []string{
	"schema", "schema_version", "engine_version", "ruleset_version",
	"bytecode_identity", "bytecode", "contract", "functions", "storage",
	"memory", "arithmetic", "calls", "events", "flows", "invariants",
	"assumptions", "analysis_warnings", "coverage", "state_model",
	"checker_findings",
}

var RequiredDetectorSections = []string{
	"schema", "schema_version", "rule", "intent", "requires",
	"counter_evidence", "proof", "analysis_requirements",
	"fixture_requirements", "reporting",
}

var RequiredRuleFields = []string{
	"id", "internal_name", "title", "category", "severity", "scope",
	"lifecycle_status", "default_status", "confidence_policy",
	"disallow_primary_evidence",
}

var RequiredIntentFields = []string{
	"vulnerability_class", "attack_thesis",
	"protected_asset_or_effect", "exploit_model",
}

var RequiredProofFields = []string{
	"min_level", "preferred_witness", "acceptable_witnesses",
	"witness_generation",
}

var RequiredAnalysisFields = []string{
	"min_function_coverage", "min_storage_role_confidence",
	"min_path_reachability_confidence",
	"max_unknown_action_expression_count", "max_unresolved_selector_count",
	"max_unresolved_paths", "require_no_unmodeled_terminators",
	"require_usable_primary_evidence",
}

var RequiredFixtureFields = []string{
	"corpus", "positive_fixtures_min", "negative_fixtures_min",
	"inconclusive_fixtures_min", "required_scenarios",
}

var RequiredReportingFields = []string{
	"title_template", "summary", "user_summary", "technical_summary",
	"exploit_narrative", "exploit_preconditions", "remediation_hints",
	"sarif",
}

var ProofAliases = map[string]string{
	"observation":             "P0",
	"dataflow":                "P1",
	"path_evidence":           "P2",
	"protocol_interpretation": "P3",
	"symbolic_counterexample": "P4",
}
