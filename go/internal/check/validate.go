package check

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/evm-auditor/evm-auditor/pkg/schema"
)

// ValidateAudit mirrors evm_check.schema.validate_audit.
func ValidateAudit(audit map[string]any) []string {
	errors := []string{}

	schemaVal, _ := audit["schema"].(string)
	if _, ok := schema.LegacyBehaviorSchemas[schemaVal]; !ok {
		errors = append(errors, "schema must be one of: "+joinSortedSet(schema.LegacyBehaviorSchemas))
	}

	missing := []string{}
	for _, f := range schema.RequiredAuditFields {
		if _, ok := audit[f]; !ok {
			missing = append(missing, f)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		errors = append(errors, "missing required audit fields: "+strings.Join(missing, ", "))
	}

	if v, ok := audit["schema_version"]; ok && v != nil {
		ver := AsString(v)
		if ver == "" {
			ver = fmt.Sprintf("%v", v)
		}
		mj := majorOf(ver)
		if mj != "1" && mj != "2" {
			errors = append(errors, fmt.Sprintf("unsupported behavior schema major version: %v", v))
		}
	}

	if state, ok := audit["state_model"]; ok {
		stateMap, isMap := state.(map[string]any)
		if !isMap {
			errors = append(errors, "state_model must be an object")
		} else {
			ssch, _ := stateMap["schema"].(string)
			if _, ok := schema.LegacyStateModelSchemas[ssch]; !ok {
				errors = append(errors, "state_model.schema must be one of: "+joinSortedSet(schema.LegacyStateModelSchemas))
			}
			for _, f := range []string{
				"schema", "schema_version", "storage_entities", "slot_index",
				"path_index", "guard_catalog", "call_index", "economic_index",
				"proxy_index", "initializer_index", "evidence_index",
			} {
				if _, ok := stateMap[f]; !ok {
					errors = append(errors, "state_model missing "+f)
				}
			}
		}
	}
	return errors
}

// ValidateRule mirrors evm_check.schema.validate_rule.
func ValidateRule(rule map[string]any, root string) map[string]any {
	errors := []string{}
	warnings := []string{}

	missing := []string{}
	for _, s := range schema.RequiredDetectorSections {
		if _, ok := rule[s]; !ok {
			missing = append(missing, s)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		errors = append(errors, "detector missing required sections: "+strings.Join(missing, ", "))
	}

	if AsString(rule["schema"]) != schema.DetectorSchema {
		errors = append(errors, "detector schema must be "+schema.DetectorSchema)
	}
	if v, ok := rule["schema_version"]; ok && v != nil {
		ver := AsString(v)
		if !sameMajor(ver, schema.SupportedDetectorVer) {
			errors = append(errors, fmt.Sprintf("unsupported detector schema major version: %v", v))
		}
	}

	meta := AsMap(rule["rule"])
	intent := AsMap(rule["intent"])
	requires := AsMap(rule["requires"])
	counter := rule["counter_evidence"]
	proof := AsMap(rule["proof"])
	analysis := AsMap(rule["analysis_requirements"])
	fixtures := AsMap(rule["fixture_requirements"])
	reporting := AsMap(rule["reporting"])

	requireFields("rule", meta, schema.RequiredRuleFields, &errors)
	requireFields("intent", intent, schema.RequiredIntentFields, &errors)
	requireFields("proof", proof, schema.RequiredProofFields, &errors)
	requireFields("analysis_requirements", analysis, schema.RequiredAnalysisFields, &errors)
	requireFields("fixture_requirements", fixtures, schema.RequiredFixtureFields, &errors)
	requireFields("reporting", reporting, schema.RequiredReportingFields, &errors)

	disallowed := SetFromList(meta["disallow_primary_evidence"])
	if _, ok := disallowed["function_name"]; !ok {
		errors = append(errors, "detector must disallow function_name and selector as primary evidence")
	} else if _, ok := disallowed["selector"]; !ok {
		errors = append(errors, "detector must disallow function_name and selector as primary evidence")
	}

	severity := strings.ToLower(AsString(meta["severity"]))
	if severity == "" {
		severity = "warning"
	}
	minRequired, ok := schema.SeverityMinProof[severity]
	if !ok {
		minRequired = "P2"
	}
	declaredRaw := AsString(proof["min_level"])
	if declaredRaw == "" {
		declaredRaw = "P2"
	}
	declared := normalizeProof(declaredRaw)
	if _, ok := schema.ProofOrder[declaredRaw]; !ok {
		errors = append(errors, "proof.min_level must be one of P0, P1, P2, P3, P4")
	}
	preferredWitness := AsString(proof["preferred_witness"])
	if preferredWitness == "" {
		preferredWitness = "none"
	}
	witnessesAny, hasWitnesses := proof["acceptable_witnesses"]
	witnesses := AsStringList(witnessesAny)
	if _, ok := schema.ValidWitnesses[preferredWitness]; !ok {
		errors = append(errors, "invalid proof.preferred_witness: "+preferredWitness)
	}
	if !hasWitnesses {
		errors = append(errors, "proof.acceptable_witnesses must be a non-empty list")
	} else if _, isList := witnessesAny.([]any); !isList || len(witnesses) == 0 {
		errors = append(errors, "proof.acceptable_witnesses must be a non-empty list")
	} else {
		invalid := []string{}
		for _, w := range witnesses {
			if _, ok := schema.ValidWitnesses[w]; !ok {
				invalid = append(invalid, w)
			}
		}
		sort.Strings(invalid)
		if len(invalid) > 0 {
			errors = append(errors, "invalid acceptable witnesses: "+strings.Join(invalid, ", "))
		}
	}
	if order(declared) < order(minRequired) {
		errors = append(errors, fmt.Sprintf("%s severity requires at least %s, got %s", severity, minRequired, declared))
	}
	witSet := map[string]struct{}{}
	for _, w := range witnesses {
		witSet[w] = struct{}{}
	}
	if _, ok := witSet[preferredWitness]; !ok {
		errors = append(errors, "proof.preferred_witness must be included in proof.acceptable_witnesses")
	}

	status := AsString(meta["default_status"])
	if status == "" {
		status = "probable_vulnerability"
	}
	if _, ok := schema.ValidStatuses[status]; !ok {
		errors = append(errors, "invalid rule.default_status: "+status)
	}
	scope := AsString(meta["scope"])
	if _, ok := schema.ValidScopes[scope]; !ok {
		errors = append(errors, "invalid rule.scope: "+scope)
	}

	confidencePolicyAny, hasCP := meta["confidence_policy"]
	confidencePolicy, isMap := confidencePolicyAny.(map[string]any)
	if !hasCP || !isMap {
		errors = append(errors, "rule.confidence_policy must be an object")
	} else {
		for _, f := range []string{"base", "with_witness", "inconclusive"} {
			if _, ok := confidencePolicy[f]; !ok {
				errors = append(errors, "rule.confidence_policy missing "+f)
			}
		}
	}

	confidenceCapPolicy, hasCap := meta["confidence_cap_policy"]
	requiredConfidenceInputs, hasInputs := meta["required_confidence_inputs"]
	if hasCap && confidenceCapPolicy != nil {
		capStr := AsString(confidenceCapPolicy)
		if _, ok := schema.ValidConfidenceCapPolicies[capStr]; !ok {
			errors = append(errors, "rule.confidence_cap_policy must be one of: "+joinSortedSet(schema.ValidConfidenceCapPolicies))
		}
		inputs := AsStringList(requiredConfidenceInputs)
		_, isList := requiredConfidenceInputs.([]any)
		if !isList || len(inputs) == 0 {
			errors = append(errors, "rule.required_confidence_inputs must be a non-empty list when confidence_cap_policy is set")
		} else {
			invalid := []string{}
			for _, v := range inputs {
				if _, ok := schema.ValidConfidenceInputs[v]; !ok {
					invalid = append(invalid, v)
				}
			}
			sort.Strings(invalid)
			if len(invalid) > 0 {
				errors = append(errors, "invalid rule.required_confidence_inputs: "+strings.Join(invalid, ", "))
			}
		}
	} else if hasInputs && requiredConfidenceInputs != nil {
		errors = append(errors, "rule.required_confidence_inputs requires rule.confidence_cap_policy")
	}

	counterMap, isMap := counter.(map[string]any)
	if !isMap {
		errors = append(errors, "counter_evidence must be an object")
	} else {
		for _, f := range []string{"suppress_if_any", "downgrade_if_any", "inconclusive_if_any", "manual_review_if_any"} {
			if _, ok := counterMap[f]; !ok {
				errors = append(errors, "counter_evidence missing "+f)
			}
		}
	}

	if v, ok := analysis["require_usable_primary_evidence"]; ok {
		if _, isBool := v.(bool); !isBool {
			errors = append(errors, "analysis_requirements.require_usable_primary_evidence must be a boolean")
		}
	}

	if scope == "multi_tx" || scope == "cross_function" || scope == "protocol" {
		seqAny := requires["sequence"]
		seq, isList := seqAny.([]any)
		if !isList || len(seq) < 2 {
			errors = append(errors, fmt.Sprintf("%s detector requires a sequence with at least two steps", scope))
		} else {
			validateSequence(seq, &errors)
		}
	}

	if scope == "multi_tx" || scope == "cross_function" {
		stateful, ok := requires["stateful"]
		if ok {
			if b, isBool := stateful.(bool); isBool && !b {
				errors = append(errors, "stateful cross-function or multi-tx detectors must set requires.stateful=true")
			}
		}
	}

	if !hasRealAnalysisThresholds(analysis) {
		errors = append(errors, "analysis_requirements are too permissive for production detectors")
	}

	if AsInt(fixtures["positive_fixtures_min"], 0) < 1 {
		errors = append(errors, "fixture_requirements.positive_fixtures_min must be at least 1")
	}
	if AsInt(fixtures["negative_fixtures_min"], 0) < 1 {
		errors = append(errors, "fixture_requirements.negative_fixtures_min must be at least 1")
	}
	if AsInt(fixtures["inconclusive_fixtures_min"], 0) < 1 {
		errors = append(errors, "fixture_requirements.inconclusive_fixtures_min must be at least 1")
	}
	scenarios, _ := fixtures["required_scenarios"].([]any)
	if len(scenarios) == 0 {
		errors = append(errors, "fixture_requirements.required_scenarios must not be empty")
	}

	if root != "" {
		corpusRel := AsString(fixtures["corpus"])
		corpusPath := filepath.Join(root, corpusRel)
		if _, err := os.Stat(corpusPath); err != nil {
			errors = append(errors, "declared corpus does not exist: "+corpusPath)
		}
	}

	if !hasEffectRequirement(requires) {
		errors = append(errors, "detector requires at least one sensitive effect constraint")
	}

	_ = intent
	return map[string]any{
		"schema":   schema.RuleValidationSchema,
		"ok":       len(errors) == 0,
		"errors":   errors,
		"warnings": warnings,
	}
}

// ValidateCorpus mirrors evm_check.schema.validate_corpus.
func ValidateCorpus(manifest map[string]any, expectedRuleID string) map[string]any {
	errors := []string{}
	if AsString(manifest["schema"]) != schema.CorpusSchema {
		errors = append(errors, "corpus schema must be "+schema.CorpusSchema)
	}
	if v, ok := manifest["schema_version"]; ok && v != nil {
		if !sameMajor(AsString(v), schema.SupportedCorpusVer) {
			errors = append(errors, fmt.Sprintf("unsupported corpus schema major version: %v", v))
		}
	}
	cases, isList := manifest["cases"].([]any)
	if !isList {
		errors = append(errors, "corpus must include a cases list")
	}
	if _, ok := manifest["metrics"].(map[string]any); !ok {
		errors = append(errors, "corpus must include a metrics object")
	}
	if _, ok := manifest["scenario_taxonomy"]; !ok {
		errors = append(errors, "corpus must include scenario_taxonomy")
	}
	for _, ca := range cases {
		caseMap, _ := ca.(map[string]any)
		for _, f := range []string{"id", "audit_json", "expectation"} {
			if _, ok := caseMap[f]; !ok {
				errors = append(errors, fmt.Sprintf("corpus case missing %s: %v", f, ca))
			}
		}
		expectation := AsMap(caseMap["expectation"])
		kind := AsString(expectation["kind"])
		if kind != "positive" && kind != "negative" && kind != "inconclusive" {
			errors = append(errors, fmt.Sprintf("invalid expectation.kind for case %v", caseMap["id"]))
		}
		ids := AsStringList(expectation["rule_ids"])
		if expectedRuleID != "" {
			found := false
			for _, id := range ids {
				if id == expectedRuleID {
					found = true
					break
				}
			}
			if !found {
				errors = append(errors, fmt.Sprintf("case %v does not validate detector %s", caseMap["id"], expectedRuleID))
			}
		}
	}
	return map[string]any{
		"schema": "evm-audit.corpus_validation",
		"ok":     len(errors) == 0,
		"errors": errors,
	}
}

func validateSequence(sequence []any, errors *[]string) {
	bindings := map[string]struct{}{}
	sawJoin := false
	for idx, stepAny := range sequence {
		i := idx + 1
		step, _ := stepAny.(map[string]any)
		if AsString(step["id"]) == "" {
			*errors = append(*errors, fmt.Sprintf("sequence step %d missing id", i))
		}
		match, isMap := step["match"].(map[string]any)
		if !isMap {
			*errors = append(*errors, fmt.Sprintf("sequence step %d missing match object", i))
			continue
		}
		bind := AsMap(step["bind"])
		for _, v := range bind {
			if s, ok := v.(string); ok && strings.HasPrefix(s, "$") {
				bindings[s] = struct{}{}
			}
		}
		joinFields := []string{"same_slot_as", "same_guard_as", "same_delegate_target_as", "same_call_target_as"}
		for _, jf := range joinFields {
			if joinUsesBinding(match, jf) {
				sawJoin = true
			}
		}
		if stepNeedsBinding(match) && i > 1 {
			anyJoin := false
			for _, jf := range joinFields {
				if joinUsesBinding(match, jf) {
					anyJoin = true
					break
				}
			}
			if !anyJoin {
				*errors = append(*errors, fmt.Sprintf("sequence step %d must join to a previous binding", i))
			}
		}
	}
	if len(bindings) > 0 && !sawJoin {
		*errors = append(*errors, "sequence binds variables but never reuses them in a join")
	}
	if len(bindings) == 0 {
		*errors = append(*errors, "sequence requires explicit bind variables for state joins")
	}
}

func joinUsesBinding(match map[string]any, joinField string) bool {
	for _, v := range match {
		if mp, ok := v.(map[string]any); ok {
			if jv, ok := mp[joinField].(string); ok && strings.HasPrefix(jv, "$") {
				return true
			}
		}
	}
	return false
}

func stepNeedsBinding(match map[string]any) bool {
	for _, k := range []string{"storage_read", "storage_write", "delegatecall", "proxy_write", "authorization_state", "external_call"} {
		if _, ok := match[k]; ok {
			return true
		}
	}
	return false
}

func hasRealAnalysisThresholds(a map[string]any) bool {
	return AsFloat(a["min_function_coverage"], 0) >= 0.5 &&
		AsFloat(a["min_storage_role_confidence"], 0) >= 0.5 &&
		AsFloat(a["min_path_reachability_confidence"], 0) >= 0.5 &&
		AsInt(a["max_unknown_action_expression_count"], 1_000_000) < 1_000_000 &&
		AsInt(a["max_unresolved_selector_count"], 1_000_000) < 1_000_000 &&
		AsInt(a["max_unresolved_paths"], 1_000_000) < 1_000_000
}

func hasEffectRequirement(requires map[string]any) bool {
	for _, key := range []string{"reachable_effect_any", "authorized_path_effect_any", "economic_effect_any"} {
		if list, ok := requires[key].([]any); ok && len(list) > 0 {
			return true
		}
	}
	if seq, ok := requires["sequence"].([]any); ok {
		for _, st := range seq {
			step, _ := st.(map[string]any)
			match := AsMap(step["match"])
			for _, key := range []string{"reachable_effect_any", "authorized_path_effect_any", "economic_effect_any"} {
				if list, ok := match[key].([]any); ok && len(list) > 0 {
					return true
				}
			}
		}
	}
	if ext, ok := requires["external_call"].(map[string]any); ok {
		if list, ok := ext["return_flow_effect_any"].([]any); ok && len(list) > 0 {
			return true
		}
	}
	return false
}

func requireFields(prefix string, obj map[string]any, required []string, errors *[]string) {
	if obj == nil {
		*errors = append(*errors, prefix+" must be an object")
		return
	}
	missing := []string{}
	for _, f := range required {
		if _, ok := obj[f]; !ok {
			missing = append(missing, f)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		*errors = append(*errors, prefix+" missing required fields: "+strings.Join(missing, ", "))
	}
}

func sameMajor(a, b string) bool { return majorOf(a) == majorOf(b) }

func majorOf(v string) string {
	for i := 0; i < len(v); i++ {
		if v[i] == '.' {
			return v[:i]
		}
	}
	return v
}

func order(level string) int {
	if v, ok := schema.ProofOrder[level]; ok {
		return v
	}
	return -1
}

func normalizeProof(value string) string {
	if alias, ok := schema.ProofAliases[value]; ok {
		return alias
	}
	if _, ok := schema.ProofOrder[value]; ok {
		return value
	}
	return "P2"
}

func joinSortedSet(s map[string]struct{}) string {
	keys := make([]string, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}
