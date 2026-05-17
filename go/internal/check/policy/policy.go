// Package policy ports evm_check.policy: status, severity, confidence,
// coverage gates.
package policy

import (
	chk "github.com/evm-auditor/evm-auditor/internal/check"
)

const (
	StatusProbable     = "probable_vulnerability"
	StatusSuspicious   = "suspicious_behavior"
	StatusSuppressed   = "suppressed_by_counter_evidence"
	StatusInconclusive = "analysis_inconclusive"

	WitnessStatusNotAttempted = "not_attempted"
	WitnessStatusSuppressed   = "suppressed_by_counter_evidence"
	WitnessStatusInconclusive = "analysis_inconclusive"
)

// StatusFor mirrors evm_check.policy.status_for.
func StatusFor(coverageOK bool, counter map[string]any, witness map[string]any, defaultStatus string) string {
	if !coverageOK {
		return StatusInconclusive
	}
	if hasNonEmpty(counter, "suppressed_by") || hasNonEmpty(counter, "suppress_if_any") {
		return StatusSuppressed
	}
	if hasNonEmpty(counter, "inconclusive_if_any") || hasNonEmpty(counter, "inconclusive_by") {
		return StatusInconclusive
	}
	if hasNonEmpty(counter, "downgraded_by") || hasNonEmpty(counter, "downgrade_if_any") {
		return StatusSuspicious
	}
	if hasNonEmpty(counter, "manual_review_if_any") {
		return StatusSuspicious
	}
	if witness != nil || defaultStatus == StatusProbable || defaultStatus == "confirmed_vulnerability" {
		return defaultStatus
	}
	return StatusSuspicious
}

// ConfidenceFor mirrors evm_check.policy.confidence_for.
func ConfidenceFor(meta, coverageChecks map[string]any, witness map[string]any, coverageOK bool) float64 {
	cp := chk.AsMap(meta["confidence_policy"])
	base := chk.AsFloat(cp["base"], 0.6)
	var confidence float64
	switch {
	case !coverageOK:
		def := base - 0.25
		if def < 0.2 {
			def = 0.2
		}
		confidence = chk.AsFloat(cp["inconclusive"], def)
	case witness != nil:
		def := base + 0.2
		if def > 0.99 {
			def = 0.99
		}
		confidence = chk.AsFloat(cp["with_witness"], def)
	default:
		confidence = base
	}
	if cap, ok := ConfidenceCap(meta, coverageChecks); ok {
		if cap < confidence {
			return cap
		}
	}
	return confidence
}

// ConfidenceCap mirrors evm_check.policy.confidence_cap. Second return is false
// when no cap applies.
func ConfidenceCap(meta, coverageChecks map[string]any) (float64, bool) {
	if chk.AsString(meta["confidence_cap_policy"]) != "min_required_input" {
		return 0, false
	}
	inputs := chk.AsStringList(meta["required_confidence_inputs"])
	if len(inputs) == 0 {
		return 0, false
	}
	actual := chk.AsMap(coverageChecks["actual"])
	values := []float64{}
	for _, name := range inputs {
		if v, ok := actual[name]; ok {
			values = append(values, chk.AsFloat(v, 0))
		}
	}
	if len(values) == 0 {
		return 0, false
	}
	min := values[0]
	for _, v := range values[1:] {
		if v < min {
			min = v
		}
	}
	return min, true
}

// CoverageChecks mirrors evm_check.policy.coverage_checks.
func CoverageChecks(audit, rule map[string]any) map[string]any {
	coverage := chk.AsMap(audit["coverage"])
	analysis := chk.AsMap(rule["analysis_requirements"])
	actual := map[string]any{
		"function_coverage":                   chk.AsFloat(coverage["function_coverage"], 0),
		"unknown_action_expression_count":     chk.AsInt(coverage["unknown_action_expression_count"], 0),
		"unresolved_selector_count":           chk.AsInt(coverage["unresolved_selector_count"], 0),
		"unresolved_path_count":               chk.AsInt(coverage["unresolved_path_count"], 0),
		"storage_role_confidence":             chk.AsFloat(coverage["storage_role_confidence"], 1.0),
		"path_reachability_confidence":        chk.AsFloat(coverage["path_reachability_confidence"], 1.0),
		"external_call_resolution_confidence": chk.AsFloat(coverage["external_call_resolution_confidence"], 1.0),
		"has_unmodeled_terminators":           chk.AsBool(coverage["has_unmodeled_terminators"]),
	}
	failures := []string{}
	if actual["function_coverage"].(float64) < chk.AsFloat(analysis["min_function_coverage"], 0) {
		failures = append(failures, "function_coverage")
	}
	if actual["storage_role_confidence"].(float64) < chk.AsFloat(analysis["min_storage_role_confidence"], 0) {
		failures = append(failures, "storage_role_confidence")
	}
	if actual["path_reachability_confidence"].(float64) < chk.AsFloat(analysis["min_path_reachability_confidence"], 0) {
		failures = append(failures, "path_reachability_confidence")
	}
	if actual["unknown_action_expression_count"].(int) > chk.AsInt(analysis["max_unknown_action_expression_count"], 0) {
		failures = append(failures, "unknown_action_expression_count")
	}
	if actual["unresolved_selector_count"].(int) > chk.AsInt(analysis["max_unresolved_selector_count"], 0) {
		failures = append(failures, "unresolved_selector_count")
	}
	if actual["unresolved_path_count"].(int) > chk.AsInt(analysis["max_unresolved_paths"], 0) {
		failures = append(failures, "unresolved_path_count")
	}
	if chk.AsBool(analysis["require_no_unmodeled_terminators"]) && actual["has_unmodeled_terminators"].(bool) {
		failures = append(failures, "has_unmodeled_terminators")
	}
	failuresAny := make([]any, len(failures))
	for i, f := range failures {
		failuresAny[i] = f
	}
	return map[string]any{
		"matched":      len(failures) == 0,
		"requirements": analysis,
		"actual":       actual,
		"failures":     failuresAny,
	}
}

// WitnessStatusFor maps a finding status to a witness_status (no dynamic exec).
func WitnessStatusFor(status string) string {
	switch status {
	case StatusSuppressed:
		return WitnessStatusSuppressed
	case StatusInconclusive:
		return WitnessStatusInconclusive
	}
	return WitnessStatusNotAttempted
}

// SeverityFor mirrors evm_check.policy.severity_for.
func SeverityFor(severity string, coverageOK bool, counter map[string]any) string {
	sev := severity
	if sev == "" {
		sev = "warning"
	}
	sev = lower(sev)
	if !coverageOK {
		if sev == "critical" || sev == "high" {
			return "medium"
		}
		return sev
	}
	if hasNonEmpty(counter, "downgraded_by") || hasNonEmpty(counter, "downgrade_if_any") {
		if sev == "critical" || sev == "high" {
			return "medium"
		}
		return "low"
	}
	if hasNonEmpty(counter, "inconclusive_by") || hasNonEmpty(counter, "inconclusive_if_any") {
		if sev == "critical" || sev == "high" {
			return "medium"
		}
		return sev
	}
	if hasNonEmpty(counter, "manual_review_if_any") {
		if sev == "critical" || sev == "high" {
			return "medium"
		}
		return sev
	}
	return sev
}

func hasNonEmpty(m map[string]any, key string) bool {
	v, ok := m[key]
	if !ok || v == nil {
		return false
	}
	switch t := v.(type) {
	case []any:
		return len(t) > 0
	case []string:
		return len(t) > 0
	case string:
		return t != ""
	case bool:
		return t
	}
	return true
}

func lower(s string) string {
	out := []byte(s)
	for i, c := range out {
		if c >= 'A' && c <= 'Z' {
			out[i] = c + 32
		}
	}
	return string(out)
}
