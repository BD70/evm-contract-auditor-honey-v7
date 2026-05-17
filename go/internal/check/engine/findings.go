package engine

import (
	"sort"

	chk "github.com/evm-auditor/evm-auditor/internal/check"
	"github.com/evm-auditor/evm-auditor/internal/check/policy"
	"github.com/evm-auditor/evm-auditor/internal/check/witness"
)

// BuildFunctionFinding mirrors evm_check.findings.build_function_finding.
func BuildFunctionFinding(audit, fn, rule, details map[string]any) map[string]any {
	meta := chk.AsMap(rule["rule"])
	proof := chk.AsMap(rule["proof"])
	reporting := chk.AsMap(rule["reporting"])
	coverageChecks := chk.AsMap(details["coverage_checks"])
	coverageOK := chk.AsBool(coverageChecks["matched"])
	wit, _ := details["witness"].(map[string]any)
	counter := chk.AsMap(details["counter_evidence"])

	proofLevel := chk.AsString(proof["min_level"])
	if wit != nil {
		proofLevel = "P4"
	}
	if proofLevel == "" {
		proofLevel = "P2"
	}

	defaultStatus := chk.AsString(meta["default_status"])
	if defaultStatus == "" {
		defaultStatus = policy.StatusProbable
	}
	status := policy.StatusFor(coverageOK, counter, wit, defaultStatus)
	confidence := policy.ConfidenceFor(meta, coverageChecks, wit, coverageOK)
	severity := policy.SeverityFor(chk.AsString(meta["severity"]), coverageOK, counter)

	return map[string]any{
		"rule_id":         meta["id"],
		"internal_name":   meta["internal_name"],
		"title":           meta["title"],
		"category":        meta["category"],
		"severity":        severity,
		"status":          status,
		"witness_status":  policy.WitnessStatusFor(status),
		"witness_goal":    rule["witness_goal"],
		"confidence":      confidence,
		"proof_level":     proofLevel,
		"scope":           meta["scope"],
		"function":        coalesceMap(fn["identity"]),
		"evidence": map[string]any{
			"actions":    actionRefs(fn),
			"flows":      coalesceListAny(fn["flows"]),
			"arithmetic": coalesceListAny(fn["arithmetic"]),
			"accounting": coalesceListAny(fn["accounting"]),
			"details":    details,
		},
		"counter_evidence_checked": counter,
		"counter_evidence":         coalesceMap(rule["counter_evidence"]),
		"exploit_preconditions":    coalesceListAny(reporting["exploit_preconditions"]),
		"summary":                  reporting["summary"],
		"user_summary":             reporting["user_summary"],
		"technical_summary":        reporting["technical_summary"],
		"exploit_narrative":        reporting["exploit_narrative"],
		"reporting":                reporting,
		"proof": map[string]any{
			"required":         proof,
			"required_witness": coalesceString(proof["preferred_witness"], "none"),
			"witness":          wit,
		},
	}
}

// BuildStatefulFinding mirrors evm_check.findings.build_stateful_finding.
func BuildStatefulFinding(audit, rule map[string]any, sequences []map[string]any, coverageChecks, counterResults map[string]any) map[string]any {
	meta := chk.AsMap(rule["rule"])
	reporting := chk.AsMap(rule["reporting"])
	wit := witness.Collect(audit, rule, map[string]any{"sequences": toAnyList(sequences)})
	coverageOK := chk.AsBool(coverageChecks["matched"])
	defaultStatus := chk.AsString(meta["default_status"])
	if defaultStatus == "" {
		defaultStatus = policy.StatusProbable
	}
	status := policy.StatusFor(coverageOK, counterResults, wit, defaultStatus)
	proofLevel := chk.AsString(chk.AsMap(rule["proof"])["min_level"])
	if wit != nil {
		proofLevel = "P4"
	}
	if proofLevel == "" {
		proofLevel = "P2"
	}
	return map[string]any{
		"rule_id":         meta["id"],
		"internal_name":   meta["internal_name"],
		"title":           meta["title"],
		"category":        meta["category"],
		"severity":        policy.SeverityFor(chk.AsString(meta["severity"]), coverageOK, counterResults),
		"status":          status,
		"witness_status":  policy.WitnessStatusFor(status),
		"witness_goal":    rule["witness_goal"],
		"confidence":      policy.ConfidenceFor(meta, coverageChecks, wit, coverageOK),
		"proof_level":     proofLevel,
		"scope":           meta["scope"],
		"function":        nil,
		"evidence": map[string]any{
			"sequences":       toAnyList(sequences),
			"state_model":     coalesceMap(audit["state_model"]),
			"coverage_checks": coverageChecks,
		},
		"counter_evidence_checked": counterResults,
		"counter_evidence":         coalesceMap(rule["counter_evidence"]),
		"exploit_preconditions":    coalesceListAny(reporting["exploit_preconditions"]),
		"summary":                  reporting["summary"],
		"user_summary":             reporting["user_summary"],
		"technical_summary":        reporting["technical_summary"],
		"exploit_narrative":        reporting["exploit_narrative"],
		"reporting":                reporting,
		"proof": map[string]any{
			"required":         coalesceMap(rule["proof"]),
			"required_witness": coalesceString(chk.AsMap(rule["proof"])["preferred_witness"], "none"),
			"witness":          wit,
		},
	}
}

// EvaluateSequenceCounterEvidence mirrors evm_check.findings.evaluate_sequence_counter_evidence.
func EvaluateSequenceCounterEvidence(sequences []map[string]any, rule, audit map[string]any) map[string]any {
	counter := chk.AsMap(rule["counter_evidence"])
	suppressTokens := chk.AsStringList(counter["suppress_if_any"])
	downgradeTokens := chk.AsStringList(counter["downgrade_if_any"])
	inconclusiveTokens := chk.AsStringList(counter["inconclusive_if_any"])

	catalog := map[string]struct{}{}
	if audit != nil {
		state := chk.AsMap(audit["state_model"])
		for _, e := range chk.AsList(state["guard_catalog"]) {
			entry := chk.AsMap(e)
			if id := chk.AsString(entry["id"]); id != "" {
				catalog[id] = struct{}{}
			}
			if t := chk.AsString(entry["type"]); t != "" {
				catalog[t] = struct{}{}
			}
		}
		for _, e := range chk.AsList(state["library_fingerprints"]) {
			if id := chk.AsString(chk.AsMap(e)["id"]); id != "" {
				catalog[id] = struct{}{}
			}
		}
		for _, e := range chk.AsList(state["proxy_index"]) {
			entry := chk.AsMap(e)
			if v := chk.AsString(entry["proxy_standard"]); v != "" {
				catalog[v] = struct{}{}
			}
			if v := chk.AsString(entry["slot_kind"]); v != "" {
				catalog[v] = struct{}{}
			}
		}
		for _, fnAny := range chk.AsList(audit["functions"]) {
			for _, t := range chk.AsStringList(chk.AsMap(fnAny)["behavior_tags"]) {
				catalog[t] = struct{}{}
			}
		}
	}

	suppressedBy := []string{}
	downgradedBy := []string{}
	inconclusiveBy := []string{}
	for _, sequence := range sequences {
		guards := map[string]struct{}{}
		for _, st := range chk.AsList(sequence["steps"]) {
			step := chk.AsMap(st)
			for _, ref := range stepGuardRefs(step) {
				guards[ref] = struct{}{}
			}
		}
		for k := range catalog {
			guards[k] = struct{}{}
		}
		suppressHit := tokensIn(suppressTokens, guards)
		downgradeHit := tokensIn(downgradeTokens, guards)
		inconclusiveHit := tokensIn(inconclusiveTokens, guards)
		if len(suppressHit) > 0 {
			sequence["suppressed_by"] = stringsToAny(suppressHit)
			suppressedBy = append(suppressedBy, suppressHit...)
		}
		if len(downgradeHit) > 0 {
			sequence["downgraded_by"] = stringsToAny(downgradeHit)
			downgradedBy = append(downgradedBy, downgradeHit...)
		}
		if len(inconclusiveHit) > 0 {
			sequence["inconclusive_by"] = stringsToAny(inconclusiveHit)
			inconclusiveBy = append(inconclusiveBy, inconclusiveHit...)
		}
	}
	return map[string]any{
		"suppressed_by":   stringsToAny(uniqSorted(suppressedBy)),
		"downgraded_by":   stringsToAny(uniqSorted(downgradedBy)),
		"inconclusive_by": stringsToAny(uniqSorted(inconclusiveBy)),
	}
}

func stepGuardRefs(step map[string]any) []string {
	refs := []string{}
	for _, key := range []string{"writer", "reader", "call"} {
		m := chk.AsMap(step[key])
		refs = append(refs, chk.AsStringList(m["guard_refs"])...)
	}
	return refs
}

func actionRefs(fn map[string]any) []any {
	out := []any{}
	for _, a := range chk.AsList(fn["actions"]) {
		action := chk.AsMap(a)
		out = append(out, map[string]any{
			"id":              action["id"],
			"type":            action["type"],
			"offset":          action["offset"],
			"block":           action["block"],
			"semantic_effect": action["semantic_effect"],
		})
	}
	return out
}

func tokensIn(tokens []string, set map[string]struct{}) []string {
	out := []string{}
	for _, t := range tokens {
		if _, ok := set[t]; ok {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	if len(out) > 1 {
		dedup := out[:1]
		for _, v := range out[1:] {
			if v != dedup[len(dedup)-1] {
				dedup = append(dedup, v)
			}
		}
		out = dedup
	}
	return out
}

func uniqSorted(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	for _, s := range items {
		seen[s] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func coalesceMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func coalesceString(v any, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}
