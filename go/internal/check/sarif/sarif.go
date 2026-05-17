// Package sarif renders checker findings as SARIF 2.1.0.
package sarif

import (
	"sort"

	chk "github.com/evm-auditor/evm-auditor/internal/check"
)

// ToSARIF mirrors evm_check.sarif.to_sarif.
func ToSARIF(checkResult map[string]any) map[string]any {
	rules := map[string]map[string]any{}
	results := []any{}

	findings := chk.AsList(checkResult["findings"])
	for _, fAny := range findings {
		finding := chk.AsMap(fAny)
		ruleID := chk.AsString(finding["rule_id"])
		if ruleID == "" {
			ruleID = "evm.unknown"
		}
		if _, ok := rules[ruleID]; !ok {
			rules[ruleID] = map[string]any{
				"id":               ruleID,
				"name":             coalesce(finding["title"], ruleID),
				"shortDescription": map[string]any{"text": coalesce(finding["title"], ruleID)},
				"properties": map[string]any{
					"category":    finding["category"],
					"severity":    finding["severity"],
					"status":      finding["status"],
					"proof_level": finding["proof_level"],
				},
			}
		}
		fn := chk.AsMap(finding["function"])
		witnessGoal := chk.AsMap(finding["witness_goal"])
		successCondition := chk.AsString(witnessGoal["success_condition"])
		messageText := coalesce(finding["title"], ruleID)
		if successCondition != "" {
			messageText = messageText + " — Proof goal: " + successCondition
		}
		results = append(results, map[string]any{
			"ruleId":    ruleID,
			"level":     levelFor(chk.AsString(finding["severity"])),
			"message":   map[string]any{"text": messageText},
			"locations": locationsFor(finding),
			"properties": map[string]any{
				"status":                finding["status"],
				"witness_status":        finding["witness_status"],
				"severity":              finding["severity"],
				"confidence":            finding["confidence"],
				"proof_level":           finding["proof_level"],
				"internal_name":         finding["internal_name"],
				"selector":              fn["selector"],
				"function":              fn["name"],
				"scope":                 finding["scope"],
				"evidence":              coalesceMap(finding["evidence"]),
				"witness":               chk.AsMap(finding["proof"])["witness"],
				"witness_goal":          witnessGoalOrNil(witnessGoal),
				"counter_evidence":      coalesceMap(finding["counter_evidence"]),
				"exploit_preconditions": coalesceList(finding["exploit_preconditions"]),
			},
		})
	}

	ruleList := []map[string]any{}
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}
	// Python preserves dict insertion order; replicate by sorting on rule id for determinism.
	sort.Slice(ruleList, func(i, j int) bool {
		return chk.AsString(ruleList[i]["id"]) < chk.AsString(ruleList[j]["id"])
	})
	ruleListAny := make([]any, len(ruleList))
	for i, r := range ruleList {
		ruleListAny[i] = r
	}

	return map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{
				"driver": map[string]any{
					"name":  "evm-audit",
					"rules": ruleListAny,
				},
			},
			"results": results,
		}},
	}
}

func levelFor(severity string) string {
	switch lower(severity) {
	case "critical", "high":
		return "error"
	case "medium", "warning":
		return "warning"
	case "low", "info", "informational":
		return "note"
	}
	return "none"
}

func locationsFor(finding map[string]any) []any {
	fn := chk.AsMap(finding["function"])
	logical := []any{}
	selector := chk.AsString(fn["selector"])
	if selector != "" {
		logical = append(logical, map[string]any{"name": "function:" + selector, "kind": "function"})
	}
	evidence := chk.AsMap(finding["evidence"])
	slotRefs := []string{}
	for _, sa := range chk.AsList(evidence["sequences"]) {
		seq := chk.AsMap(sa)
		for _, sr := range chk.AsList(seq["slot_refs"]) {
			slotRefs = append(slotRefs, chk.AsString(sr))
		}
		for _, st := range chk.AsList(seq["steps"]) {
			step := chk.AsMap(st)
			if v := chk.AsString(step["slot"]); v != "" {
				slotRefs = append(slotRefs, v)
			}
		}
	}
	if len(slotRefs) > 0 {
		uniq := uniqSorted(slotRefs)
		for _, slot := range uniq {
			logical = append(logical, map[string]any{"name": "storage-slot:" + slot, "kind": "object"})
		}
	}
	return []any{map[string]any{
		"physicalLocation": map[string]any{
			"artifactLocation": map[string]any{"uri": "bytecode:metadata_stripped_keccak256:unknown"},
			"region":           map[string]any{"startLine": 1, "startColumn": 1},
		},
		"logicalLocations": logical,
	}}
}

func witnessGoalOrNil(wg map[string]any) any {
	if len(wg) == 0 {
		return nil
	}
	return wg
}

func coalesce(v any, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}

func coalesceMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func coalesceList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return []any{}
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

func uniqSorted(items []string) []string {
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
