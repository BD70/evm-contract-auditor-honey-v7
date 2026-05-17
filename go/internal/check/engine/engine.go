// Package engine ports evm_check.engine: detector matcher (function + stateful).
package engine

import (
	"encoding/json"
	"sort"

	chk "github.com/evm-auditor/evm-auditor/internal/check"
	"github.com/evm-auditor/evm-auditor/internal/check/policy"
	"github.com/evm-auditor/evm-auditor/internal/check/witness"
)

// Result mirrors the Python checker output shape.
type Result struct {
	Schema             string           `json:"schema"`
	SchemaVersion      string           `json:"schema_version"`
	AuditSchema        any              `json:"audit_schema"`
	AuditSchemaVersion any              `json:"audit_schema_version"`
	RulesLoaded        int              `json:"rules_loaded"`
	Findings           []map[string]any `json:"findings"`
	Trace              []map[string]any `json:"trace"`
}

// CheckAudit mirrors evm_check.engine.check_audit. Returns the checker result
// dict ready for JSON marshaling.
func CheckAudit(audit map[string]any, rules []map[string]any) (map[string]any, error) {
	auditErrors := chk.ValidateAudit(audit)
	if len(auditErrors) > 0 {
		return nil, validationError(auditErrors)
	}

	findings := []map[string]any{}
	trace := []map[string]any{}
	for _, rule := range rules {
		validation := chk.ValidateRule(rule, "")
		if !validation["ok"].(bool) {
			rid := chk.AsString(chk.AsMap(rule["rule"])["id"])
			if rid == "" {
				rid = "<unknown>"
			}
			errs := validation["errors"].([]string)
			return nil, validationDetail(rid, errs)
		}
		ruleFindings, ruleTrace := evaluateRule(audit, rule)
		findings = append(findings, ruleFindings...)
		trace = append(trace, ruleTrace...)
	}

	return map[string]any{
		"schema":               "evm-audit.checker",
		"schema_version":       "1.0.0",
		"audit_schema":         audit["schema"],
		"audit_schema_version": audit["schema_version"],
		"rules_loaded":         len(rules),
		"findings":             toAnyList(findings),
		"trace":                toAnyList(trace),
	}, nil
}

func evaluateRule(audit, rule map[string]any) ([]map[string]any, []map[string]any) {
	scope := chk.AsString(chk.AsMap(rule["rule"])["scope"])
	if scope == "contract" || scope == "cross_function" || scope == "multi_tx" || scope == "protocol" {
		return evaluateStatefulRule(audit, rule)
	}

	findings := []map[string]any{}
	trace := []map[string]any{}
	for _, fnAny := range chk.AsList(audit["functions"]) {
		fn := chk.AsMap(fnAny)
		matched, details := matchFunction(audit, fn, rule)
		ruleID := chk.AsString(chk.AsMap(rule["rule"])["id"])
		identity := chk.AsMap(fn["identity"])
		trace = append(trace, map[string]any{
			"rule_id":  ruleID,
			"function": identity["selector"],
			"matched":  matched,
			"details":  details,
		})
		if matched {
			findings = append(findings, BuildFunctionFinding(audit, fn, rule, details))
		}
	}
	return findings, trace
}

func matchFunction(audit, fn, rule map[string]any) (bool, map[string]any) {
	requires := chk.AsMap(rule["requires"])
	requireUsable := requireUsablePrimaryEvidence(rule)
	tags := functionTags(fn)
	for k := range globalTags(audit) {
		tags[k] = struct{}{}
	}

	identity := chk.AsMap(fn["identity"])
	fnSelector := identity["selector"]
	state := chk.AsMap(audit["state_model"])
	for _, p := range chk.AsList(state["path_index"]) {
		entry := chk.AsMap(p)
		if entry["function"] == fnSelector {
			for _, g := range chk.AsStringList(entry["guard_refs"]) {
				tags[g] = struct{}{}
			}
		}
	}
	for _, c := range chk.AsList(state["guard_catalog"]) {
		entry := chk.AsMap(c)
		if entry["function"] != fnSelector {
			continue
		}
		if gid := chk.AsString(entry["id"]); gid != "" {
			tags[gid] = struct{}{}
		}
		if gtype := chk.AsString(entry["type"]); gtype != "" {
			tags[gtype] = struct{}{}
		}
	}

	required := chk.SetFromList(requires["facts_all"])
	missing := []string{}
	for tag := range required {
		if _, ok := tags[tag]; !ok {
			missing = append(missing, tag)
		}
	}
	sort.Strings(missing)
	counter := chk.AsMap(rule["counter_evidence"])
	forbidden := counterTagsHit(tags, chk.AsStringList(counter["suppress_if_any"]))
	flowChecks := matchFlows(fn, chk.AsList(requires["flows_all"]))
	arithmeticChecks := matchArithmetic(fn, rule, requireUsable)
	effectChecks := matchFunctionEffects(fn, requires)
	coverageResults := policy.CoverageChecks(audit, rule)
	counterEvidence := counterEvidenceDetails(tags, rule)
	wit := witness.Collect(audit, rule, map[string]any{
		"function": fn,
		"effects":  effectChecks,
	})

	matched := len(missing) == 0 && len(forbidden) == 0 &&
		flowChecks["matched"].(bool) &&
		arithmeticChecks["matched"].(bool) &&
		effectChecks["matched"].(bool)

	return matched, map[string]any{
		"required_facts":    chk.SortedSet(required),
		"available_facts":   chk.SortedSet(tags),
		"missing_facts":     stringsToAny(missing),
		"suppressed_by":     stringsToAny(forbidden),
		"flow_checks":       flowChecks,
		"arithmetic_checks": arithmeticChecks,
		"effect_checks":     effectChecks,
		"coverage_checks":   coverageResults,
		"counter_evidence":  counterEvidence,
		"witness":           wit,
	}
}

func evaluateStatefulRule(audit, rule map[string]any) ([]map[string]any, []map[string]any) {
	requires := chk.AsMap(rule["requires"])
	state := chk.AsMap(audit["state_model"])
	ruleMeta := chk.AsMap(rule["rule"])
	ruleID := chk.AsString(ruleMeta["id"])
	scope := chk.AsString(ruleMeta["scope"])

	allTags := globalTags(audit)
	for _, fnAny := range chk.AsList(audit["functions"]) {
		for k := range functionTags(chk.AsMap(fnAny)) {
			allTags[k] = struct{}{}
		}
	}
	requiredFacts := chk.SetFromList(requires["facts_all"])
	missingFacts := []string{}
	for tag := range requiredFacts {
		if _, ok := allTags[tag]; !ok {
			missingFacts = append(missingFacts, tag)
		}
	}
	sort.Strings(missingFacts)
	if len(missingFacts) > 0 {
		return nil, []map[string]any{{
			"rule_id": ruleID,
			"scope":   scope,
			"matched": false,
			"details": map[string]any{"missing_facts": stringsToAny(missingFacts)},
		}}
	}

	authEffects := chk.SetFromList(requires["authorized_path_effect_any"])
	if len(authEffects) > 0 {
		contractEffects := map[string]struct{}{}
		for _, fnAny := range chk.AsList(audit["functions"]) {
			for k := range functionEffects(chk.AsMap(fnAny)) {
				contractEffects[k] = struct{}{}
			}
		}
		for _, slot := range chk.AsList(state["slot_index"]) {
			for k := range slotEffects(chk.AsMap(slot)) {
				contractEffects[k] = struct{}{}
			}
		}
		for _, callAny := range chk.AsList(state["call_index"]) {
			call := chk.AsMap(callAny)
			if chk.AsString(call["kind"]) == "delegatecall" {
				contractEffects["delegatecall"] = struct{}{}
			}
			for _, e := range chk.AsStringList(call["reachable_effects"]) {
				contractEffects[e] = struct{}{}
			}
			for _, e := range chk.AsStringList(call["return_flow_effects"]) {
				contractEffects[e] = struct{}{}
			}
		}
		for _, st := range chk.AsList(requires["sequence"]) {
			match := chk.AsMap(chk.AsMap(st)["match"])
			if _, ok := match["delegatecall"]; ok {
				contractEffects["delegatecall"] = struct{}{}
			}
		}
		if !chk.IntersectAny(authEffects, contractEffects) {
			return nil, []map[string]any{{
				"rule_id": ruleID,
				"scope":   scope,
				"matched": false,
				"details": map[string]any{
					"missing_authorized_effects": stringsToAny(chk.SortedSet(authEffects)),
				},
			}}
		}
	}

	matchedSequences := matchSequences(audit, rule, state)
	coverageResults := policy.CoverageChecks(audit, rule)
	counterResults := EvaluateSequenceCounterEvidence(matchedSequences, rule, audit)

	filtered := []map[string]any{}
	for _, seq := range matchedSequences {
		if len(chk.AsStringList(seq["suppressed_by"])) == 0 {
			filtered = append(filtered, seq)
		}
	}
	matched := len(filtered) > 0
	trace := []map[string]any{{
		"rule_id": ruleID,
		"scope":   scope,
		"matched": matched,
		"details": map[string]any{
			"sequences":        toAnyList(matchedSequences),
			"counter_evidence": counterResults,
			"coverage_checks":  coverageResults,
		},
	}}
	if !matched {
		return nil, trace
	}
	finding := BuildStatefulFinding(audit, rule, filtered, coverageResults, counterResults)
	return []map[string]any{finding}, trace
}

func matchSequences(audit, rule, state map[string]any) []map[string]any {
	requires := chk.AsMap(rule["requires"])
	sequence := chk.AsList(requires["sequence"])
	requireUsable := requireUsablePrimaryEvidence(rule)
	if len(sequence) == 0 {
		return matchContractPredicates(audit, rule, state, requireUsable)
	}
	contexts := []map[string]any{newContext()}
	for _, stepAny := range sequence {
		step := chk.AsMap(stepAny)
		next := []map[string]any{}
		for _, ctx := range contexts {
			matches := matchStep(step, state, ctx, requireUsable)
			next = append(next, matches...)
		}
		contexts = next
	}
	return contexts
}

func newContext() map[string]any {
	return map[string]any{
		"bindings":              map[string]any{},
		"steps":                 []any{},
		"slot_refs":             []any{},
		"guard_refs":            []any{},
		"delegate_target_refs":  []any{},
	}
}

func matchContractPredicates(audit, rule, state map[string]any, requireUsable bool) []map[string]any {
	predicates := chk.AsMap(rule["requires"])
	matches := []map[string]any{}
	hasStructural := false
	if _, ok := predicates["storage_write"]; ok {
		hasStructural = true
	}
	if _, ok := predicates["external_call"]; ok {
		hasStructural = true
	}

	for _, slotAny := range chk.AsList(state["slot_index"]) {
		slot := chk.AsMap(slotAny)
		writeConstraint := chk.AsMap(predicates["storage_write"])
		if !matchSlotConstraint(slot, writeConstraint, map[string]any{}, requireUsable) {
			continue
		}
		if len(writeConstraint) > 0 {
			anyOk := false
			for _, w := range chk.AsList(slot["writers"]) {
				if matchWriter(chk.AsMap(w), writeConstraint) {
					anyOk = true
					break
				}
			}
			if !anyOk {
				continue
			}
		}
		effects := chk.AsStringList(predicates["reachable_effect_any"])
		if len(effects) > 0 {
			se := slotEffects(slot)
			ok := false
			for _, e := range effects {
				if _, has := se[e]; has {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}
		matches = append(matches, map[string]any{
			"bindings": map[string]any{"$slot": slot["slot"]},
			"steps": []any{map[string]any{
				"id":      "contract_predicate",
				"slot":    slot["slot"],
				"writers": coalesceListAny(slot["writers"]),
			}},
			"slot_refs":            []any{slot["slot"]},
			"guard_refs":           coalesceListAny(slot["guards"]),
			"delegate_target_refs": []any{},
		})
	}

	if extConstraint, ok := predicates["external_call"].(map[string]any); ok && len(extConstraint) > 0 {
		effects := chk.AsStringList(predicates["reachable_effect_any"])
		for _, callAny := range chk.AsList(state["call_index"]) {
			call := chk.AsMap(callAny)
			if !matchExternalCall(call, extConstraint, predicates, map[string]any{}, requireUsable) {
				continue
			}
			callEffects := map[string]struct{}{}
			for _, e := range chk.AsStringList(call["return_flow_effects"]) {
				callEffects[e] = struct{}{}
			}
			for _, e := range chk.AsStringList(call["reachable_effects"]) {
				callEffects[e] = struct{}{}
			}
			if len(effects) > 0 {
				ok := false
				for _, e := range effects {
					if _, has := callEffects[e]; has {
						ok = true
						break
					}
				}
				if !ok {
					continue
				}
			}
			matches = append(matches, map[string]any{
				"bindings": map[string]any{"$target": call["target"]},
				"steps": []any{map[string]any{
					"id":          "contract_predicate",
					"call_target": call["target"],
					"call":        call,
				}},
				"slot_refs":            []any{},
				"guard_refs":           coalesceListAny(call["guard_refs"]),
				"delegate_target_refs": []any{},
			})
		}
	}

	if len(matches) == 0 && !hasStructural {
		requiredEffects := chk.SetFromList(predicates["reachable_effect_any"])
		contractEffects := map[string]struct{}{}
		for _, fnAny := range chk.AsList(audit["functions"]) {
			for k := range functionEffects(chk.AsMap(fnAny)) {
				contractEffects[k] = struct{}{}
			}
		}
		for _, slot := range chk.AsList(state["slot_index"]) {
			for k := range slotEffects(chk.AsMap(slot)) {
				contractEffects[k] = struct{}{}
			}
		}
		for _, callAny := range chk.AsList(state["call_index"]) {
			call := chk.AsMap(callAny)
			for _, e := range chk.AsStringList(call["reachable_effects"]) {
				contractEffects[e] = struct{}{}
			}
		}
		if len(requiredEffects) == 0 || chk.IntersectAny(requiredEffects, contractEffects) {
			allGuards := []any{}
			for _, slot := range chk.AsList(state["slot_index"]) {
				for _, g := range chk.AsList(chk.AsMap(slot)["guards"]) {
					allGuards = append(allGuards, g)
				}
			}
			matches = append(matches, map[string]any{
				"bindings":             map[string]any{},
				"steps":                []any{map[string]any{"id": "contract_level_fact_match"}},
				"slot_refs":            []any{},
				"guard_refs":           allGuards,
				"delegate_target_refs": []any{},
			})
		}
	}
	return matches
}

func matchStep(step, state, context map[string]any, requireUsable bool) []map[string]any {
	match := chk.AsMap(step["match"])
	bindings := chk.AsMap(context["bindings"])
	results := []map[string]any{}

	if c, ok := match["storage_write"].(map[string]any); ok {
		for _, slotAny := range chk.AsList(state["slot_index"]) {
			slot := chk.AsMap(slotAny)
			if !matchSlotConstraint(slot, c, bindings, requireUsable) {
				continue
			}
			for _, w := range chk.AsList(slot["writers"]) {
				writer := chk.AsMap(w)
				if !matchWriter(writer, c) {
					continue
				}
				results = append(results, extendContext(context, step, slot, writer, nil, nil))
			}
		}
		return results
	}
	if c, ok := match["storage_read"].(map[string]any); ok {
		_ = c
		for _, slotAny := range chk.AsList(state["slot_index"]) {
			slot := chk.AsMap(slotAny)
			if !matchSlotConstraint(slot, chk.AsMap(match["storage_read"]), bindings, requireUsable) {
				continue
			}
			for _, r := range chk.AsList(slot["readers"]) {
				reader := chk.AsMap(r)
				if !matchReader(reader, match) {
					continue
				}
				results = append(results, extendContext(context, step, slot, nil, reader, nil))
			}
		}
		return results
	}
	if c, ok := match["delegatecall"].(map[string]any); ok {
		for _, callAny := range chk.AsList(state["call_index"]) {
			call := chk.AsMap(callAny)
			if matchDelegatecall(call, c, bindings, requireUsable) {
				results = append(results, extendContext(context, step, nil, nil, nil, call))
			}
		}
		return results
	}
	if c, ok := match["external_call"].(map[string]any); ok {
		for _, callAny := range chk.AsList(state["call_index"]) {
			call := chk.AsMap(callAny)
			if matchExternalCall(call, c, match, bindings, requireUsable) {
				results = append(results, extendContext(context, step, nil, nil, nil, call))
			}
		}
		return results
	}
	return results
}

func extendContext(context, step, slot, writer, reader, call map[string]any) map[string]any {
	bindings := map[string]any{}
	for k, v := range chk.AsMap(context["bindings"]) {
		bindings[k] = v
	}
	bind := chk.AsMap(step["bind"])
	if slot != nil {
		for key, nameAny := range bind {
			name, ok := nameAny.(string)
			if !ok || len(name) == 0 || name[0] != '$' {
				continue
			}
			switch key {
			case "slot":
				bindings[name] = slot["slot"]
			case "path":
				src := writer
				if src == nil {
					src = reader
				}
				if src == nil {
					src = map[string]any{}
				}
				bindings[name] = src["path"]
			case "guard":
				src := writer
				if src == nil {
					src = reader
				}
				if src == nil {
					src = map[string]any{}
				}
				refs := chk.AsStringList(src["guard_refs"])
				if len(refs) > 0 {
					bindings[name] = refs[0]
				} else {
					bindings[name] = nil
				}
			case "value_origin":
				if writer != nil {
					bindings[name] = writer["write_origin"]
				} else {
					bindings[name] = nil
				}
			}
		}
	}
	if call != nil && slot == nil {
		for key, nameAny := range bind {
			name, ok := nameAny.(string)
			if !ok || len(name) == 0 || name[0] != '$' {
				continue
			}
			if key == "call_target" {
				bindings[name] = call["target"]
			}
		}
	}
	steps := append([]any{}, chk.AsList(context["steps"])...)
	slotRefs := append([]any{}, chk.AsList(context["slot_refs"])...)
	guardRefs := append([]any{}, chk.AsList(context["guard_refs"])...)
	delegateRefs := append([]any{}, chk.AsList(context["delegate_target_refs"])...)
	entry := map[string]any{"id": step["id"]}
	if slot != nil {
		entry["slot"] = slot["slot"]
		entry["semantic_role"] = slot["semantic_role"]
		slotRefs = append(slotRefs, slot["slot"])
		for _, g := range chk.AsList(slot["guards"]) {
			guardRefs = append(guardRefs, g)
		}
	}
	if writer != nil {
		entry["writer"] = writer
	}
	if reader != nil {
		entry["reader"] = reader
	}
	if call != nil {
		entry["call"] = call
		delegateRefs = append(delegateRefs, call["target"])
	}
	steps = append(steps, entry)
	return map[string]any{
		"bindings":             bindings,
		"steps":                steps,
		"slot_refs":            slotRefs,
		"guard_refs":           guardRefs,
		"delegate_target_refs": delegateRefs,
	}
}

func matchSlotConstraint(slot, constraint, bindings map[string]any, requireUsable bool) bool {
	if requireUsable && !trustUsable(slot["trust"]) {
		return false
	}
	roles := chk.SetFromList(constraint["semantic_role_any"])
	if len(roles) > 0 {
		if _, ok := roles[chk.AsString(slot["semantic_role"])]; !ok {
			return false
		}
	}
	if sameSlot, ok := constraint["same_slot_as"].(string); ok && sameSlot != "" {
		if !equalAny(slot["slot"], bindings[sameSlot]) {
			return false
		}
	}
	minConf := chk.AsFloat(constraint["min_role_confidence"], 0)
	rc := chk.AsFloat(slot["role_confidence"], chk.AsFloat(slot["confidence"], 0))
	if rc < minConf {
		return false
	}
	if pk := chk.AsString(constraint["proxy_slot_kind"]); pk != "" {
		proxy := chk.AsMap(slot["proxy"])
		if chk.AsString(proxy["slot_kind"]) != pk {
			return false
		}
	}
	return true
}

func matchWriter(writer, constraint map[string]any) bool {
	if chk.AsBool(constraint["user_controlled_write_value"]) && !chk.AsBool(writer["user_controlled_write_value"]) {
		return false
	}
	if cr := chk.AsString(constraint["caller_reachability"]); cr != "" && chk.AsString(writer["caller_reachability"]) != cr {
		return false
	}
	if cc := chk.AsString(constraint["caller_constraint"]); cc != "" && chk.AsString(writer["caller_constraint"]) != cc {
		return false
	}
	origins := chk.SetFromList(constraint["write_origin_any"])
	if len(origins) > 0 {
		if _, ok := origins[chk.AsString(writer["write_origin"])]; !ok {
			return false
		}
	}
	return true
}

func matchReader(reader, match map[string]any) bool {
	constraint := chk.AsMap(match["storage_read"])
	if used := chk.AsString(constraint["used_in"]); used != "" && chk.AsString(reader["used_in"]) != used {
		return false
	}
	authorized := chk.SetFromList(match["authorized_path_effect_any"])
	if len(authorized) > 0 {
		readerAuth := chk.SetFromList(reader["authorized_path_effects"])
		if !chk.IntersectAny(authorized, readerAuth) {
			return false
		}
	}
	reachable := chk.SetFromList(match["reachable_effect_any"])
	if len(reachable) > 0 {
		readerReach := chk.SetFromList(reader["reachable_effects"])
		if !chk.IntersectAny(reachable, readerReach) {
			return false
		}
	}
	return true
}

func matchDelegatecall(call, constraint, bindings map[string]any, requireUsable bool) bool {
	if requireUsable && !trustUsable(call["trust"]) {
		return false
	}
	if chk.AsString(call["kind"]) != "delegatecall" {
		return false
	}
	if origins, ok := constraint["target_origin_any"].([]any); ok && len(origins) > 0 {
		set := chk.SetFromList(origins)
		if _, ok := set[chk.AsString(call["target_origin"])]; !ok {
			return false
		}
	}
	if sameSlot, ok := constraint["same_slot_as"].(string); ok && sameSlot != "" {
		if !equalAny(call["target_slot"], bindings[sameSlot]) {
			return false
		}
	}
	if ctrl := chk.AsString(constraint["target_controllability"]); ctrl != "" && chk.AsString(call["target_controllability"]) != ctrl {
		return false
	}
	return true
}

func matchExternalCall(call, constraint, matchCtx, bindings map[string]any, requireUsable bool) bool {
	if requireUsable && !trustUsable(call["trust"]) {
		return false
	}
	kind := chk.AsString(call["kind"])
	if kind != "external_call" && kind != "call" && kind != "staticcall" {
		return false
	}
	if origins, ok := constraint["target_origin_any"].([]any); ok && len(origins) > 0 {
		set := chk.SetFromList(origins)
		if _, ok := set[chk.AsString(call["target_origin"])]; !ok {
			return false
		}
	}
	if ctrl := chk.AsString(constraint["target_controllability"]); ctrl != "" && chk.AsString(call["target_controllability"]) != ctrl {
		return false
	}
	if val := chk.AsString(constraint["address_validation"]); val != "" && chk.AsString(call["address_validation"]) != val {
		return false
	}
	if chk.AsBool(constraint["return_value_consumed"]) && !chk.AsBool(call["return_value_consumed"]) {
		return false
	}
	if sameTarget, ok := constraint["same_call_target_as"].(string); ok && sameTarget != "" {
		if !equalAny(call["target"], bindings[sameTarget]) {
			return false
		}
	}
	returnEffects := chk.SetFromList(constraint["return_flow_effect_any"])
	if len(returnEffects) > 0 {
		callReturn := chk.SetFromList(call["return_flow_effects"])
		if !chk.IntersectAny(returnEffects, callReturn) {
			return false
		}
	}
	reachable := chk.SetFromList(matchCtx["reachable_effect_any"])
	if len(reachable) > 0 {
		callEffects := map[string]struct{}{}
		for _, e := range chk.AsStringList(call["return_flow_effects"]) {
			callEffects[e] = struct{}{}
		}
		for _, e := range chk.AsStringList(call["reachable_effects"]) {
			callEffects[e] = struct{}{}
		}
		if !chk.IntersectAny(reachable, callEffects) {
			return false
		}
	}
	return true
}

func functionTags(fn map[string]any) map[string]struct{} {
	tags := map[string]struct{}{}
	for _, t := range chk.AsStringList(fn["behavior_tags"]) {
		tags[t] = struct{}{}
	}
	for _, t := range chk.AsStringList(fn["tags"]) {
		tags[t] = struct{}{}
	}
	for _, a := range chk.AsList(fn["arithmetic"]) {
		ar := chk.AsMap(a)
		for _, t := range chk.AsStringList(ar["behavior_tags"]) {
			tags[t] = struct{}{}
		}
		if op := chk.AsString(ar["operation"]); op != "" {
			tags[op] = struct{}{}
		}
		if k := chk.AsString(ar["economic_fact_kind"]); k != "" {
			tags[k] = struct{}{}
		}
	}
	for _, fa := range chk.AsList(fn["accounting"]) {
		fact := chk.AsMap(fa)
		for _, t := range chk.AsStringList(fact["behavior_tags"]) {
			tags[t] = struct{}{}
		}
		if k := chk.AsString(fact["kind"]); k != "" {
			tags[k] = struct{}{}
		}
		if r := chk.AsString(fact["mismatch_relation"]); r != "" {
			tags[r] = struct{}{}
		}
	}
	state := chk.AsMap(fn["state"])
	guards := state["guards"]
	if guards == nil {
		guards = fn["guards"]
	}
	for _, g := range chk.AsList(guards) {
		if s, ok := g.(string); ok {
			tags[s] = struct{}{}
		}
	}
	return tags
}

func globalTags(audit map[string]any) map[string]struct{} {
	tags := map[string]struct{}{}
	for _, t := range chk.AsStringList(audit["global_tags"]) {
		tags[t] = struct{}{}
	}
	for _, inv := range chk.AsList(audit["invariants"]) {
		if k := chk.AsString(chk.AsMap(inv)["kind"]); k != "" {
			tags[k] = struct{}{}
		}
	}
	state := chk.AsMap(audit["state_model"])
	for _, e := range chk.AsList(state["proxy_index"]) {
		if v := chk.AsString(chk.AsMap(e)["proxy_standard"]); v != "" {
			tags[v] = struct{}{}
		}
	}
	fingerprint := chk.AsMap(audit["bytecode_fingerprint"])
	for _, t := range chk.AsStringList(fingerprint["tags"]) {
		tags[t] = struct{}{}
	}
	for _, e := range chk.AsList(state["guard_catalog"]) {
		entry := chk.AsMap(e)
		if gtype := chk.AsString(entry["type"]); gtype != "" {
			tags[gtype] = struct{}{}
		}
		if chk.AsString(entry["strength"]) == "strong" {
			tags["STRONG_GUARD_PRESENT"] = struct{}{}
		}
	}
	if init := chk.AsList(state["initializer_index"]); len(init) > 0 {
		tags["INITIALIZABLE"] = struct{}{}
		tags["initializer_guard"] = struct{}{}
	}
	return tags
}

func matchFlows(fn map[string]any, flowRules []any) map[string]any {
	if len(flowRules) == 0 {
		return map[string]any{"matched": true, "matches": []any{}}
	}
	matches := []any{}
	flowTexts := []string{}
	for _, f := range chk.AsList(fn["flows"]) {
		flowTexts = append(flowTexts, jsonSorted(f))
	}
	actionTexts := []string{}
	for _, a := range chk.AsList(fn["actions"]) {
		actionTexts = append(actionTexts, jsonSorted(a))
	}
	callTexts := []string{}
	for _, c := range chk.AsList(fn["external_calls"]) {
		callTexts = append(callTexts, jsonSorted(c))
	}
	tagText := jsonSorted(fn["behavior_tags"])
	stateText := jsonSorted(fn["state"])
	haystack := joinLines(flowTexts, actionTexts, callTexts, []string{stateText, tagText})
	allOK := true
	for _, ra := range flowRules {
		rule := chk.AsMap(ra)
		required := []string{}
		for _, pair := range [][2]string{{"source", "from"}, {"through", "through"}, {"sink", "to"}} {
			value := rule[pair[0]]
			if value == nil {
				value = rule[pair[1]]
			}
			if value == nil {
				continue
			}
			required = append(required, chk.AsString(value))
		}
		ok := true
		for _, p := range required {
			if !contains(haystack, p) {
				ok = false
				break
			}
		}
		matches = append(matches, map[string]any{"rule": rule, "matched": ok})
		if !ok {
			allOK = false
		}
	}
	return map[string]any{"matched": allOK, "matches": matches}
}

func matchArithmetic(fn, rule map[string]any, requireUsable bool) map[string]any {
	requires := chk.AsMap(rule["requires"])
	required := chk.SetFromList(requires["economic_effect_any"])
	category := chk.AsString(chk.AsMap(rule["rule"])["category"])
	if len(required) == 0 && category != "arithmetic_invariant" && category != "accounting_invariant" {
		return map[string]any{"matched": true, "matches": []any{}}
	}
	matches := []any{}
	for _, fa := range chk.AsList(fn["arithmetic"]) {
		fact := chk.AsMap(fa)
		if requireUsable && !trustUsable(fact["trust"]) {
			continue
		}
		tags := chk.SetFromList(fact["behavior_tags"])
		effects := chk.SetFromList(fact["economic_effects"])
		if len(required) > 0 {
			union := unionSets(tags, effects)
			if !chk.IntersectAny(required, union) {
				continue
			}
		}
		op := chk.AsString(fact["operation"])
		if op == "fixed_point_mul_div" || op == "fixed_point_candidate" {
			matches = append(matches, fact)
			continue
		}
		if _, ok := tags["fixed_point_floor_mul_or_div"]; ok {
			matches = append(matches, fact)
		}
	}
	for _, fa := range chk.AsList(fn["accounting"]) {
		fact := chk.AsMap(fa)
		if requireUsable && !trustUsable(fact["trust"]) {
			continue
		}
		tags := chk.SetFromList(fact["behavior_tags"])
		effects := chk.SetFromList(fact["economic_effects"])
		if len(required) > 0 {
			union := unionSets(tags, effects)
			if !chk.IntersectAny(required, union) {
				continue
			}
		}
		matches = append(matches, fact)
	}
	if len(matches) == 0 && len(required) > 0 && category != "arithmetic_invariant" && category != "accounting_invariant" {
		fnTags := chk.SetFromList(fn["behavior_tags"])
		if chk.IntersectAny(required, fnTags) {
			return map[string]any{"matched": true, "matches": []any{}}
		}
	}
	return map[string]any{"matched": len(matches) > 0, "matches": matches}
}

func matchFunctionEffects(fn, requires map[string]any) map[string]any {
	actual := functionEffects(fn)
	required := chk.SetFromList(requires["reachable_effect_any"])
	authorized := chk.SetFromList(requires["authorized_path_effect_any"])
	matched := true
	if len(required) > 0 && !chk.IntersectAny(required, actual) {
		matched = false
	}
	if len(authorized) > 0 && !chk.IntersectAny(authorized, actual) {
		matched = false
	}
	return map[string]any{"matched": matched, "actual": stringsToAny(chk.SortedSet(actual))}
}

func functionEffects(fn map[string]any) map[string]struct{} {
	effects := map[string]struct{}{}
	for _, a := range chk.AsList(fn["actions"]) {
		action := chk.AsMap(a)
		if se := chk.AsString(action["semantic_effect"]); se != "" {
			effects[se] = struct{}{}
		}
		t := chk.AsString(action["type"])
		if t == "DELEGATECALL" {
			effects["delegatecall"] = struct{}{}
		}
		if t == "SELFDESTRUCT" {
			effects["selfdestruct"] = struct{}{}
		}
	}
	for _, c := range chk.AsList(fn["external_calls"]) {
		call := chk.AsMap(c)
		if se := chk.AsString(call["semantic_effect"]); se != "" {
			effects[se] = struct{}{}
		}
	}
	state := chk.AsMap(fn["state"])
	for _, r := range chk.AsList(state["reads"]) {
		read := chk.AsMap(r)
		for _, e := range chk.AsStringList(read["reachable_effects"]) {
			effects[e] = struct{}{}
		}
	}
	for _, fa := range chk.AsList(fn["accounting"]) {
		fact := chk.AsMap(fa)
		for _, e := range chk.AsStringList(fact["economic_effects"]) {
			effects[e] = struct{}{}
		}
	}
	return effects
}

func slotEffects(slot map[string]any) map[string]struct{} {
	effects := map[string]struct{}{}
	for _, r := range chk.AsList(slot["readers"]) {
		reader := chk.AsMap(r)
		for _, e := range chk.AsStringList(reader["reachable_effects"]) {
			effects[e] = struct{}{}
		}
		for _, e := range chk.AsStringList(reader["authorized_path_effects"]) {
			effects[e] = struct{}{}
		}
	}
	return effects
}

func counterTagsHit(tags map[string]struct{}, configured []string) []string {
	out := []string{}
	for _, t := range configured {
		if _, ok := tags[t]; ok {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

func counterEvidenceDetails(tags map[string]struct{}, rule map[string]any) map[string]any {
	counter := chk.AsMap(rule["counter_evidence"])
	return map[string]any{
		"suppress_if_any":      stringsToAny(counterTagsHit(tags, chk.AsStringList(counter["suppress_if_any"]))),
		"downgrade_if_any":     stringsToAny(counterTagsHit(tags, chk.AsStringList(counter["downgrade_if_any"]))),
		"inconclusive_if_any":  stringsToAny(counterTagsHit(tags, chk.AsStringList(counter["inconclusive_if_any"]))),
		"manual_review_if_any": stringsToAny(counterTagsHit(tags, chk.AsStringList(counter["manual_review_if_any"]))),
	}
}

func requireUsablePrimaryEvidence(rule map[string]any) bool {
	return chk.AsBool(chk.AsMap(rule["analysis_requirements"])["require_usable_primary_evidence"])
}

func trustUsable(trust any) bool {
	if trust == nil {
		return true
	}
	tm, ok := trust.(map[string]any)
	if !ok {
		return true
	}
	v, ok := tm["usable_as_detector_proof"]
	if !ok {
		return true
	}
	b, ok := v.(bool)
	if !ok {
		return false
	}
	return b
}

func equalAny(a, b any) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

func jsonSorted(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func joinLines(groups ...[]string) string {
	out := ""
	first := true
	for _, g := range groups {
		for _, s := range g {
			if !first {
				out += "\n"
			}
			out += s
			first = false
		}
	}
	return out
}

func contains(s, substr string) bool {
	if substr == "" {
		return true
	}
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func unionSets(a, b map[string]struct{}) map[string]struct{} {
	out := map[string]struct{}{}
	for k := range a {
		out[k] = struct{}{}
	}
	for k := range b {
		out[k] = struct{}{}
	}
	return out
}

func toAnyList(items []map[string]any) []any {
	out := make([]any, len(items))
	for i, m := range items {
		out[i] = m
	}
	return out
}

func stringsToAny(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

func coalesceListAny(v any) []any {
	if l, ok := v.([]any); ok {
		out := make([]any, len(l))
		copy(out, l)
		return out
	}
	return []any{}
}

type validationErr struct{ msg string }

func (e *validationErr) Error() string { return e.msg }

func validationError(errs []string) error {
	return &validationErr{msg: joinSemi(errs)}
}

func validationDetail(rid string, errs []string) error {
	return &validationErr{msg: "detector " + rid + " validation failed: " + joinSemi(errs)}
}

func joinSemi(items []string) string {
	out := ""
	for i, s := range items {
		if i > 0 {
			out += "; "
		}
		out += s
	}
	return out
}
