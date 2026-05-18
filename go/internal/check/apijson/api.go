// Package apijson ports evm_audit.api: emits evm-audit.api.v2 documents.
package apijson

import (
	"encoding/json"
	"fmt"
	"strings"

	chk "github.com/evm-auditor/evm-auditor/internal/check"
	"github.com/evm-auditor/evm-auditor/pkg/schema"
)

var erc20Selectors = []struct {
	sel  string
	name string
}{
	{"0xa9059cbb", "transfer(address,uint256)"},
	{"0x23b872dd", "transferFrom(address,address,uint256)"},
	{"0x095ea7b3", "approve(address,uint256)"},
	{"0x70a08231", "balanceOf(address)"},
	{"0xdd62ed3e", "allowance(address,address)"},
	{"0x18160ddd", "totalSupply()"},
	{"0x313ce567", "decimals()"},
}

var valueMovingSelectors = map[string]struct{}{
	"0xa9059cbb": {},
	"0x23b872dd": {},
}

var approvalSelectors = map[string]struct{}{
	"0x095ea7b3": {},
}

// ToAPIJSON mirrors evm_audit.api.to_api_json.
func ToAPIJSON(audit, checker map[string]any, inputKind, inputValue, bytecodeHex string, chainContext map[string]any) map[string]any {
	rawFindings := chk.AsList(checker["findings"])
	findings := collapseAPIFindings(rawFindings)
	positive := map[string]struct{}{
		"probable_vulnerability":  {},
		"confirmed_vulnerability": {},
	}
	matched := false
	for _, f := range findings {
		if _, ok := positive[chk.AsString(f["status"])]; ok {
			matched = true
			break
		}
	}
	severities := map[string]struct{}{}
	for _, f := range findings {
		severities[strings.ToLower(chk.AsString(f["severity"]))] = struct{}{}
	}
	ordered := []string{"critical", "high", "medium", "low", "info", "informational"}
	var highestSeverity any
	for _, s := range ordered {
		if _, ok := severities[s]; ok {
			highestSeverity = s
			break
		}
	}
	highestConfidence := 0.0
	for _, f := range findings {
		if c := chk.AsFloat(f["confidence"], 0); c > highestConfidence {
			highestConfidence = c
		}
	}
	rawAnalysisWarnings := append([]any{}, chk.AsList(audit["analysis_warnings"])...)
	pipelineWarns := chk.AsList(chk.AsMap(chk.AsMap(audit["diagnostics"])["analysis"])["pipeline_warnings"])
	for _, pw := range pipelineWarns {
		rawAnalysisWarnings = append(rawAnalysisWarnings, map[string]any{
			"id":       "pipeline_truncated",
			"message":  pw,
			"severity": "info",
		})
	}
	warnings := []any{}
	for _, w := range rawAnalysisWarnings {
		wm := chk.AsMap(w)
		if msg := wm["message"]; msg != nil && chk.AsString(msg) != "" {
			warnings = append(warnings, msg)
		}
	}
	if chainContext == nil {
		chainContext = map[string]any{}
	}
	apiFindings := make([]any, len(findings))
	for i, f := range findings {
		apiFindings[i] = apiFinding(f)
	}
	return map[string]any{
		"ok":                true,
		"schema":            schema.APISchema,
		"schema_version":    schema.APISchemaVer,
		"input":             map[string]any{"kind": inputKind, "value": inputValue},
		"analysis_context":  coalesceMap(audit["analysis_context"]),
		"bytecode_identity": coalesceMap(audit["bytecode_identity"]),
		"analysis": map[string]any{
			"matched":            matched,
			"finding_count":      len(findings),
			"raw_match_count":    len(rawFindings),
			"highest_severity":   highestSeverity,
			"highest_confidence": highestConfidence,
		},
		"coverage": coalesceMap(audit["coverage"]),
		"diagnostics": map[string]any{
			"analysis_warnings":   warnings,
			"deconstruction":      coalesceMap(audit["diagnostics"]),
			"checker_trace_count": len(chk.AsList(checker["trace"])),
		},
		"artifacts": map[string]any{
			"behavior_schema":     audit["schema"],
			"state_model_schema":  chk.AsMap(audit["state_model"])["schema"],
		},
		"exposure_estimate": exposureEstimate(audit, findings, bytecodeHex),
		"findings":          apiFindings,
		"warnings":          warnings,
		"chain_context":     chainContext,
		// Surfaced for downstream sidecar gates (panel/src/server/sim/sidecar.ts).
		// Without these, gated sidecars (bridge, erc4626-withdraw, etc.) can't
		// see the bytecode fingerprint and either over-run or skip silently.
		// The fields are already computed in the behavior layer; passing them
		// through is essentially free in payload size for downstream consumers.
		"global_tags":          coalesceList(audit["global_tags"]),
		"bytecode_fingerprint": coalesceMap(audit["bytecode_fingerprint"]),
	}
}

func collapseAPIFindings(findings []any) []map[string]any {
	type key struct {
		ruleID            string
		status            string
		severity          string
		proofLevel        string
		summary           string
		userSummary       string
		technicalSummary  string
		exploitNarrative  string
		witnessKind       string
		mismatchAmount    string
		mismatchRelation  string
	}
	keys := []key{}
	groups := map[key]map[string]any{}
	for _, fAny := range findings {
		f := chk.AsMap(fAny)
		witness := chk.AsMap(chk.AsMap(f["proof"])["witness"])
		k := key{
			ruleID:           chk.AsString(f["rule_id"]),
			status:           chk.AsString(f["status"]),
			severity:         chk.AsString(f["severity"]),
			proofLevel:       chk.AsString(f["proof_level"]),
			summary:          chk.AsString(f["summary"]),
			userSummary:      chk.AsString(f["user_summary"]),
			technicalSummary: chk.AsString(f["technical_summary"]),
			exploitNarrative: chk.AsString(f["exploit_narrative"]),
			witnessKind:      chk.AsString(witness["kind"]),
			mismatchAmount:   fmt.Sprint(witness["mismatch_amount"]),
			mismatchRelation: chk.AsString(witness["mismatch_relation"]),
		}
		fn := chk.AsMap(f["function"])
		fnRef := map[string]any{
			"selector": fn["selector"],
			"name":     fn["name"],
		}
		entry, ok := groups[k]
		if !ok {
			collapsed := map[string]any{}
			for kk, vv := range f {
				collapsed[kk] = vv
			}
			collapsed["match_count"] = 1
			collapsed["affected_functions"] = []any{fnRef}
			collapsed["raw_matches"] = []any{rawMatch(f)}
			groups[k] = collapsed
			keys = append(keys, k)
			continue
		}
		entry["match_count"] = chk.AsInt(entry["match_count"], 1) + 1
		affected := chk.AsList(entry["affected_functions"])
		if !containsMap(affected, fnRef) {
			affected = append(affected, fnRef)
			entry["affected_functions"] = affected
		}
		raw := chk.AsList(entry["raw_matches"])
		rm := rawMatch(f)
		if !containsMap(raw, rm) {
			raw = append(raw, rm)
			entry["raw_matches"] = raw
		}
	}
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, groups[k])
	}
	return out
}

func apiFinding(f map[string]any) map[string]any {
	fn := chk.AsMap(f["function"])
	witness := chk.AsMap(chk.AsMap(f["proof"])["witness"])
	id := fn["id"]
	if id == nil {
		if sel := chk.AsString(fn["selector"]); sel != "" {
			id = "fn:" + sel
		}
	}
	affected, hasAffected := f["affected_functions"]
	if !hasAffected {
		affected = []any{map[string]any{
			"selector": fn["selector"],
			"name":     fn["name"],
		}}
	}
	rawMatches, hasRaw := f["raw_matches"]
	if !hasRaw {
		rawMatches = []any{rawMatch(f)}
	}
	user := f["user_summary"]
	if chk.AsString(user) == "" {
		user = f["summary"]
	}
	tech := f["technical_summary"]
	if chk.AsString(tech) == "" {
		tech = f["summary"]
	}
	matchCount := chk.AsInt(f["match_count"], 1)
	return map[string]any{
		"rule_id":            f["rule_id"],
		"internal_name":      f["internal_name"],
		"title":              f["title"],
		"status":             f["status"],
		"severity":           f["severity"],
		"confidence":         f["confidence"],
		"proof_level":        f["proof_level"],
		"scope":              f["scope"],
		"match_count":        matchCount,
		"function": map[string]any{
			"selector": fn["selector"],
			"name":     fn["name"],
			"id":       id,
		},
		"affected_functions":     affected,
		"raw_matches":            rawMatches,
		"summary":                f["summary"],
		"user_summary":           user,
		"technical_summary":      tech,
		"exploit_narrative":      f["exploit_narrative"],
		"exploit_preconditions":  coalesceList(f["exploit_preconditions"]),
		"evidence_refs":          coalesceMap(witness["evidence_refs"]),
		"witness":                f["proof"].(map[string]any)["witness"],
		"witness_status":         f["witness_status"],
		"witness_goal":           f["witness_goal"],
		"judged_by":              f["judged_by"],
		"judge_verdict":          f["judge_verdict"],
		"judge_rationale":        f["judge_rationale"],
		"judge_confidence":       f["judge_confidence"],
		"requires_manual_review": f["requires_manual_review"],
	}
}

func rawMatch(f map[string]any) map[string]any {
	fn := chk.AsMap(f["function"])
	witness := chk.AsMap(chk.AsMap(f["proof"])["witness"])
	evidence := chk.AsMap(witness["evidence_refs"])
	id := fn["id"]
	if id == nil {
		if sel := chk.AsString(fn["selector"]); sel != "" {
			id = "fn:" + sel
		}
	}
	return map[string]any{
		"function": map[string]any{
			"selector": fn["selector"],
			"name":     fn["name"],
			"id":       id,
		},
		"path_id":       witness["path_id"],
		"witness_id":    witness["witness_id"],
		"evidence_refs": evidence,
	}
}

func exposureEstimate(audit map[string]any, findings []map[string]any, bytecodeHex string) map[string]any {
	functions := chk.AsList(audit["functions"])
	state := chk.AsMap(audit["state_model"])
	callIndex := chk.AsList(state["call_index"])

	tokenOps := []any{}
	type opKey struct{ a, b string }
	seen := map[opKey]struct{}{}
	for _, fnAny := range functions {
		fn := chk.AsMap(fnAny)
		identity := chk.AsMap(fn["identity"])
		selector := chk.AsString(identity["selector"])
		fnName := identity["name"]
		guards := []map[string]any{}
		for _, g := range chk.AsList(fn["guards"]) {
			if m, ok := g.(map[string]any); ok {
				guards = append(guards, m)
			}
		}
		guardIDs := []any{}
		for _, g := range guards {
			guardIDs = append(guardIDs, chk.AsString(g["id"]))
		}
		isGuarded := len(guardIDs) > 0

		for _, actionAny := range chk.AsList(fn["actions"]) {
			action := chk.AsMap(actionAny)
			t := chk.AsString(action["type"])
			if t != "CALL" && t != "STATICCALL" && t != "DELEGATECALL" {
				continue
			}
			expr := fmt.Sprint(action["expression"])
			for _, m := range erc20Selectors {
				if strings.Contains(expr, m.sel) {
					k := opKey{selector, m.sel}
					if _, ok := seen[k]; ok {
						continue
					}
					seen[k] = struct{}{}
					_, valueMoving := valueMovingSelectors[m.sel]
					_, requiresApproval := approvalSelectors[m.sel]
					tokenOps = append(tokenOps, map[string]any{
						"function":          selector,
						"function_name":     fnName,
						"erc20_method":      m.name,
						"erc20_selector":    m.sel,
						"moves_value":       valueMoving,
						"requires_approval": requiresApproval,
						"guarded":           isGuarded,
						"guard_refs":        guardIDs,
					})
				}
			}
		}
	}
	for _, callAny := range callIndex {
		call := chk.AsMap(callAny)
		target := fmt.Sprint(call["target"])
		fnSel := chk.AsString(call["function"])
		for _, m := range erc20Selectors {
			if strings.Contains(target, m.sel) {
				k := opKey{fnSel, m.sel}
				if _, ok := seen[k]; ok {
					continue
				}
				seen[k] = struct{}{}
				_, valueMoving := valueMovingSelectors[m.sel]
				_, requiresApproval := approvalSelectors[m.sel]
				guardRefs := chk.AsList(call["guard_refs"])
				tokenOps = append(tokenOps, map[string]any{
					"function":          fnSel,
					"function_name":     nil,
					"erc20_method":      m.name,
					"erc20_selector":    m.sel,
					"moves_value":       valueMoving,
					"requires_approval": requiresApproval,
					"guarded":           len(guardRefs) > 0,
					"guard_refs":        guardRefs,
				})
			}
		}
	}

	bytecodeERC20 := []any{}
	bc := strings.ToLower(strings.ReplaceAll(bytecodeHex, "0x", ""))
	for _, m := range erc20Selectors {
		raw := m.sel[2:]
		if strings.Contains(bc, raw) {
			bytecodeERC20 = append(bytecodeERC20, map[string]any{
				"erc20_selector": m.sel,
				"erc20_method":   m.name,
				"source":         "bytecode_scan",
			})
		}
	}

	usesTransferFrom := false
	for _, opAny := range tokenOps {
		op := chk.AsMap(opAny)
		if chk.AsString(op["erc20_selector"]) == "0x23b872dd" {
			usesTransferFrom = true
			break
		}
	}
	if !usesTransferFrom {
		for _, eAny := range bytecodeERC20 {
			e := chk.AsMap(eAny)
			if chk.AsString(e["erc20_selector"]) == "0x23b872dd" {
				usesTransferFrom = true
				break
			}
		}
	}
	usesApprove := false
	for _, opAny := range tokenOps {
		op := chk.AsMap(opAny)
		if chk.AsBool(op["requires_approval"]) {
			usesApprove = true
			break
		}
	}
	if !usesApprove {
		for _, eAny := range bytecodeERC20 {
			e := chk.AsMap(eAny)
			if chk.AsString(e["erc20_selector"]) == "0x095ea7b3" {
				usesApprove = true
				break
			}
		}
	}

	exposureType := "unknown"
	hasUnguardedSelfdestruct := false
	hasDelegateTakeover := false
	for _, f := range findings {
		switch chk.AsString(f["rule_id"]) {
		case "control.unguarded_selfdestruct":
			hasUnguardedSelfdestruct = true
		case "delegatecall.storage_controlled_target":
			hasDelegateTakeover = true
		}
	}
	hasMovesValue := false
	for _, opAny := range tokenOps {
		if chk.AsBool(chk.AsMap(opAny)["moves_value"]) {
			hasMovesValue = true
			break
		}
	}
	switch {
	case hasUnguardedSelfdestruct:
		exposureType = "total_contract_eth_balance"
	case hasDelegateTakeover:
		exposureType = "full_storage_takeover"
	case usesTransferFrom:
		exposureType = "caller_approved_tokens"
	case hasMovesValue:
		exposureType = "per_transaction_amount"
	case len(tokenOps) == 0:
		exposureType = "none"
	}
	return map[string]any{
		"type":                    exposureType,
		"token_operations":        tokenOps,
		"bytecode_selector_hints": bytecodeERC20,
		"uses_transfer_from":      usesTransferFrom,
		"uses_approve":            usesApprove,
	}
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

func containsMap(items []any, candidate map[string]any) bool {
	cb, _ := json.Marshal(candidate)
	for _, item := range items {
		ib, _ := json.Marshal(item)
		if string(ib) == string(cb) {
			return true
		}
	}
	return false
}
