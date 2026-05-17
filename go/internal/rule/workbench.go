// Package rule ports evm_rule: detector workbench (init, validate, doctor,
// test, explain).
package rule

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	chk "github.com/evm-auditor/evm-auditor/internal/check"
	"github.com/evm-auditor/evm-auditor/internal/check/engine"
	"github.com/evm-auditor/evm-auditor/internal/check/loader"
)

// Init writes a detector + corpus template named ruleID under outDir/corpusRoot.
// Mirrors evm_rule._init_detector.
func Init(ruleID, outDir, corpusRoot string) (map[string]any, error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}
	corpusPath := filepath.Join(corpusRoot, ruleID)
	if err := os.MkdirAll(corpusPath, 0o755); err != nil {
		return nil, err
	}
	detectorPath := filepath.Join(outDir, ruleID+".json")
	if err := writeTemplate(detectorPath, fillTemplate(detectorTemplate(), ruleID)); err != nil {
		return nil, err
	}
	manifestPath := filepath.Join(corpusPath, "corpus.json")
	if err := writeTemplate(manifestPath, fillTemplate(corpusTemplate(), ruleID)); err != nil {
		return nil, err
	}
	return map[string]any{
		"detector": detectorPath,
		"corpus":   manifestPath,
	}, nil
}

func writeTemplate(path string, data any) error {
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

func fillTemplate(template any, ruleID string) any {
	raw, _ := json.Marshal(template)
	s := strings.ReplaceAll(string(raw), "{rule_id}", ruleID)
	var out any
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

// Explain mirrors evm_rule subcommand `explain`.
func Explain(rulePath, auditPath string) (map[string]any, error) {
	rules, err := loader.LoadRules(rulePath)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("no rules found at %s", rulePath)
	}
	rule := rules[0]
	auditRaw, err := os.ReadFile(auditPath)
	if err != nil {
		return nil, err
	}
	var auditAny any
	if err := decodeJSON(auditRaw, &auditAny); err != nil {
		return nil, err
	}
	auditAny = loader.ConvertNumbers(auditAny)
	audit, _ := auditAny.(map[string]any)
	result, err := engine.CheckAudit(audit, []map[string]any{rule})
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"findings": result["findings"],
		"trace":    result["trace"],
	}, nil
}

// Validate mirrors evm_rule subcommand `validate`.
func Validate(rulePath string) (map[string]any, error) {
	rules, err := loader.LoadRules(rulePath)
	if err != nil {
		return nil, err
	}
	root := validationRoot(rulePath)
	result := validateRules(rules, root)
	if result["ok"].(bool) {
		for _, rule := range rules {
			fixtures := chk.AsMap(rule["fixture_requirements"])
			rel := chk.AsString(fixtures["corpus"])
			corpusPath := filepath.Join(root, rel)
			if _, err := os.Stat(corpusPath); err == nil {
				manifestRaw, err := os.ReadFile(filepath.Join(corpusPath, "corpus.json"))
				if err != nil {
					continue
				}
				var corpus map[string]any
				if err := decodeJSONMap(manifestRaw, &corpus); err != nil {
					continue
				}
				rid := chk.AsString(chk.AsMap(rule["rule"])["id"])
				cv := chk.ValidateCorpus(corpus, rid)
				if !cv["ok"].(bool) {
					result["ok"] = false
					errs := result["errors"].([]any)
					errs = append(errs, map[string]any{
						"rule_id": rid,
						"errors":  toAnyList(cv["errors"].([]string)),
					})
					result["errors"] = errs
				}
			}
		}
	}
	return result, nil
}

func validateRules(rules []map[string]any, root string) map[string]any {
	results := make([]map[string]any, len(rules))
	for i, r := range rules {
		results[i] = chk.ValidateRule(r, root)
	}
	errors := []any{}
	warnings := []any{}
	for i, res := range results {
		errs := res["errors"].([]string)
		warns := res["warnings"].([]string)
		rid := chk.AsString(chk.AsMap(rules[i]["rule"])["id"])
		if len(errs) > 0 {
			errors = append(errors, map[string]any{
				"rule_id": rid,
				"errors":  toAnyList(errs),
			})
		}
		if len(warns) > 0 {
			warnings = append(warnings, map[string]any{
				"rule_id":  rid,
				"warnings": toAnyList(warns),
			})
		}
	}
	return map[string]any{
		"schema":   "evm-audit.detector_validation",
		"ok":       len(errors) == 0,
		"errors":   errors,
		"warnings": warnings,
	}
}

// Doctor mirrors evm_rule subcommand `doctor`.
func Doctor(rulePath string) (map[string]any, error) {
	rules, err := loader.LoadRules(rulePath)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("no rule found at %s", rulePath)
	}
	rule := rules[0]
	issues := []string{}
	requires := chk.AsMap(rule["requires"])
	sequence := chk.AsList(requires["sequence"])
	if len(sequence) > 0 {
		anyBind := false
		for _, st := range sequence {
			step := chk.AsMap(st)
			if len(chk.AsMap(step["bind"])) > 0 {
				anyBind = true
				break
			}
		}
		if !anyBind {
			issues = append(issues, "sequence has no bind variables")
		}
		anyJoin := false
		for _, st := range sequence {
			step := chk.AsMap(st)
			match := chk.AsMap(step["match"])
			for _, v := range match {
				vm, ok := v.(map[string]any)
				if !ok {
					continue
				}
				for _, key := range []string{"same_slot_as", "same_guard_as", "same_delegate_target_as"} {
					if _, has := vm[key]; has {
						anyJoin = true
						break
					}
				}
				if anyJoin {
					break
				}
			}
			if anyJoin {
				break
			}
		}
		if !anyJoin {
			issues = append(issues, "sequence has no explicit joins")
		}
	}
	analysis := chk.AsMap(rule["analysis_requirements"])
	if chk.AsInt(analysis["max_unknown_action_expression_count"], 0) >= 1_000_000 {
		issues = append(issues, "analysis thresholds are effectively disabled")
	}
	proof := chk.AsMap(rule["proof"])
	severity := chk.AsString(chk.AsMap(rule["rule"])["severity"])
	if chk.AsString(proof["preferred_witness"]) == "none" && (severity == "high" || severity == "critical") {
		issues = append(issues, "high-severity detector has no witness strategy")
	}
	return map[string]any{
		"rule_id": chk.AsMap(rule["rule"])["id"],
		"issues":  toAnyList(issues),
	}, nil
}

// Test mirrors evm_rule subcommand `test`.
func Test(rulePath, corpusPath string) (map[string]any, bool, error) {
	rules, err := loader.LoadRules(rulePath)
	if err != nil {
		return nil, false, err
	}
	if len(rules) == 0 {
		return nil, false, fmt.Errorf("no rule found at %s", rulePath)
	}
	rule := rules[0]
	rid := chk.AsString(chk.AsMap(rule["rule"])["id"])
	corpus, err := loader.LoadCorpusManifest(corpusPath, rid)
	if err != nil {
		return nil, false, err
	}
	failures := []any{}
	results := []any{}
	counts := map[string]int{"positive": 0, "negative": 0, "inconclusive": 0}
	falsePositive := 0
	falseNegative := 0
	for _, caAny := range chk.AsList(corpus["cases"]) {
		ca := chk.AsMap(caAny)
		auditPath := filepath.Join(corpusPath, chk.AsString(ca["audit_json"]))
		raw, err := os.ReadFile(auditPath)
		if err != nil {
			return nil, false, err
		}
		var auditAny any
		if err := decodeJSON(raw, &auditAny); err != nil {
			return nil, false, err
		}
		auditAny = loader.ConvertNumbers(auditAny)
		audit, _ := auditAny.(map[string]any)
		result, err := engine.CheckAudit(audit, []map[string]any{rule})
		if err != nil {
			return nil, false, err
		}
		matchedIDs := map[string]struct{}{}
		for _, fAny := range chk.AsList(result["findings"]) {
			f := chk.AsMap(fAny)
			matchedIDs[chk.AsString(f["rule_id"])] = struct{}{}
		}
		expectation := chk.AsMap(ca["expectation"])
		kind := chk.AsString(expectation["kind"])
		counts[kind]++
		expected := chk.SetFromList(expectation["rule_ids"])
		missing := []string{}
		forbidden := []string{}
		switch kind {
		case "positive":
			for r := range expected {
				if _, ok := matchedIDs[r]; !ok {
					missing = append(missing, r)
				}
			}
			sort.Strings(missing)
		case "negative":
			for r := range expected {
				if _, ok := matchedIDs[r]; ok {
					forbidden = append(forbidden, r)
				}
			}
			sort.Strings(forbidden)
		}
		inconclusiveOK := true
		if kind == "inconclusive" {
			inconclusiveOK = false
			for _, fAny := range chk.AsList(result["findings"]) {
				f := chk.AsMap(fAny)
				if _, ok := expected[chk.AsString(f["rule_id"])]; ok && chk.AsString(f["status"]) == "analysis_inconclusive" {
					inconclusiveOK = true
					break
				}
			}
		}
		ok := len(missing) == 0 && len(forbidden) == 0 && inconclusiveOK
		if !ok {
			failures = append(failures, map[string]any{
				"case":             ca["id"],
				"missing":          toAnyList(missing),
				"forbidden":        toAnyList(forbidden),
				"inconclusive_ok":  inconclusiveOK,
			})
		}
		falsePositive += len(forbidden)
		falseNegative += len(missing)
		matched := make([]string, 0, len(matchedIDs))
		for k := range matchedIDs {
			matched = append(matched, k)
		}
		sort.Strings(matched)
		results = append(results, map[string]any{
			"case":     ca["id"],
			"ok":       ok,
			"findings": toAnyList(matched),
		})
	}
	fixtures := chk.AsMap(rule["fixture_requirements"])
	if counts["positive"] < chk.AsInt(fixtures["positive_fixtures_min"], 0) {
		failures = append(failures, map[string]any{
			"case":             "__fixture_requirements__",
			"missing_positive": true,
		})
	}
	if counts["negative"] < chk.AsInt(fixtures["negative_fixtures_min"], 0) {
		failures = append(failures, map[string]any{
			"case":             "__fixture_requirements__",
			"missing_negative": true,
		})
	}
	if counts["inconclusive"] < chk.AsInt(fixtures["inconclusive_fixtures_min"], 0) {
		failures = append(failures, map[string]any{
			"case":                 "__fixture_requirements__",
			"missing_inconclusive": true,
		})
	}
	metrics := map[string]any{}
	for k, v := range chk.AsMap(corpus["metrics"]) {
		metrics[k] = v
	}
	metrics["false_positive_count"] = falsePositive
	metrics["false_negative_count"] = falseNegative
	if falsePositive == 0 {
		metrics["detector_precision"] = 1.0
	} else {
		metrics["detector_precision"] = 0.0
	}
	if falseNegative == 0 {
		metrics["detector_recall"] = 1.0
	} else {
		metrics["detector_recall"] = 0.0
	}
	return map[string]any{
		"ok":       len(failures) == 0,
		"metrics":  metrics,
		"results":  results,
		"failures": failures,
	}, len(failures) == 0, nil
}

func validationRoot(rulePath string) string {
	st, err := os.Stat(rulePath)
	if err != nil || st.IsDir() {
		cwd, _ := os.Getwd()
		return cwd
	}
	abs, _ := filepath.Abs(rulePath)
	for p := filepath.Dir(abs); ; p = filepath.Dir(p) {
		if filepath.Base(p) == "rules" {
			return filepath.Dir(p)
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	return filepath.Dir(abs)
}

func toAnyList(items []string) []any {
	out := make([]any, len(items))
	for i, s := range items {
		out[i] = s
	}
	return out
}

func decodeJSON(raw []byte, v *any) error {
	return decodeUseNumber(raw, v)
}

func decodeJSONMap(raw []byte, v *map[string]any) error {
	var anyVal any
	if err := decodeUseNumber(raw, &anyVal); err != nil {
		return err
	}
	anyVal = loader.ConvertNumbers(anyVal)
	m, ok := anyVal.(map[string]any)
	if !ok {
		return fmt.Errorf("expected JSON object")
	}
	*v = m
	return nil
}

func decodeUseNumber(raw []byte, v *any) error {
	d := newDecoder(raw)
	return d.Decode(v)
}
