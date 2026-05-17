// Package diff ports evm_diff: source-truth fixture comparison.
package diff

import (
	"sort"

	chk "github.com/evm-auditor/evm-auditor/internal/check"
)

// DiffTruth mirrors evm_diff.__main__.diff_truth.
func DiffTruth(truth, audit map[string]any) map[string]any {
	failures := []any{}
	functions := map[string]map[string]any{}
	for _, fnAny := range chk.AsList(audit["functions"]) {
		fn := chk.AsMap(fnAny)
		identity := chk.AsMap(fn["identity"])
		if sel := chk.AsString(identity["selector"]); sel != "" {
			functions[sel] = fn
		}
	}
	for _, fnAny := range chk.AsList(audit["functions"]) {
		fn := chk.AsMap(fnAny)
		identity := chk.AsMap(fn["identity"])
		if name := chk.AsString(identity["name"]); name != "" {
			functions[name] = fn
		}
	}

	for _, expectedAny := range chk.AsList(truth["functions"]) {
		expected := chk.AsMap(expectedAny)
		key := chk.AsString(expected["selector"])
		if key == "" {
			key = chk.AsString(expected["name"])
		}
		fn, ok := functions[key]
		if !ok {
			failures = append(failures, map[string]any{
				"function": key,
				"error":    "missing_function",
			})
			continue
		}
		expectedWrites := chk.AsStringList(expected["writes"])
		if len(expectedWrites) > 0 {
			observed := observedWrites(fn)
			missing := []string{}
			for _, w := range expectedWrites {
				found := false
				for o := range observed {
					if contains(o, w) {
						found = true
						break
					}
				}
				if !found {
					missing = append(missing, w)
				}
			}
			sort.Strings(missing)
			if len(missing) > 0 {
				obs := make([]string, 0, len(observed))
				for o := range observed {
					obs = append(obs, o)
				}
				sort.Strings(obs)
				failures = append(failures, map[string]any{
					"function": key,
					"error":    "missing_writes",
					"missing":  toAnyList(missing),
					"observed": toAnyList(obs),
				})
			}
		}
		if expectedMutability := chk.AsString(expected["mutability"]); expectedMutability != "" {
			obs := chk.AsString(chk.AsMap(fn["interface"])["mutability"])
			if obs == "" {
				obs = inferMutability(fn)
			}
			if obs != expectedMutability {
				failures = append(failures, map[string]any{
					"function": key,
					"error":    "mutability_mismatch",
					"expected": expectedMutability,
					"observed": obs,
				})
			}
		}
	}
	return map[string]any{
		"schema":   "evm-audit.diff",
		"ok":       len(failures) == 0,
		"failures": failures,
	}
}

func observedWrites(fn map[string]any) map[string]struct{} {
	state := chk.AsMap(fn["state"])
	out := map[string]struct{}{}
	semantic := chk.AsMap(state["semantic_summary"])
	for _, w := range chk.AsStringList(semantic["writes"]) {
		out[w] = struct{}{}
	}
	for _, w := range chk.AsList(state["writes"]) {
		entry := chk.AsMap(w)
		if slot := chk.AsString(entry["slot"]); slot != "" {
			out[slot] = struct{}{}
		}
	}
	return out
}

func inferMutability(fn map[string]any) string {
	state := chk.AsMap(fn["state"])
	if len(chk.AsList(state["writes"])) > 0 {
		return "nonpayable"
	}
	if len(chk.AsList(state["reads"])) > 0 {
		return "view"
	}
	return "unknown"
}

func contains(s, sub string) bool {
	if sub == "" {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func toAnyList(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}
