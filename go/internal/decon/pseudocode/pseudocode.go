// Package pseudocode renders a human-readable semantic deconstruction report
// from a behavior.v2 map. Text-functional port of evm_decon/output.py
// format_semantic (section structure + labels preserved; exact column
// formatting is intentionally not byte-identical — see plan stage 5).
package pseudocode

import (
	"fmt"
	"sort"
	"strings"
)

func asMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func asList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return nil
}

func asStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}

func rule(ch string) string { return strings.Repeat(ch, 72) }

// Render produces the semantic report for a behavior.v2 document.
func Render(behavior map[string]any) string {
	var b strings.Builder
	w := func(s string) { b.WriteString(s); b.WriteByte('\n') }

	w(rule("="))
	w("  EVM SEMANTIC DECONSTRUCTION REPORT")
	w(rule("="))
	w("")

	// 1. CONTRACT IDENTITY
	w(rule("-"))
	w("  1. CONTRACT IDENTITY")
	w(rule("-"))
	w("")
	bc := asMap(behavior["bytecode"])
	w(fmt.Sprintf("  Bytecode Size:    %v bytes", bc["runtime_size"]))
	w(fmt.Sprintf("  Runtime Hash:     %v", bc["runtime_hash"]))
	w(fmt.Sprintf("  Analysis Hash:    %v", bc["analysis_hash"]))
	contract := asMap(behavior["contract"])
	if fam := asStr(contract["family"]); fam != "" {
		w(fmt.Sprintf("  Contract Family:  %s", fam))
	}
	fp := asMap(behavior["bytecode_fingerprint"])
	if pt := asStr(fp["proxy_type"]); pt != "" {
		w(fmt.Sprintf("  Proxy:            %s", pt))
	}
	if impl := asStr(fp["implementation_address"]); impl != "" {
		w(fmt.Sprintf("  Implementation:   %s", impl))
	}
	w("")

	// 2. INTERFACE TABLE
	w(rule("-"))
	w("  2. INTERFACE TABLE")
	w(rule("-"))
	w("")
	functions := asList(behavior["functions"])
	if len(functions) == 0 {
		w("  No functions detected")
	} else {
		w(fmt.Sprintf("  %-12s %-45s %-10s", "Selector", "Signature", "Mutability"))
		w(fmt.Sprintf("  %-12s %-45s %-10s", strings.Repeat("-", 10), strings.Repeat("-", 43), strings.Repeat("-", 10)))
		rows := make([]string, 0, len(functions))
		for _, fnAny := range functions {
			id := asMap(asMap(fnAny)["identity"])
			sel := asStr(id["selector"])
			name := asStr(id["name"])
			if name == "" {
				name = "<unresolved>"
			}
			rows = append(rows, fmt.Sprintf("  %-12s %-45s %-10s", sel, name, asStr(id["mutability"])))
		}
		sort.Strings(rows)
		for _, r := range rows {
			w(r)
		}
		w("")
		w(fmt.Sprintf("  Total: %d functions", len(functions)))
	}
	w("")

	// 3. SEMANTIC ARCHITECTURE
	w(rule("-"))
	w("  3. SEMANTIC ARCHITECTURE")
	w(rule("-"))
	w("")
	gtags := asList(behavior["global_tags"])
	if len(gtags) == 0 {
		w("  (no contract-level tags)")
	} else {
		strs := make([]string, 0, len(gtags))
		for _, t := range gtags {
			strs = append(strs, asStr(t))
		}
		sort.Strings(strs)
		for _, t := range strs {
			w("  • " + t)
		}
	}
	w("")

	// 4. STORAGE LAYOUT
	w(rule("-"))
	w("  4. STORAGE LAYOUT")
	w(rule("-"))
	w("")
	slots := asList(asMap(behavior["storage"])["slots"])
	if len(slots) == 0 {
		w("  (no storage slots recovered)")
	} else {
		for _, sAny := range slots {
			s := asMap(sAny)
			w(fmt.Sprintf("  slot %-4v %-20s kind=%v", s["slot"], asStr(s["name"]), s["kind"]))
		}
	}
	w("")

	// 5. FUNCTION CARDS
	w(rule("-"))
	w("  5. FUNCTION CARDS")
	w(rule("-"))
	w("")
	for _, fnAny := range functions {
		fn := asMap(fnAny)
		id := asMap(fn["identity"])
		w(fmt.Sprintf("  ▸ %s %s", asStr(id["selector"]), asStr(id["name"])))
		st := asMap(fn["state"])
		if g := asList(st["guards"]); len(g) > 0 {
			parts := make([]string, 0, len(g))
			for _, x := range g {
				parts = append(parts, asStr(x))
			}
			w("      guards: " + strings.Join(parts, ", "))
		}
		if c := asList(fn["external_calls"]); len(c) > 0 {
			w(fmt.Sprintf("      external_calls: %d", len(c)))
		}
		if tg := asList(fn["behavior_tags"]); len(tg) > 0 {
			parts := make([]string, 0, len(tg))
			for _, x := range tg {
				parts = append(parts, asStr(x))
			}
			sort.Strings(parts)
			w("      tags: " + strings.Join(parts, ", "))
		}
	}
	w("")

	// 6. RISK SUMMARY
	w(rule("-"))
	w("  6. RISK SUMMARY")
	w(rule("-"))
	w("")
	sm := asMap(behavior["state_model"])
	w(fmt.Sprintf("  Functions:            %d", len(functions)))
	w(fmt.Sprintf("  Storage slots:        %d", len(slots)))
	w(fmt.Sprintf("  Guard catalog:        %d", len(asList(sm["guard_catalog"]))))
	w(fmt.Sprintf("  Call index:           %d", len(asList(sm["call_index"]))))
	w(fmt.Sprintf("  Library fingerprints: %d", len(asList(sm["library_fingerprints"]))))
	lf := asList(sm["library_fingerprints"])
	if len(lf) > 0 {
		ids := make([]string, 0, len(lf))
		for _, e := range lf {
			ids = append(ids, asStr(asMap(e)["id"]))
		}
		sort.Strings(ids)
		w("  Detected libraries:   " + strings.Join(ids, ", "))
	}
	w("")
	w(rule("="))
	return b.String()
}
