package builder

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/evm-auditor/evm-auditor/internal/decon/pipeline"
)

// state_model index builders. Ported from evm_decon/audit_json.py
// (_path_index:759, _call_index:822, _economic_index:1129,
// _initializer_index:1239, _evidence_index:1251, _library_fingerprints:1184).
//
// The Go behavior IR is lighter than Python's (no per-action expression /
// target_slot / semantic_effect, no `paths`), so call/path/economic rows are
// derived approximations with Python-compatible key names and ordering. Token
// surfaces that drive counter-evidence (guard_refs, library_fingerprints) are
// faithful — that is the parity contract.

func fnSelector(fn map[string]any) string {
	return asString(asMap(fn["identity"])["selector"])
}

// guardRefs ports audit_json._guard_refs against the Go function shape, where
// guards live under state.guards (list of strings or {id|type|name}).
func guardRefs(fn map[string]any) []string {
	refs := []string{}
	collect := func(items []any) {
		for _, g := range items {
			switch v := g.(type) {
			case string:
				if v != "" {
					refs = append(refs, v)
				}
			case map[string]any:
				id := asString(v["id"])
				if id == "" {
					id = asString(v["type"])
				}
				if id == "" {
					id = asString(v["name"])
				}
				if id != "" {
					refs = append(refs, id)
				}
			}
		}
	}
	collect(asList(asMap(fn["state"])["guards"]))
	collect(asList(fn["guards"]))
	return refs
}

// functionEffects ports audit_json._function_effects.
func functionEffects(fn map[string]any) []string {
	set := map[string]struct{}{}
	for _, a := range asList(fn["actions"]) {
		am := asMap(a)
		if se := asString(am["semantic_effect"]); se != "" {
			set[se] = struct{}{}
		}
		switch strings.ToUpper(asString(am["type"])) {
		case "DELEGATECALL":
			set["delegatecall"] = struct{}{}
		case "SELFDESTRUCT":
			set["selfdestruct"] = struct{}{}
		}
	}
	for _, c := range asList(fn["external_calls"]) {
		if se := asString(asMap(c)["semantic_effect"]); se != "" {
			set[se] = struct{}{}
		}
	}
	for _, f := range asList(fn["accounting"]) {
		for _, e := range asStringList(asMap(f)["economic_effects"]) {
			set[e] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for e := range set {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

func guardType(guard string) string {
	t := strings.ToLower(guard)
	if strings.Contains(t, "initializer") {
		return "initializer_guard"
	}
	for _, tok := range []string{"owner", "admin", "role", "governance", "timelock", "tx_origin_whitelist", "msg_sender_guard"} {
		if strings.Contains(t, tok) {
			return "authorization_guard"
		}
	}
	if strings.Contains(t, "signature") || strings.Contains(t, "permit") {
		return "signature_authorization_guard"
	}
	return "generic_guard"
}

func guardStrength(guard string) string {
	switch guardType(guard) {
	case "authorization_guard", "initializer_guard", "signature_authorization_guard":
		return "strong"
	}
	return "weak"
}

func pathIndex(art *pipeline.Artifacts, functions []any) []any {
	rows := []any{}
	for _, fnAny := range functions {
		fn := asMap(fnAny)
		sel := fnSelector(fn)
		guards := guardRefs(fn)
		effects := functionEffects(fn)
		gany := make([]any, len(guards))
		for i, g := range guards {
			gany[i] = g
		}
		eany := make([]any, len(effects))
		for i, e := range effects {
			eany[i] = e
		}
		authEffects := []any{}
		if len(guards) > 0 {
			authEffects = eany
		}
		rows = append(rows, map[string]any{
			"id":                       "path:" + sel,
			"function_id":              sel,
			"function":                 sel,
			"guard_refs":               gany,
			"reachable_effects":        eany,
			"authorized_path_effects":  authEffects,
			"reachability_confidence":  0.5,
		})
	}
	return rows
}

func callIndex(art *pipeline.Artifacts, functions []any) []any {
	rows := []any{}
	captured := map[string]bool{}
	for _, fnAny := range functions {
		fn := asMap(fnAny)
		sel := fnSelector(fn)
		guards := guardRefs(fn)
		effects := functionEffects(fn)
		gany := make([]any, len(guards))
		for i, g := range guards {
			gany[i] = g
		}
		eany := make([]any, len(effects))
		for i, e := range effects {
			eany[i] = e
		}
		// Action-derived call rows (port of audit_json._call_index loop 1):
		// bytecode-inferred trust, usable as detector proof.
		for _, aAny := range asList(fn["actions"]) {
			a := asMap(aAny)
			kind := normalizeCallKind(asString(a["type"]), asString(a["description"]))
			if kind == "" {
				continue
			}
			captured[fmt.Sprint(a["offset"])] = true
			rows = append(rows, map[string]any{
				"id":                     asString(a["id"]),
				"function":               sel,
				"kind":                   kind,
				"target":                 firstNonEmpty(a["target"], a["description"]),
				"target_slot":            a["target_slot"],
				"target_origin":          orDefault(asString(a["target_origin"]), "computed"),
				"target_controllability": orDefault(asString(a["target_controllability"]), "unknown"),
				"semantic_effect":        a["semantic_effect"],
				"trust": map[string]any{
					"source":                   "bytecode_inferred",
					"confidence":               0.75,
					"usable_as_detector_proof": true,
				},
				"return_value_consumed": true,
				"guard_refs":            gany,
				"reachable_effects":     eany,
				"return_flow_effects":   []any{},
			})
		}
		// external_calls rows (port of loop 2): heuristic trust, not usable
		// as standalone proof — matches Python default _trust("heuristic",0.4,False).
		for _, cAny := range asList(fn["external_calls"]) {
			c := asMap(cAny)
			kind := normalizeCallKind(asString(c["kind"]), asString(c["description"]))
			if kind == "" {
				kind = "call"
			}
			rows = append(rows, map[string]any{
				"id":                     asString(c["id"]),
				"function":               sel,
				"kind":                   kind,
				"target":                 firstNonEmpty(c["target"], c["description"]),
				"target_slot":            c["target_slot"],
				"target_origin":          orDefault(asString(c["target_origin"]), "external"),
				"target_controllability": orDefault(asString(c["target_controllability"]), "unknown"),
				"semantic_effect":        c["semantic_effect"],
				"trust": map[string]any{
					"source":                   "heuristic",
					"confidence":               0.4,
					"usable_as_detector_proof": false,
				},
				"return_value_consumed": true,
				"guard_refs":            gany,
				"reachable_effects":     eany,
				"return_flow_effects":   []any{},
			})
		}
	}
	rows = append(rows, scanUnreachableCalls(art, captured)...)
	enrichCalldataOriginCalls(rows)
	return rows
}

const minUnresolvedCallsForCalldata = 3

// scanUnreachableCalls ports audit_json._scan_unreachable_calls: CALL/STATICCALL
// /DELEGATECALL ops living in blocks not owned by any sliced function (the Go
// slicer attributes far fewer blocks than Python, so the real external call in
// e.g. a swap router lands here). Only calldata-origin targets are emitted,
// matching Python exactly.
func scanUnreachableCalls(art *pipeline.Artifacts, captured map[string]bool) []any {
	if art == nil || art.Sim == nil || art.Blocks == nil {
		return nil
	}
	blockMap := map[int]int{} // block id -> start offset
	for _, b := range art.Blocks.Blocks {
		blockMap[b.ID] = b.StartOffset
	}
	owned := map[int]bool{}
	if art.Slice != nil {
		for _, fn := range art.Slice.Functions {
			for _, bid := range fn.BodyBlocks {
				owned[bid] = true
			}
		}
		for _, bid := range art.Slice.DispatcherBlocks {
			owned[bid] = true
		}
	}

	bids := make([]int, 0, len(art.Sim.Traces))
	for bid := range art.Sim.Traces {
		bids = append(bids, bid)
	}
	sort.Ints(bids)

	calldataTargets := []map[string]any{}
	valueForwarding := map[string]bool{}
	hasStorageCallTargets := false
	for _, bid := range bids {
		if owned[bid] {
			continue
		}
		if _, ok := blockMap[bid]; !ok {
			continue
		}
		trace := art.Sim.Traces[bid]
		if trace == nil {
			continue
		}
		for _, op := range trace.Operations {
			if op.Category != "call" {
				continue
			}
			offsetHex := fmt.Sprintf("0x%04x", op.Offset)
			if captured[offsetHex] {
				continue
			}
			desc := strings.ToLower(op.Description)
			kind := "call"
			switch {
			case strings.Contains(desc, "delegatecall"):
				kind = "delegatecall"
			case strings.Contains(desc, "staticcall"):
				kind = "staticcall"
			case strings.Contains(desc, "callcode"):
				kind = "callcode"
			}
			if strings.HasPrefix(desc, "create") {
				continue
			}
			targetExpr := extractCallTargetExpr(desc)
			origin := classifyUnreachableTarget(targetExpr)
			emitKind := kind
			if kind == "call" || kind == "staticcall" {
				emitKind = "external_call"
			}
			entry := map[string]any{
				"id":              fmt.Sprintf("unreachable:%d:%s", bid, offsetHex),
				"function":        guessFunctionForBlock(bid, blockMap, art),
				"kind":            emitKind,
				"target":          targetExpr,
				"target_origin":   origin,
				"semantic_effect": nil,
				"trust": map[string]any{
					"source":                   "bytecode_inferred",
					"confidence":               0.7,
					"usable_as_detector_proof": true,
				},
			}
			switch origin {
			case "calldata":
				entry["target_controllability"] = "caller_controlled"
				if callForwardsValue(desc) {
					valueForwarding[entry["id"].(string)] = true
				}
				calldataTargets = append(calldataTargets, entry)
			case "storage":
				entry["target_controllability"] = "fixed_storage"
				hasStorageCallTargets = true
			default:
				entry["target_controllability"] = "unknown"
			}
		}
	}

	rows := []any{}
	for _, entry := range calldataTargets {
		entry["return_value_consumed"] = true
		entry["address_validation"] = "none"
		effects := []any{}
		if valueForwarding[entry["id"].(string)] {
			effects = []any{"asset_transfer", "call_value_forwarding"}
		} else if hasStorageCallTargets {
			effects = []any{"asset_transfer", "accounting_mutation"}
		}
		entry["return_flow_effects"] = effects
		entry["reachable_effects"] = effects
		entry["guard_refs"] = []any{}
		entry["evidence_refs"] = []any{entry["id"]}
		rows = append(rows, entry)
	}
	return rows
}

// enrichCalldataOriginCalls ports audit_json._enrich_calldata_origin_calls:
// a function making >= 3 calls to unresolved ("computed") targets is treated
// as accepting an attacker-supplied interface address.
func enrichCalldataOriginCalls(rows []any) {
	byFn := map[string][]map[string]any{}
	for _, rAny := range rows {
		r := asMap(rAny)
		fn := asString(r["function"])
		if fn == "" {
			continue
		}
		byFn[fn] = append(byFn[fn], r)
	}
	for _, fnRows := range byFn {
		computed := []map[string]any{}
		for _, r := range fnRows {
			k := asString(r["kind"])
			if asString(r["target_origin"]) == "computed" &&
				(k == "call" || k == "staticcall" || k == "external_call") {
				computed = append(computed, r)
			}
		}
		if len(computed) < minUnresolvedCallsForCalldata {
			continue
		}
		effects, _ := computed[0]["reachable_effects"].([]any)
		for _, e := range computed {
			e["target_origin"] = "calldata"
			e["target_controllability"] = "caller_controlled"
			e["address_validation"] = "none"
			if _, ok := e["return_value_consumed"]; !ok {
				e["return_value_consumed"] = true
			}
			if len(effects) > 0 {
				e["return_flow_effects"] = effects
			} else {
				e["return_flow_effects"] = []any{"accounting_mutation"}
			}
		}
	}
}

// extractCallTargetExpr ports audit_json._extract_call_target_expr: pull the
// to=... operand out of a sim call description.
func extractCallTargetExpr(desc string) string {
	idx := strings.Index(desc, "to=")
	if idx < 0 {
		return "unknown"
	}
	rest := desc[idx+3:]
	depth := 0
	end := len(rest)
	for i, ch := range rest {
		switch ch {
		case '(':
			depth++
		case ')':
			if depth == 0 {
				end = i
				goto done
			}
			depth--
		case ',', ' ':
			if depth == 0 {
				end = i
				goto done
			}
		}
	}
done:
	return strings.TrimRight(strings.TrimSpace(rest[:end]), ")")
}

// callForwardsValue reports whether a sim CALL description forwards non-zero
// ETH value (value=<expr> where expr is not a zero literal). Value forwarding
// to a caller-chosen target is itself an asset-transfer effect. staticcall /
// delegatecall carry no value operand and return false.
func callForwardsValue(desc string) bool {
	idx := strings.Index(desc, "value=")
	if idx < 0 {
		return false
	}
	rest := desc[idx+6:]
	depth := 0
	end := len(rest)
	for i, ch := range rest {
		switch ch {
		case '(':
			depth++
		case ')':
			if depth == 0 {
				end = i
				goto done
			}
			depth--
		case ',':
			if depth == 0 {
				end = i
				goto done
			}
		}
	}
done:
	v := strings.TrimSpace(rest[:end])
	switch v {
	case "", "0", "0x0", "0x00", "0x":
		return false
	}
	return true
}

// classifyUnreachableTarget ports audit_json._classify_unreachable_target.
func classifyUnreachableTarget(targetExpr string) string {
	text := strings.ToLower(targetExpr)
	if strings.Contains(text, "storage[") || strings.Contains(text, "storage_") {
		return "storage"
	}
	if text == "?" || text == "unknown" {
		return "calldata"
	}
	if strings.Contains(text, "calldataload") || strings.Contains(text, "calldata") {
		return "calldata"
	}
	if strings.Contains(text, "?") && !strings.Contains(text, "storage") {
		return "calldata"
	}
	if strings.HasPrefix(text, "0x") && len(text) >= 40 {
		return "fixed"
	}
	return "computed"
}

// guessFunctionForBlock ports audit_json._guess_function_for_block: nearest
// sliced-function body block by start offset.
func guessFunctionForBlock(bid int, blockMap map[int]int, art *pipeline.Artifacts) any {
	if art.Slice == nil {
		return nil
	}
	blockOffset, ok := blockMap[bid]
	if !ok {
		return nil
	}
	best := ""
	bestDist := math.MaxInt
	for _, fn := range art.Slice.Functions {
		for _, body := range fn.BodyBlocks {
			bo, ok := blockMap[body]
			if !ok {
				continue
			}
			d := blockOffset - bo
			if d < 0 {
				d = -d
			}
			if d < bestDist {
				bestDist = d
				best = fn.Selector
			}
		}
	}
	if best == "" {
		return nil
	}
	return best
}

// normalizeCallKind maps a Go action/call type or description to the kind
// vocabulary the detector engine matches on. Returns "" for non-call ops.
func normalizeCallKind(typ, desc string) string {
	t := strings.ToLower(typ)
	switch t {
	case "delegatecall":
		return "delegatecall"
	case "staticcall":
		return "staticcall"
	case "external_call", "call":
		return "external_call"
	}
	d := strings.ToLower(desc)
	switch {
	case strings.Contains(d, "delegatecall"):
		return "delegatecall"
	case strings.Contains(d, "staticcall"):
		return "staticcall"
	case strings.HasPrefix(d, "call") || strings.Contains(d, "call("):
		return "external_call"
	}
	return ""
}

func firstNonEmpty(vals ...any) any {
	for _, v := range vals {
		if s, ok := v.(string); ok && s != "" {
			return v
		}
		if v != nil {
			if _, isStr := v.(string); !isStr {
				return v
			}
		}
	}
	return nil
}

func economicIndex(art *pipeline.Artifacts, functions []any) []any {
	rows := []any{}
	for _, fnAny := range functions {
		fn := asMap(fnAny)
		sel := fnSelector(fn)
		for _, fAny := range asList(fn["accounting"]) {
			f := asMap(fAny)
			rows = append(rows, map[string]any{
				"id":               asString(f["id"]),
				"function":         sel,
				"kind":             orDefault(asString(f["kind"]), "accounting"),
				"economic_effects": f["economic_effects"],
				"asset":            f["asset"],
			})
		}
	}
	return rows
}

func initializerIndex(art *pipeline.Artifacts) []any {
	rows := []any{}
	for _, sAny := range slotIndex(art) {
		s := asMap(sAny)
		init := asMap(s["initializer"])
		if asBool(init["is_initializer_slot"]) {
			rows = append(rows, map[string]any{
				"slot":             s["slot"],
				"semantic_role":    s["semantic_role"],
				"single_use_guard": asBool(init["single_use_guard"]),
			})
		}
	}
	// Bytecode-level fallback: OZ Initializable detected but storage modeling
	// did not flag a slot (Go storage IR is lighter than Python's).
	if len(rows) == 0 && art.Fingerprint.HasInitializerPattern {
		rows = append(rows, map[string]any{
			"slot":             nil,
			"semantic_role":    "initializer",
			"single_use_guard": true,
		})
	}
	return rows
}

func evidenceIndex(art *pipeline.Artifacts, functions []any) []any {
	rows := []any{}
	for _, fnAny := range functions {
		fn := asMap(fnAny)
		sel := fnSelector(fn)
		for _, aAny := range asList(fn["actions"]) {
			a := asMap(aAny)
			rows = append(rows, map[string]any{
				"id":       asString(a["id"]),
				"kind":     "action",
				"function": sel,
				"offset":   a["offset"],
			})
		}
		for _, fAny := range asList(fn["accounting"]) {
			f := asMap(fAny)
			rows = append(rows, map[string]any{
				"id":       asString(f["id"]),
				"kind":     "accounting",
				"function": sel,
			})
		}
	}
	return rows
}

func libraryFingerprints(art *pipeline.Artifacts) []any {
	entries := art.Fingerprint.LibraryFingerprints()
	out := make([]any, len(entries))
	for i, e := range entries {
		out[i] = e
	}
	return out
}

// ── local any helpers (kept builder-local to avoid import cycles) ─────────

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

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func asBool(v any) bool {
	b, _ := v.(bool)
	return b
}

func asStringList(v any) []string {
	out := []string{}
	for _, e := range asList(v) {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
