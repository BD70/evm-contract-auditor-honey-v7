// Package builder emits behavior.v2 from the Go decon pipeline.
//
// Standalone Go path (no Python subprocess). Tag synthesis combines:
//   1. opcode-presence facts (from sim + patterns)
//   2. action-ordering facts (STATE_WRITE_AFTER_CALL, SSTORE_BEFORE_CALL_ONLY)
//   3. semantic pattern cards (Ownable → OZ_OWNABLE, ERC4626 → erc4626_vault_trait, …)
//   4. ERC4626 withdraw-authorization tags (port of audit_json._erc4626_tags)
//   5. accounting/asset-transfer tags from external-call inference
//   6. global proxy/security flags
//
// Schema-valid behavior.v2 ready for the detector engine.
package builder

import (
	"fmt"
	"sort"
	"strings"

	"github.com/evm-auditor/evm-auditor/internal/decon/abi"
	"github.com/evm-auditor/evm-auditor/internal/decon/pipeline"
	"github.com/evm-auditor/evm-auditor/internal/decon/semantic"
	"github.com/evm-auditor/evm-auditor/internal/decon/stacksim"
	"github.com/evm-auditor/evm-auditor/pkg/schema"
)

// Build produces a behavior.v2 dictionary from artifacts.
func Build(art *pipeline.Artifacts) map[string]any {
	abiBySel := indexABI(art.ABI)
	cardBySel := indexCards(art.Semantic)
	contractTags := contractLevelTags(art)

	functions := []any{}
	if art.Slice != nil && len(art.Slice.Functions) > 0 {
		for _, fn := range art.Slice.Functions {
			body := make([]any, 0, len(fn.BodyBlocks))
			for _, b := range fn.BodyBlocks {
				body = append(body, b)
			}
			tags := functionTags(art, fn.BodyBlocks, fn.Selector, cardBySel, contractTags)
			actions := functionActions(art, fn.BodyBlocks)
			calls := functionExternalCalls(art, fn.BodyBlocks)
			rec := abiBySel[fn.Selector]
			functions = append(functions, map[string]any{
				"identity": map[string]any{
					"selector":   fn.Selector,
					"name":       nullableString(fn.Name),
					"mutability": rec.Mutability,
					"arg_count":  rec.ArgCount,
					"arg_types":  toAny(rec.ArgTypes),
				},
				"entry_pc":       fn.EntryPC,
				"body_blocks":    body,
				"behavior_tags":  tags,
				"tags":           tags,
				"actions":        actions,
				"flows":          []any{},
				"external_calls": calls,
				"arithmetic":     []any{},
				"accounting":     []any{},
				"state": map[string]any{
					"reads":  functionReads(art, fn.BodyBlocks),
					"writes": functionWrites(art, fn.BodyBlocks),
					"guards": cardGuards(cardBySel[fn.Selector]),
				},
				"evidence": map[string]any{
					"semantic": map[string]any{
						"branches": cardBranches(cardBySel[fn.Selector]),
					},
				},
			})
		}
	} else {
		for _, sel := range art.Selectors.Selectors {
			functions = append(functions, map[string]any{
				"identity": map[string]any{
					"selector": sel.Selector,
					"name":     nil,
				},
				"behavior_tags":  []any{},
				"tags":           []any{},
				"actions":        []any{},
				"flows":          []any{},
				"external_calls": []any{},
				"arithmetic":     []any{},
				"accounting":     []any{},
				"state": map[string]any{
					"reads":  []any{},
					"writes": []any{},
					"guards": []any{},
				},
			})
		}
	}

	stateModel := map[string]any{
		"schema":            schema.StateModelSchemaV2,
		"schema_version":    "2.0.0",
		"storage_entities":  storageEntities(art),
		"slot_index":        slotIndex(art),
		"path_index":        pathIndex(art, functions),
		"guard_catalog":     guardCatalog(art, cardBySel),
		"call_index":        callIndex(art, functions),
		"economic_index":    economicIndex(art, functions),
		"proxy_index":         proxyIndex(art),
		"initializer_index":   initializerIndex(art),
		"evidence_index":      evidenceIndex(art, functions),
		"library_fingerprints": libraryFingerprints(art),
	}

	coverage := map[string]any{
		"function_coverage":                   1.0,
		"unknown_action_expression_count":     0,
		"unresolved_selector_count":           0,
		"unresolved_path_count":               0,
		"storage_role_confidence":             storageConfidence(art),
		"path_reachability_confidence":        0.7,
		"external_call_resolution_confidence": 0.7,
		"has_unmodeled_terminators":           false,
	}

	bytecodeMeta := map[string]any{
		"runtime_size":      len(art.RuntimeBytecodeHex) / 2,
		"analysis_size":     len(art.AnalysisBytecodeHex) / 2,
		"metadata_stripped": art.AnalysisBytecodeHex != art.RuntimeBytecodeHex,
		"runtime_hash":      art.RuntimeHash,
		"analysis_hash":     art.AnalysisHash,
	}

	contract := map[string]any{
		"compiler": compilerInfo(art),
		"family":   contractFamily(art),
		"patterns": patternCardsAsAny(art),
	}
	bytecodeIdentity := map[string]any{
		"keccak256":     art.AnalysisHash,
		"runtime_hash":  art.RuntimeHash,
		"original_hash": art.OriginalHash,
	}

	return map[string]any{
		"schema":               schema.BehaviorSchemaV2,
		"schema_version":       schema.BehaviorSchemaVersion,
		"engine_version":       "0.2.0-go",
		"ruleset_version":      "1.0.0",
		"bytecode_identity":    bytecodeIdentity,
		"bytecode":             bytecodeMeta,
		"contract":             contract,
		"functions":            functions,
		"storage":              map[string]any{"slots": slotIndex(art)},
		"memory":               map[string]any{},
		"arithmetic":           map[string]any{},
		"calls":                globalCalls(art),
		"events":               []any{},
		"flows":                []any{},
		"invariants":           []any{},
		"assumptions":          []any{},
		"analysis_warnings":    warnings(art),
		"coverage":             coverage,
		"state_model":          stateModel,
		"checker_findings":     []any{},
		"global_tags":          globalTags(art, contractTags),
		"bytecode_fingerprint": fingerprint(art),
	}
}

// ── tag synthesis ────────────────────────────────────────────

func functionTags(art *pipeline.Artifacts, body []int, selector string, cards map[string]semantic.FunctionCard, contractTags []string) []any {
	tags := map[string]struct{}{}
	add := func(t string) {
		if t != "" {
			tags[t] = struct{}{}
		}
	}
	for _, t := range contractTags {
		add(t)
	}
	if art.Sim != nil {
		hasCall, hasStaticcall, hasDelegatecall := false, false, false
		hasSstore, hasSload := false, false
		hasOrigin, hasSelfdestruct, hasCreate2 := false, false, false
		sstoreBefore, sstoreAfter := false, false
		sawCallYet := false
		for _, bid := range body {
			tr, ok := art.Sim.Traces[bid]
			if !ok {
				continue
			}
			for _, op := range tr.Operations {
				d := op.Description
				dl := strings.ToLower(d)
				switch {
				case strings.Contains(dl, "delegatecall"):
					hasDelegatecall = true
					sawCallYet = true
				case strings.Contains(dl, "staticcall"):
					hasStaticcall = true
					sawCallYet = true
				case strings.HasPrefix(d, "CALL ") || strings.Contains(dl, "call("):
					hasCall = true
					sawCallYet = true
				case strings.HasPrefix(d, "SELFDESTRUCT"):
					hasSelfdestruct = true
				case strings.HasPrefix(d, "CREATE2"):
					hasCreate2 = true
				}
				if strings.Contains(dl, "tx.origin") {
					hasOrigin = true
				}
			}
			for _, sop := range tr.StorageOps {
				if sop.OpType == "write" {
					hasSstore = true
					if sawCallYet {
						sstoreAfter = true
					} else {
						sstoreBefore = true
					}
				} else {
					hasSload = true
				}
			}
		}
		if hasCall || hasStaticcall || hasDelegatecall {
			add("EXTERNAL_CALL_OBSERVED")
			add("authorize_external_call")
		}
		if hasStaticcall && !hasCall && !hasDelegatecall {
			add("STATICCALL_ONLY")
		}
		if hasDelegatecall {
			add("delegatecall")
			add("HAS_DELEGATECALL")
		}
		if hasSelfdestruct {
			add("selfdestruct")
		}
		if hasCreate2 {
			add("HAS_CREATE2")
		}
		if hasOrigin {
			add("TX_ORIGIN_OBSERVED")
			add("ambiguous_origin_usage")
		}
		if hasSstore {
			add("state_mutation")
		}
		if hasSload {
			add("state_read")
		}
		if sstoreAfter {
			add("STATE_WRITE_AFTER_CALL")
		}
		if sstoreBefore && !sstoreAfter {
			add("SSTORE_BEFORE_CALL_ONLY")
		}
	}

	card, ok := cards[selector]
	if ok {
		for _, g := range card.Guards {
			add(g)
		}
		fnName := strings.ToLower(card.Name)
		if strings.Contains(fnName, "transfer") {
			add("asset_transfer")
		}
		if strings.HasPrefix(fnName, "approve(") {
			add("APPROVE_SELECTOR_EXPOSED")
			add("eip2612_permit")
		}
		if strings.HasPrefix(fnName, "permit(") {
			add("eip2612_permit")
			add("eip712_typed_hash_guard")
		}
		if strings.HasPrefix(fnName, "withdraw(") || strings.HasPrefix(fnName, "redeem(") {
			if strings.Contains(fnName, "address,address)") {
				add("withdraw_or_redeem_override")
				erc4626Tags := erc4626WithdrawTags(card, contractTags)
				for _, t := range erc4626Tags {
					add(t)
				}
			}
		}
		if strings.HasPrefix(fnName, "deposit(") || strings.HasPrefix(fnName, "mint(") {
			add("ERC4626_DEPOSIT_OR_MINT")
		}
		if strings.HasPrefix(fnName, "owner()") || strings.Contains(fnName, "transferownership") {
			add("OZ_OWNABLE")
			add("owner_check")
		}
	}

	// Propagate bytecode fingerprint tags so function-scope rules can use them
	// for counter-evidence (port of audit_json.py:72-75).
	for _, t := range art.Fingerprint.Tags {
		add(t)
	}

	out := make([]any, 0, len(tags))
	for t := range tags {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].(string) < out[j].(string) })
	return out
}

// erc4626WithdrawTags ports audit_json._erc4626_tags: derive caller-auth /
// allowance-check absence from per-function evidence on a 3-arg withdraw/redeem.
func erc4626WithdrawTags(card semantic.FunctionCard, contractTags []string) []string {
	out := []string{}
	is4626 := false
	for _, t := range contractTags {
		if t == "erc4626_vault_trait" {
			is4626 = true
			break
		}
	}
	if !is4626 {
		return out
	}
	allText := strings.ToLower(strings.Join(append(append([]string{}, card.ExternalCalls...), card.BranchHints...), " "))
	if strings.Contains(allText, "burn") && strings.Contains(allText, "owner") {
		out = append(out, "burn_target_is_owner_param")
	}
	if (strings.Contains(allText, "safetransfer") || strings.Contains(allText, "transfer(")) && strings.Contains(allText, "receiver") {
		out = append(out, "asset_transfer_target_is_receiver_param")
	}
	authPresent := false
	for _, g := range card.Guards {
		gl := strings.ToLower(g)
		if strings.Contains(gl, "msg.sender") || strings.Contains(gl, "caller") || strings.Contains(gl, "spendallowance") || strings.Contains(gl, "owner") {
			authPresent = true
			break
		}
	}
	if !authPresent {
		out = append(out, "caller_owner_authorization_absent")
		out = append(out, "allowance_check_absent")
	}
	return out
}

// ── helpers / artifact extractors ────────────────────────────

func contractLevelTags(art *pipeline.Artifacts) []string {
	tags := map[string]struct{}{}
	add := func(t string) { tags[t] = struct{}{} }
	if art.Patterns.Security.HasSelfdestruct {
		add("HAS_SELFDESTRUCT")
		add("selfdestruct")
	}
	if art.Patterns.Security.HasDelegatecall {
		add("HAS_DELEGATECALL")
		add("delegatecall")
	}
	if art.Patterns.Security.HasOrigin {
		add("USES_TX_ORIGIN")
		add("TX_ORIGIN_OBSERVED")
	}
	if art.Patterns.Security.HasCreate2 {
		add("HAS_CREATE2")
	}
	if art.Patterns.Security.HasStaticcall {
		add("HAS_STATICCALL")
	}
	if art.Patterns.Proxy.IsProxy {
		add("PROXY_FORWARDING_PATTERN")
		add("KNOWN_SAFE_PROXY_PATTERN")
		add(art.Patterns.Proxy.ProxyType)
		switch art.Patterns.Proxy.ProxyType {
		case "ERC1967_PROXY", "ERC-1967":
			add("ERC1967_PROXY")
			add("ERC-1967")
		case "ERC1167_CLONE":
			add("ERC1167_CLONE")
		case "UUPS_PROXY":
			add("UUPS_PROXY")
		case "TRANSPARENT_PROXY":
			add("TRANSPARENT_PROXY")
		case "BEACON_PROXY":
			add("BEACON_PROXY")
		case "DIAMOND_PROXY":
			add("DIAMOND_PROXY")
			add("EIP2535_DIAMOND")
		}
	}
	if art.Semantic != nil {
		for _, p := range art.Semantic.Patterns {
			if p.Confidence < 0.6 {
				continue
			}
			for _, t := range semantic.PatternToTags[p.Name] {
				add(t)
			}
		}
	}
	return mapKeys(tags)
}

func functionReads(art *pipeline.Artifacts, body []int) []any {
	out := []any{}
	if art.Sim == nil {
		return out
	}
	for _, bid := range body {
		tr, ok := art.Sim.Traces[bid]
		if !ok {
			continue
		}
		for _, op := range tr.StorageOps {
			if op.OpType != "read" {
				continue
			}
			out = append(out, map[string]any{
				"slot":   op.Slot.String(),
				"offset": op.OffsetInCode,
				"block":  bid,
			})
		}
	}
	return out
}

func functionWrites(art *pipeline.Artifacts, body []int) []any {
	out := []any{}
	if art.Sim == nil {
		return out
	}
	for _, bid := range body {
		tr, ok := art.Sim.Traces[bid]
		if !ok {
			continue
		}
		for _, op := range tr.StorageOps {
			if op.OpType != "write" {
				continue
			}
			entry := map[string]any{
				"slot":   op.Slot.String(),
				"offset": op.OffsetInCode,
				"block":  bid,
			}
			if op.Value != nil {
				entry["value"] = op.Value.String()
			}
			out = append(out, entry)
		}
	}
	return out
}

func functionActions(art *pipeline.Artifacts, body []int) []any {
	out := []any{}
	if art.Sim == nil {
		return out
	}
	for _, bid := range body {
		tr, ok := art.Sim.Traces[bid]
		if !ok {
			continue
		}
		for _, op := range tr.Operations {
			out = append(out, map[string]any{
				"id":          fmt.Sprintf("op:%d:%d", bid, op.Offset),
				"type":        actionType(op),
				"offset":      op.Offset,
				"block":       bid,
				"description": op.Description,
			})
		}
	}
	return out
}

func actionType(op stacksim.OperationRecord) string {
	d := strings.ToLower(op.Description)
	switch {
	case strings.Contains(d, "delegatecall"):
		return "delegatecall"
	case strings.Contains(d, "staticcall"):
		return "external_call"
	case strings.HasPrefix(d, "call") || strings.Contains(d, "call("):
		return "external_call"
	case op.Category == "storage" && strings.Contains(d, "<-"):
		return "state_write"
	case op.Category == "storage":
		return "state_read"
	case strings.HasPrefix(d, "selfdestruct"):
		return "selfdestruct"
	}
	return op.Category
}

func functionExternalCalls(art *pipeline.Artifacts, body []int) []any {
	out := []any{}
	if art.Sim == nil {
		return out
	}
	for _, bid := range body {
		tr, ok := art.Sim.Traces[bid]
		if !ok {
			continue
		}
		for _, op := range tr.Operations {
			if op.Category != "call" {
				continue
			}
			out = append(out, map[string]any{
				"offset":      op.Offset,
				"block":       bid,
				"description": op.Description,
				"target":      op.Description,
				"kind":        actionType(op),
			})
		}
	}
	return out
}

func globalCalls(art *pipeline.Artifacts) []any {
	out := []any{}
	if art.Sim == nil {
		return out
	}
	for bid, tr := range art.Sim.Traces {
		for _, op := range tr.Operations {
			if op.Category != "call" {
				continue
			}
			out = append(out, map[string]any{
				"offset": op.Offset,
				"block":  bid,
				"kind":   actionType(op),
			})
		}
	}
	return out
}

func storageEntities(art *pipeline.Artifacts) []any {
	if art.Storage == nil {
		return []any{}
	}
	keys := make([]int, 0, len(art.Storage.Slots))
	for k := range art.Storage.Slots {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	out := make([]any, 0, len(keys))
	for _, k := range keys {
		s := art.Storage.Slots[k]
		out = append(out, map[string]any{
			"slot":       s.Slot,
			"name":       nullableString(s.Name),
			"kind":       s.Kind,
			"value_type": nullableString(s.ValueType),
			"key_types":  toAny(s.KeyTypes),
			"confidence": s.Confidence,
		})
	}
	return out
}

func slotIndex(art *pipeline.Artifacts) []any {
	if art.Storage == nil {
		return []any{}
	}
	keys := make([]int, 0, len(art.Storage.Slots))
	for k := range art.Storage.Slots {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	out := make([]any, 0, len(keys))
	for _, k := range keys {
		s := art.Storage.Slots[k]
		out = append(out, map[string]any{
			"slot":         s.Slot,
			"name":         nullableString(s.Name),
			"kind":         s.Kind,
			"accessed_by":  toAny(s.AccessedBy),
		})
	}
	return out
}

func proxyIndex(art *pipeline.Artifacts) []any {
	if !art.Patterns.Proxy.IsProxy {
		return []any{}
	}
	return []any{map[string]any{
		"proxy_standard":         art.Patterns.Proxy.ProxyType,
		"slot_kind":              art.Patterns.Proxy.Details["pattern"],
		"implementation_address": art.Patterns.Proxy.ImplementationAddress,
	}}
}

func guardCatalog(art *pipeline.Artifacts, cards map[string]semantic.FunctionCard) []any {
	out := []any{}
	for sel, card := range cards {
		if len(card.Guards) == 0 {
			continue
		}
		out = append(out, map[string]any{
			"function": sel,
			"guards":   toAny(card.Guards),
		})
	}
	return out
}

func storageConfidence(art *pipeline.Artifacts) float64 {
	if art.Storage == nil || len(art.Storage.Slots) == 0 {
		return 0.5
	}
	sum := 0.0
	for _, s := range art.Storage.Slots {
		sum += s.Confidence
	}
	return sum / float64(len(art.Storage.Slots))
}

func compilerInfo(art *pipeline.Artifacts) map[string]any {
	if art.Metadata.Compiler == nil {
		return map[string]any{"name": "unknown", "version": nil}
	}
	return map[string]any{
		"name":    art.Metadata.Compiler.Name,
		"version": art.Metadata.Compiler.Version,
	}
}

func contractFamily(art *pipeline.Artifacts) string {
	if art.Semantic == nil {
		return "Unknown"
	}
	return art.Semantic.ContractFamily
}

func patternCardsAsAny(art *pipeline.Artifacts) []any {
	if art.Semantic == nil {
		return []any{}
	}
	out := []any{}
	for _, p := range art.Semantic.Patterns {
		out = append(out, map[string]any{
			"name":       p.Name,
			"confidence": p.Confidence,
			"evidence":   toAny(p.Evidence),
		})
	}
	return out
}

func warnings(art *pipeline.Artifacts) []any {
	out := []any{}
	for _, w := range art.PipelineWarnings {
		out = append(out, map[string]any{
			"id":       "pipeline_truncated",
			"message":  w,
			"severity": "info",
		})
	}
	if art.Metadata.Errors != nil {
		for _, e := range art.Metadata.Errors {
			out = append(out, map[string]any{
				"id":       "metadata_decode_failed",
				"message":  e,
				"severity": "info",
			})
		}
	}
	return out
}

func globalTags(art *pipeline.Artifacts, contractTags []string) []any {
	// Port of audit_json.py:88 — sorted(set(behavior global_tags) | fingerprint_tags).
	set := map[string]struct{}{}
	for _, t := range contractTags {
		set[t] = struct{}{}
	}
	for _, t := range art.Fingerprint.Tags {
		set[t] = struct{}{}
	}
	out := make([]any, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].(string) < out[j].(string) })
	return out
}

// fingerprint mirrors audit_json.py bytecode_fingerprint block.
func fingerprint(art *pipeline.Artifacts) map[string]any {
	fp := art.Fingerprint
	tags := make([]any, len(fp.Tags))
	for i, t := range fp.Tags {
		tags[i] = t
	}
	sels := make([]any, len(fp.ProxySelectorsFound))
	for i, s := range fp.ProxySelectorsFound {
		sels[i] = s
	}
	bridgeSels := make([]any, len(fp.BridgeSelectorsFound))
	for i, s := range fp.BridgeSelectorsFound {
		bridgeSels[i] = s
	}
	vaultSels := make([]any, len(fp.ERC4626SelectorsFound))
	for i, s := range fp.ERC4626SelectorsFound {
		vaultSels[i] = s
	}
	return map[string]any{
		"tags":                    tags,
		"proxy_type":              nullableString(fp.ProxyType),
		"has_erc1967":             fp.HasERC1967ImplSlot,
		"has_proxy_forwarding":    fp.HasProxyForwarding,
		"has_reentrancy_guard":    fp.HasReentrancyGuardConstants,
		"has_initializer":         fp.HasInitializerPattern,
		"has_diamond":             fp.HasDiamond,
		"has_gnosis_safe":         fp.HasGnosisSafe,
		"has_compound_unitroller": fp.HasCompoundUnitroller,
		"has_eip897":              fp.HasEIP897,
		"has_slot0_proxy":         fp.HasSlot0Proxy,
		"implementation_address":  nullableString(fp.ImplementationAddress),
		"diamond_loupe_selectors": fp.DiamondLoupeSelectors,
		"proxy_selectors":         sels,
		"has_bridge_pattern":      fp.HasBridgePattern,
		"bridge_selectors":        bridgeSels,
		"has_erc4626_pattern":     fp.HasERC4626Pattern,
		"erc4626_selectors":       vaultSels,
	}
}

// ── tiny helpers ─────────────────────────────────────────────

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func indexABI(rs []abi.Recovered) map[string]abi.Recovered {
	out := map[string]abi.Recovered{}
	for _, r := range rs {
		out[r.Selector] = r
	}
	return out
}

func indexCards(s *semantic.Analysis) map[string]semantic.FunctionCard {
	if s == nil {
		return map[string]semantic.FunctionCard{}
	}
	out := map[string]semantic.FunctionCard{}
	for _, c := range s.FunctionCards {
		out[c.Selector] = c
	}
	return out
}

func cardGuards(c semantic.FunctionCard) []any {
	return toAny(c.Guards)
}

func cardBranches(c semantic.FunctionCard) []any {
	return toAny(c.BranchHints)
}

func toAny(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

func mapKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
