// Package semantic emits PatternCard / FunctionCard / contract-family + risk
// summary by walking sliced functions, ABI, sim, and storage layout. Port of
// evm_decon/semantic_patterns.py + semantic_functions.py with simpler control
// flow and a single declarative pattern table.
package semantic

import (
	"fmt"
	"sort"
	"strings"

	"github.com/evm-auditor/evm-auditor/internal/decon/abi"
	"github.com/evm-auditor/evm-auditor/internal/decon/slicer"
	"github.com/evm-auditor/evm-auditor/internal/decon/stacksim"
	"github.com/evm-auditor/evm-auditor/internal/decon/storage"
)

// PatternCard mirrors evm_decon.semantic_patterns.PatternCard.
type PatternCard struct {
	Name       string
	Confidence float64
	Evidence   []string
	Details    map[string]any
}

// FunctionCard captures per-function semantics for downstream tag synthesis.
type FunctionCard struct {
	Selector       string
	Name           string
	Mutability     string
	Guards         []string
	StateReads     []string
	StateWrites    []string
	ExternalCalls  []string
	RiskFlags      []string
	BranchHints    []string
}

// Analysis is the combined result.
type Analysis struct {
	ContractFamily string
	Patterns       []PatternCard
	FunctionCards  []FunctionCard
	Standards      []map[string]any
	RiskSummary    []string
}

// Analyze runs all detectors. Cheap: one pass over functions per detector.
func Analyze(slc *slicer.Result, sl *storage.Result, abis []abi.Recovered, sim *stacksim.Result, resolved map[string]string) *Analysis {
	if slc == nil {
		return &Analysis{ContractFamily: "Unknown"}
	}
	names := buildNames(slc, resolved)
	abiBySel := map[string]abi.Recovered{}
	for _, a := range abis {
		abiBySel[a.Selector] = a
	}

	patterns := []PatternCard{}
	patterns = appendIfConf(patterns, detectOwnable(slc, names, sim, sl))
	patterns = appendIfConf(patterns, detectPausable(slc, names, sim))
	patterns = appendIfConf(patterns, detectERC20(slc, names))
	patterns = appendIfConf(patterns, detectERC2612(slc, names))
	patterns = appendIfConf(patterns, detectERC721(slc, names))
	patterns = appendIfConf(patterns, detectBlacklist(slc, names))
	patterns = appendIfConf(patterns, detectFeeToken(slc, names, sl))
	patterns = appendIfConf(patterns, detectMintBurn(slc, names))
	patterns = appendIfConf(patterns, detectERC4626(slc, names))
	patterns = appendIfConf(patterns, detectAccessControl(slc, names))
	patterns = appendIfConf(patterns, detectReentrancyGuard(slc, names, sim))

	sort.SliceStable(patterns, func(i, j int) bool { return patterns[i].Confidence > patterns[j].Confidence })

	cards := buildFunctionCards(slc, abiBySel, names, sim)

	highConf := []string{}
	seen := map[string]bool{}
	for _, p := range patterns {
		if p.Confidence < 0.6 {
			continue
		}
		if seen[p.Name] {
			continue
		}
		seen[p.Name] = true
		highConf = append(highConf, p.Name)
	}
	family := strings.Join(highConf, " + ")
	if family == "" {
		family = "Unknown"
	}

	return &Analysis{
		ContractFamily: family,
		Patterns:       patterns,
		FunctionCards:  cards,
		RiskSummary:    buildRiskSummary(patterns, cards),
	}
}

func buildNames(slc *slicer.Result, resolved map[string]string) map[string]string {
	out := map[string]string{}
	for _, fn := range slc.Functions {
		n := fn.Name
		if n == "" {
			n = resolved[fn.Selector]
		}
		if n == "" {
			n = resolved["0x"+strings.TrimPrefix(fn.Selector, "0x")]
		}
		if n == "" {
			n = fn.Selector
		}
		out[fn.Selector] = n
	}
	return out
}

func appendIfConf(p []PatternCard, c PatternCard) []PatternCard {
	if c.Confidence > 0.1 {
		return append(p, c)
	}
	return p
}

func detectOwnable(slc *slicer.Result, names map[string]string, sim *stacksim.Result, sl *storage.Result) PatternCard {
	ev, conf := []string{}, 0.0
	protected := map[string]struct{}{}
	if anyName(slc, names, contains("owner()")) {
		ev = append(ev, "owner() public getter exists")
		conf += 0.3
	}
	if anyName(slc, names, contains("transferOwnership")) {
		ev = append(ev, "transferOwnership(address) exists")
		conf += 0.2
	}
	guards := 0
	if sim != nil {
		for _, fn := range slc.Functions {
			for _, bid := range fn.BodyBlocks {
				tr, ok := sim.Traces[bid]
				if !ok || tr.BranchCondition == nil {
					continue
				}
				cond := tr.BranchCondition.String()
				if strings.Contains(cond, "msg.sender") && strings.Contains(cond, "storage[0x00]") {
					guards++
					protected[shortName(names[fn.Selector])] = struct{}{}
					break
				}
			}
		}
	}
	if guards > 0 {
		add := float64(guards) * 0.1
		if add > 0.4 {
			add = 0.4
		}
		conf += add
		ev = append(ev, fmt.Sprintf("msg.sender == owner guard in %d functions", guards))
	}
	if sl != nil {
		if s, ok := sl.Slots[0]; ok && (s.Kind == "packed" || s.ValueType == "address") {
			ev = append(ev, "slot 0 contains address (likely owner)")
			conf += 0.1
		}
	}
	if conf > 1 {
		conf = 1
	}
	keys := keysOf(protected)
	return PatternCard{Name: "Ownable", Confidence: conf, Evidence: ev, Details: map[string]any{"owner_slot": 0, "protected_functions": keys}}
}

func detectPausable(slc *slicer.Result, names map[string]string, sim *stacksim.Result) PatternCard {
	ev, conf := []string{}, 0.0
	guarded := map[string]struct{}{}
	if anyName(slc, names, eq("pause()")) {
		ev = append(ev, "pause() exists")
		conf += 0.3
	}
	if anyName(slc, names, eq("unpause()")) {
		ev = append(ev, "unpause() exists")
		conf += 0.2
	}
	if anyName(slc, names, eq("paused()")) {
		ev = append(ev, "paused() exists")
		conf += 0.2
	}
	if sim != nil {
		for _, fn := range slc.Functions {
			n := names[fn.Selector]
			if n == "pause()" || n == "unpause()" || n == "paused()" {
				continue
			}
			for _, bid := range fn.BodyBlocks {
				tr, ok := sim.Traces[bid]
				if !ok || tr.BranchCondition == nil {
					continue
				}
				cond := tr.BranchCondition.String()
				if strings.Contains(cond, "storage[0x00]") && strings.Contains(cond, "0xff") {
					guarded[shortName(n)] = struct{}{}
					break
				}
			}
		}
	}
	if len(guarded) > 0 {
		conf += 0.3
		ev = append(ev, fmt.Sprintf("whenNotPaused guard in %d funcs", len(guarded)))
	}
	if conf > 1 {
		conf = 1
	}
	return PatternCard{Name: "Pausable", Confidence: conf, Evidence: ev, Details: map[string]any{"guarded_methods": keysOf(guarded)}}
}

var erc20Required = map[string]string{
	"transfer":     "transfer(address,uint256)",
	"transferFrom": "transferFrom(address,address,uint256)",
	"approve":      "approve(address,uint256)",
	"allowance":    "allowance(address,address)",
	"balanceOf":    "balanceOf(address)",
	"totalSupply":  "totalSupply()",
}

func detectERC20(slc *slicer.Result, names map[string]string) PatternCard {
	have := map[string]bool{}
	for _, n := range names {
		have[n] = true
	}
	matched, ev := []string{}, []string{}
	for k, sig := range erc20Required {
		if have[sig] {
			matched = append(matched, k)
			ev = append(ev, sig+" present")
		}
	}
	conf := 0.0
	switch {
	case len(matched) == len(erc20Required):
		conf = 0.95
		ev = append(ev, "all 6 ERC-20 required functions present")
	case len(matched) >= 4:
		conf = 0.7
	case len(matched) >= 3:
		conf = 0.4
	default:
		conf = 0.1 * float64(len(matched))
	}
	for _, opt := range []string{"name()", "symbol()", "decimals()"} {
		if have[opt] {
			conf += 0.05
		}
	}
	if conf > 1 {
		conf = 1
	}
	sort.Strings(matched)
	return PatternCard{Name: "ERC20", Confidence: conf, Evidence: ev, Details: map[string]any{"matched_required": toAny(matched)}}
}

func detectERC2612(slc *slicer.Result, names map[string]string) PatternCard {
	have := map[string]bool{}
	for _, n := range names {
		have[n] = true
	}
	required := []string{
		"permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
		"DOMAIN_SEPARATOR()",
		"nonces(address)",
	}
	matched := []string{}
	for _, sig := range required {
		if have[sig] {
			matched = append(matched, sig)
		}
	}
	conf := float64(len(matched)) / float64(len(required))
	ev := []string{}
	for _, m := range matched {
		ev = append(ev, m+" present")
	}
	if len(matched) == len(required) {
		conf = 0.9
	}
	return PatternCard{Name: "EIP-2612 Permit", Confidence: conf, Evidence: ev, Details: map[string]any{"matched": toAny(matched)}}
}

func detectERC721(slc *slicer.Result, names map[string]string) PatternCard {
	have := map[string]bool{}
	for _, n := range names {
		have[n] = true
	}
	strict := []string{
		"ownerOf(uint256)",
		"safeTransferFrom(address,address,uint256)",
		"safeTransferFrom(address,address,uint256,bytes)",
	}
	count := 0
	for _, s := range strict {
		if have[s] {
			count++
		}
	}
	ev, conf := []string{}, 0.0
	switch {
	case count >= 2:
		conf = 0.8
		ev = append(ev, "ownerOf + safeTransferFrom present → likely ERC-721")
	case count == 1:
		conf = 0.4
	}
	if have["supportsInterface(bytes4)"] {
		conf += 0.1
		ev = append(ev, "supportsInterface(bytes4) present")
	}
	if conf > 1 {
		conf = 1
	}
	return PatternCard{Name: "ERC721", Confidence: conf, Evidence: ev}
}

func detectBlacklist(slc *slicer.Result, names map[string]string) PatternCard {
	ev, conf := []string{}, 0.0
	checks := map[string]float64{
		"addBlackList":        0.3,
		"removeBlackList":     0.2,
		"destroyBlackFunds":   0.3,
		"getBlackListStatus":  0.1,
		"isBlackListed":       0.1,
	}
	for k, w := range checks {
		if anyName(slc, names, contains(k)) {
			ev = append(ev, k+" exists")
			conf += w
		}
	}
	if conf > 1 {
		conf = 1
	}
	return PatternCard{Name: "Blacklist", Confidence: conf, Evidence: ev}
}

func detectFeeToken(slc *slicer.Result, names map[string]string, sl *storage.Result) PatternCard {
	ev, conf := []string{}, 0.0
	if anyName(slc, names, contains("basisPointsRate")) {
		ev = append(ev, "basisPointsRate() getter")
		conf += 0.35
	}
	if anyName(slc, names, contains("maximumFee")) {
		ev = append(ev, "maximumFee() getter")
		conf += 0.25
	}
	if anyName(slc, names, contains("setParams")) {
		ev = append(ev, "setParams() exists")
		conf += 0.3
	}
	if conf > 1 {
		conf = 1
	}
	return PatternCard{Name: "FeeToken", Confidence: conf, Evidence: ev}
}

func detectMintBurn(slc *slicer.Result, names map[string]string) PatternCard {
	ev, conf := []string{}, 0.0
	check := func(sub string, w float64, msg string) {
		if anyName(slc, names, containsLower(sub)) {
			ev = append(ev, msg)
			conf += w
		}
	}
	check("issue", 0.4, "issue(uint256)")
	check("redeem", 0.4, "redeem(uint256)")
	check("mint", 0.3, "mint exists")
	check("burn", 0.3, "burn exists")
	if conf > 1 {
		conf = 1
	}
	return PatternCard{Name: "MintBurn", Confidence: conf, Evidence: ev}
}

func detectERC4626(slc *slicer.Result, names map[string]string) PatternCard {
	have := map[string]bool{}
	for _, n := range names {
		have[n] = true
	}
	required := []string{
		"deposit(uint256,address)",
		"mint(uint256,address)",
		"withdraw(uint256,address,address)",
		"redeem(uint256,address,address)",
		"asset()",
		"totalAssets()",
	}
	matched := 0
	ev := []string{}
	for _, s := range required {
		if have[s] {
			matched++
			ev = append(ev, s+" present")
		}
	}
	conf := float64(matched) / float64(len(required))
	if matched >= 4 {
		conf = 0.85
	}
	return PatternCard{Name: "ERC4626", Confidence: conf, Evidence: ev}
}

func detectAccessControl(slc *slicer.Result, names map[string]string) PatternCard {
	have := map[string]bool{}
	for _, n := range names {
		have[n] = true
	}
	conf, ev := 0.0, []string{}
	if have["hasRole(bytes32,address)"] {
		conf += 0.4
		ev = append(ev, "hasRole present")
	}
	if have["grantRole(bytes32,address)"] {
		conf += 0.3
		ev = append(ev, "grantRole present")
	}
	if have["revokeRole(bytes32,address)"] {
		conf += 0.2
		ev = append(ev, "revokeRole present")
	}
	if have["DEFAULT_ADMIN_ROLE()"] {
		conf += 0.1
	}
	if conf > 1 {
		conf = 1
	}
	return PatternCard{Name: "OZAccessControl", Confidence: conf, Evidence: ev}
}

func detectReentrancyGuard(slc *slicer.Result, names map[string]string, sim *stacksim.Result) PatternCard {
	if sim == nil {
		return PatternCard{Name: "ReentrancyGuard"}
	}
	// Heuristic: look for SSTORE→external call→SSTORE on same constant slot in any function.
	hits := 0
	for _, fn := range slc.Functions {
		slots := map[string]int{} // slot → state machine: 0 nothing, 1 seen-sstore-pre, 2 seen-call, 3 sstore-post (guard)
		for _, bid := range fn.BodyBlocks {
			tr := sim.Traces[bid]
			if tr == nil {
				continue
			}
			for _, op := range tr.Operations {
				if op.Category == "call" {
					for k, v := range slots {
						if v == 1 {
							slots[k] = 2
						}
					}
				}
			}
			for _, sop := range tr.StorageOps {
				key := sop.Slot.String()
				if sop.OpType != "write" {
					continue
				}
				switch slots[key] {
				case 0:
					slots[key] = 1
				case 2:
					slots[key] = 3
					hits++
				}
			}
		}
	}
	if hits == 0 {
		return PatternCard{Name: "ReentrancyGuard"}
	}
	return PatternCard{Name: "ReentrancyGuard", Confidence: 0.7, Evidence: []string{fmt.Sprintf("write→call→write pattern in %d funcs", hits)}}
}

func buildFunctionCards(slc *slicer.Result, abis map[string]abi.Recovered, names map[string]string, sim *stacksim.Result) []FunctionCard {
	out := make([]FunctionCard, 0, len(slc.Functions))
	for _, fn := range slc.Functions {
		card := FunctionCard{
			Selector: fn.Selector,
			Name:     names[fn.Selector],
		}
		if a, ok := abis[fn.Selector]; ok {
			card.Mutability = a.Mutability
		}
		if sim != nil {
			for _, bid := range fn.BodyBlocks {
				tr := sim.Traces[bid]
				if tr == nil {
					continue
				}
				if tr.BranchCondition != nil {
					cond := tr.BranchCondition.String()
					card.BranchHints = append(card.BranchHints, cond)
					if strings.Contains(cond, "msg.sender") && strings.Contains(cond, "storage[") {
						card.Guards = appendUnique(card.Guards, "msg_sender_guard")
					}
					if strings.Contains(cond, "tx.origin") {
						card.Guards = appendUnique(card.Guards, "tx_origin_check")
					}
					if strings.Contains(cond, "msg.value") {
						card.Guards = appendUnique(card.Guards, "callvalue_guard")
					}
				}
				for _, op := range tr.Operations {
					if op.Category == "call" {
						card.ExternalCalls = appendUnique(card.ExternalCalls, op.Description)
					}
				}
				for _, sop := range tr.StorageOps {
					if sop.OpType == "read" {
						card.StateReads = appendUnique(card.StateReads, sop.Slot.String())
					} else {
						card.StateWrites = appendUnique(card.StateWrites, sop.Slot.String())
					}
				}
			}
		}
		out = append(out, card)
	}
	return out
}

func buildRiskSummary(patterns []PatternCard, cards []FunctionCard) []string {
	risks := []string{}
	for _, p := range patterns {
		if p.Confidence < 0.6 {
			continue
		}
		switch p.Name {
		case "Blacklist":
			risks = append(risks, "owner can freeze/destroy balances")
		case "FeeToken":
			risks = append(risks, "owner-configurable transfer fee")
		case "LegacyUpgradeForwarder":
			risks = append(risks, "calls forward to upgraded address (legacy proxy pattern)")
		}
	}
	return risks
}

// helpers
type pred func(string) bool

func contains(s string) pred       { return func(x string) bool { return strings.Contains(x, s) } }
func containsLower(s string) pred  { return func(x string) bool { return strings.Contains(strings.ToLower(x), s) } }
func eq(s string) pred             { return func(x string) bool { return x == s } }

func anyName(slc *slicer.Result, names map[string]string, p pred) bool {
	for _, fn := range slc.Functions {
		if p(names[fn.Selector]) {
			return true
		}
	}
	return false
}

func shortName(n string) string {
	if i := strings.IndexByte(n, '('); i >= 0 {
		return n[:i]
	}
	return n
}

func keysOf(m map[string]struct{}) []any {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	out := make([]any, len(ks))
	for i, k := range ks {
		out[i] = k
	}
	return out
}

func toAny(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// PatternsByName maps high-confidence pattern detections to behavior_tags
// consumed by the detector engine.
var PatternToTags = map[string][]string{
	"Ownable":         {"OZ_OWNABLE", "owner_check", "ownership_pattern"},
	"Pausable":        {"PAUSABLE", "pausable_guard"},
	"ERC20":           {"ERC20", "erc20_token_trait"},
	"ERC721":          {"ERC721"},
	"ERC4626":         {"erc4626_vault_trait", "ERC4626_DEPOSIT_OR_MINT"},
	"OZAccessControl": {"OZ_ACCESS_CONTROL", "role_admin_guard"},
	"EIP-2612 Permit": {"eip2612_permit", "DOMAIN_SEPARATOR_SLOT_READ"},
	"Blacklist":       {"BLACKLIST_PATTERN"},
	"FeeToken":        {"FEE_TOKEN_PATTERN"},
	"MintBurn":        {"mint", "burn"},
	"ReentrancyGuard": {"REENTRANCY_GUARD", "OZ_REENTRANCY_GUARD", "reentrancy_guard"},
}
