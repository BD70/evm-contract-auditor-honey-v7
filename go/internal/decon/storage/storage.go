// Package storage recovers Solidity-style storage layout from sim traces:
// constant slots, getter-anchored names, mapping/nested-mapping/packed/string
// classification. Port of evm_decon/storage_layout.py with cleaner control
// flow — getter anchors as table-driven map, packed detection via simple
// regex over stack annotations.
package storage

import (
	"regexp"
	"strconv"

	"github.com/evm-auditor/evm-auditor/internal/decon/slicer"
	"github.com/evm-auditor/evm-auditor/internal/decon/stacksim"
)

// SlotInfo mirrors Python StorageSlotInfo.
type SlotInfo struct {
	Slot       int
	Kind       string   // value | mapping | nested_mapping | dynamic_array | string | packed
	Name       string
	ValueType  string
	KeyTypes   []string
	Packing    []map[string]any
	Confidence float64
	Evidence   []string
	AccessedBy []string
}

// Result mirrors Python StorageLayoutResult.
type Result struct {
	Slots              map[int]*SlotInfo
	MappingAccesses    []map[string]any
	UnresolvedAccesses []map[string]any
}

type getterMeta struct {
	Name      string
	Kind      string
	ValueType string
	KeyTypes  []string
}

var getterToSlot = map[string]getterMeta{
	"balances(address)":           {"balances", "mapping", "uint256", []string{"address"}},
	"allowed(address,address)":    {"allowed", "nested_mapping", "uint256", []string{"address", "address"}},
	"isBlackListed(address)":      {"isBlackListed", "mapping", "bool", []string{"address"}},
	"balanceOf(address)":          {"balanceOf", "mapping", "uint256", []string{"address"}},
	"allowance(address,address)":  {"allowance", "nested_mapping", "uint256", []string{"address", "address"}},
	"getBlackListStatus(address)": {"isBlackListed", "mapping", "bool", []string{"address"}},
	"owner()":                     {"owner", "packed", "address", nil},
	"paused()":                    {"paused", "packed", "bool", nil},
	"name()":                      {"name", "string", "string", nil},
	"symbol()":                    {"symbol", "string", "string", nil},
	"decimals()":                  {"decimals", "value", "uint256", nil},
	"totalSupply()":               {"_totalSupply", "value", "uint256", nil},
	"_totalSupply()":              {"_totalSupply", "value", "uint256", nil},
	"deprecated()":                {"deprecated", "packed", "bool", nil},
	"upgradedAddress()":           {"upgradedAddress", "packed", "address", nil},
	"basisPointsRate()":           {"basisPointsRate", "value", "uint256", nil},
	"maximumFee()":                {"maximumFee", "value", "uint256", nil},
	"DOMAIN_SEPARATOR()":          {"DOMAIN_SEPARATOR", "value", "bytes32", nil},
	"nonces(address)":             {"nonces", "mapping", "uint256", []string{"address"}},
	"factory()":                   {"factory", "value", "address", nil},
	"token0()":                    {"token0", "value", "address", nil},
	"token1()":                    {"token1", "value", "address", nil},
	"price0CumulativeLast()":      {"price0CumulativeLast", "value", "uint256", nil},
	"price1CumulativeLast()":      {"price1CumulativeLast", "value", "uint256", nil},
	"kLast()":                     {"kLast", "value", "uint256", nil},
}

var slotRe = regexp.MustCompile(`storage\[0x([0-9a-fA-F]+)\]`)

// Recover walks sim traces and returns a typed storage layout.
func Recover(sim *stacksim.Result, slice *slicer.Result, resolved map[string]string) *Result {
	res := &Result{
		Slots:              map[int]*SlotInfo{},
		MappingAccesses:    []map[string]any{},
		UnresolvedAccesses: []map[string]any{},
	}
	if sim == nil {
		return res
	}

	owningSelector := func(bid int) string {
		if slice == nil {
			return ""
		}
		return slice.BlockToFunction[bid]
	}

	for bid, tr := range sim.Traces {
		for _, op := range tr.StorageOps {
			slotStr := op.Slot.String()
			owner := owningSelector(bid)
			if op.Slot.IsConst() {
				slotNum := int(op.Slot.Const.Int64())
				ensureSlot(res.Slots, slotNum)
				if owner != "" && !contains(res.Slots[slotNum].AccessedBy, owner) {
					res.Slots[slotNum].AccessedBy = append(res.Slots[slotNum].AccessedBy, owner)
				}
				continue
			}
			rec := map[string]any{
				"block":          bid,
				"slot_expr":      slotStr,
				"op_type":        op.OpType,
				"owning_selector": owner,
			}
			if containsSubstr(slotStr, "keccak256") {
				res.MappingAccesses = append(res.MappingAccesses, rec)
				continue
			}
			res.UnresolvedAccesses = append(res.UnresolvedAccesses, rec)
		}
	}

	if slice != nil {
		for _, fn := range slice.Functions {
			meta, ok := getterToSlot[fn.Name]
			if !ok {
				continue
			}
			for _, bid := range fn.BodyBlocks {
				tr, ok := sim.Traces[bid]
				if !ok {
					continue
				}
				for _, op := range tr.StorageOps {
					if op.OpType != "read" || !op.Slot.IsConst() {
						continue
					}
					slotNum := int(op.Slot.Const.Int64())
					ensureSlot(res.Slots, slotNum)
					info := res.Slots[slotNum]
					if meta.Kind == "mapping" || meta.Kind == "nested_mapping" {
						continue
					}
					if meta.Name != "" {
						if meta.Kind == "packed" {
							info.Packing = append(info.Packing, map[string]any{
								"name": meta.Name,
								"type": meta.ValueType,
							})
							if info.Name == "" {
								info.Name = meta.Name + "_packed"
							}
						} else if info.Name == "" {
							info.Name = meta.Name
						}
					}
					if meta.Kind != "" && info.Kind != "packed" {
						info.Kind = meta.Kind
					}
					if meta.ValueType != "" && info.ValueType == "" {
						info.ValueType = meta.ValueType
					}
					if len(meta.KeyTypes) > 0 && len(info.KeyTypes) == 0 {
						info.KeyTypes = append(info.KeyTypes, meta.KeyTypes...)
					}
					if info.Confidence < 0.9 {
						info.Confidence = 0.9
					}
					info.Evidence = append(info.Evidence, "getter "+fn.Name+" reads slot")
				}
			}
		}
	}

	applyERC20Anchor(res, resolved)
	detectPacked(res, sim)
	detectStrings(res, sim)
	return res
}

func applyERC20Anchor(res *Result, resolved map[string]string) {
	names := map[string]struct{}{}
	for _, n := range resolved {
		names[n] = struct{}{}
	}
	_, a := names["totalSupply()"]
	_, b := names["balanceOf(address)"]
	_, c := names["allowance(address,address)"]
	if !(a && b && c) {
		return
	}
	defaults := map[int]getterMeta{
		0: {"totalSupply", "value", "uint256", nil},
		1: {"balanceOf", "mapping", "uint256", []string{"address"}},
		2: {"allowance", "nested_mapping", "uint256", []string{"address", "address"}},
	}
	for slot, meta := range defaults {
		ensureSlot(res.Slots, slot)
		info := res.Slots[slot]
		if info.Name != "" {
			continue
		}
		info.Name = meta.Name
		info.Kind = meta.Kind
		info.ValueType = meta.ValueType
		info.KeyTypes = append([]string(nil), meta.KeyTypes...)
		if info.Confidence < 0.8 {
			info.Confidence = 0.8
		}
		info.Evidence = append(info.Evidence, "ERC20 getter anchor")
	}
}

func detectPacked(res *Result, sim *stacksim.Result) {
	for bid, tr := range sim.Traces {
		for _, ann := range tr.StackAnnotations {
			if !containsSubstr(ann, "storage[") {
				continue
			}
			m := slotRe.FindStringSubmatch(ann)
			if m == nil {
				continue
			}
			slotNum, err := strconv.ParseInt(m[1], 16, 64)
			if err != nil {
				continue
			}
			info := ensureSlot(res.Slots, int(slotNum))
			switch {
			case containsSubstr(ann, "& 0xff"):
				if info.Kind == "value" && info.ValueType == "address" {
					info.Evidence = append(info.Evidence, "address mask in block")
					_ = bid
				} else if info.Kind == "value" {
					info.Kind = "packed"
					info.Evidence = append(info.Evidence, "byte-masked access")
				}
			case containsSubstr(ann, "ffffffffffffffffffffffffffffffffffffffff"):
				if info.Kind == "value" {
					info.Kind = "packed"
					if len(info.Packing) == 0 {
						info.Packing = []map[string]any{
							{"offset": 0, "width": 160, "type": "address"},
						}
					}
					info.Evidence = append(info.Evidence, "address-masked access")
				}
			}
		}
	}
}

func detectStrings(res *Result, sim *stacksim.Result) {
	for _, tr := range sim.Traces {
		for _, ann := range tr.StackAnnotations {
			if !(containsSubstr(ann, "storage[") && containsSubstr(ann, "& 0x01")) {
				continue
			}
			m := slotRe.FindStringSubmatch(ann)
			if m == nil {
				continue
			}
			slotNum, err := strconv.ParseInt(m[1], 16, 64)
			if err != nil || slotNum < 7 {
				continue
			}
			info := ensureSlot(res.Slots, int(slotNum))
			info.Kind = "string"
			info.ValueType = "string"
			info.Evidence = append(info.Evidence, "bit-0 check pattern (string length)")
		}
	}
}

func ensureSlot(slots map[int]*SlotInfo, n int) *SlotInfo {
	if s, ok := slots[n]; ok {
		return s
	}
	s := &SlotInfo{Slot: n, Kind: "value", Confidence: 0.5}
	slots[n] = s
	return s
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func containsSubstr(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
