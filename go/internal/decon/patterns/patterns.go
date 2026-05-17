// Package patterns ports evm_decon/patterns.py: proxy detect, security flags,
// embedded string scan, opcode-frequency stats.
package patterns

import (
	"encoding/hex"
	"sort"
	"strings"

	"github.com/evm-auditor/evm-auditor/internal/decon/disasm"
)

// EIP-1167 minimal-proxy template constants.
const (
	eip1167Prefix      = "363d3d373d3d3d363d73"
	eip1167Suffix      = "5af43d82803e903d91602b57fd5bf3"
	eip1167TotalBytes  = 45
	eip1967ImplSlot    = "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
	eip1967AdminSlot   = "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
	eip1967BeaconSlot  = "a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
)

// ProxyInfo mirrors evm_decon.patterns.ProxyInfo.
type ProxyInfo struct {
	IsProxy               bool
	ProxyType             string
	ImplementationAddress string
	Details               map[string]any
}

// SecurityFlags mirrors evm_decon.patterns.SecurityFlags.
type SecurityFlags struct {
	HasSelfdestruct      bool
	HasDelegatecall      bool
	HasCallcode          bool
	HasCreate            bool
	HasCreate2           bool
	HasOrigin            bool
	HasStaticcall        bool
	HasSendOrTransfer    bool
	SelfdestructOffsets  []int
	DelegatecallOffsets  []int
}

// StringLiteral mirrors evm_decon.patterns.StringLiteral.
type StringLiteral struct {
	Offset   int
	Value    string
	Encoding string
	Length   int
}

// Result mirrors evm_decon.patterns.PatternResult. Standards detection is left
// out (port pending — needs known_signatures table).
type Result struct {
	Proxy             ProxyInfo
	Security          SecurityFlags
	Standards         []map[string]any
	Strings           []StringLiteral
	OpcodeFrequency   []KV
	OpcodeCategories  []KV
}

// KV is a single (opcode, count) pair preserved in descending-count order to
// mirror Python's `dict(sorted(... key=-count))`.
type KV struct {
	Key   string
	Value int
}

// Detect runs the full pattern pipeline.
func Detect(d disasm.Result, bytecodeHex string, _ map[string]struct{}) Result {
	return Result{
		Proxy:            detectProxy(d, bytecodeHex),
		Security:         detectSecurity(d),
		Standards:        []map[string]any{}, // TODO: port known_signatures.detect_standards
		Strings:          extractStrings(bytecodeHex),
		OpcodeFrequency:  opcodeFrequency(d),
		OpcodeCategories: categoryFrequency(d),
	}
}

func detectProxy(d disasm.Result, bytecodeHex string) ProxyInfo {
	hexStr := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(bytecodeHex)), "0x")
	bc, err := hex.DecodeString(hexStr)
	if err != nil {
		return ProxyInfo{}
	}

	// 1. EIP-1167 exact match
	if len(bc) == eip1167TotalBytes {
		prefix, _ := hex.DecodeString(eip1167Prefix)
		suffix, _ := hex.DecodeString(eip1167Suffix)
		if bytesEqual(bc[:10], prefix) && bytesEqual(bc[30:], suffix) {
			return ProxyInfo{
				IsProxy:               true,
				ProxyType:             "EIP-1167",
				ImplementationAddress: "0x" + hex.EncodeToString(bc[10:30]),
				Details:               map[string]any{"pattern": "minimal_proxy", "exact_match": true},
			}
		}
	}

	// 1b. EIP-1167 embedded
	if idx := strings.Index(hexStr, eip1167Prefix); idx >= 0 {
		addrStart := idx + 20
		suffixStart := addrStart + 40
		if suffixStart+len(eip1167Suffix) <= len(hexStr) &&
			hexStr[suffixStart:suffixStart+len(eip1167Suffix)] == eip1167Suffix {
			return ProxyInfo{
				IsProxy:               true,
				ProxyType:             "EIP-1167",
				ImplementationAddress: "0x" + hexStr[addrStart:addrStart+40],
				Details:               map[string]any{"pattern": "minimal_proxy", "embedded": true},
			}
		}
	}

	// 2. EIP-1967
	hasEIP1967 := false
	for _, ins := range d.Instructions {
		if ins.Mnemonic != "PUSH32" || ins.Operand == nil {
			continue
		}
		operand := ins.Operand.Text(16)
		// Pad to 64 chars for comparison.
		for len(operand) < 64 {
			operand = "0" + operand
		}
		if operand == eip1967ImplSlot || operand == eip1967AdminSlot || operand == eip1967BeaconSlot {
			hasEIP1967 = true
			break
		}
	}
	if hasEIP1967 && hasOpcode(d, "DELEGATECALL") {
		return ProxyInfo{
			IsProxy:   true,
			ProxyType: "EIP-1967",
			Details:   map[string]any{"pattern": "upgradeable_proxy", "slot_detected": true},
		}
	}

	// 3. Generic small-delegatecall heuristic
	if hasOpcode(d, "DELEGATECALL") && d.BytecodeSize < 500 {
		return ProxyInfo{
			IsProxy:   true,
			ProxyType: "DELEGATECALL-based",
			Details:   map[string]any{"pattern": "generic_proxy", "heuristic": true},
		}
	}
	return ProxyInfo{}
}

func detectSecurity(d disasm.Result) SecurityFlags {
	flags := SecurityFlags{}
	for i, ins := range d.Instructions {
		switch ins.Mnemonic {
		case "SELFDESTRUCT":
			flags.HasSelfdestruct = true
			flags.SelfdestructOffsets = append(flags.SelfdestructOffsets, ins.Offset)
		case "DELEGATECALL":
			flags.HasDelegatecall = true
			flags.DelegatecallOffsets = append(flags.DelegatecallOffsets, ins.Offset)
		case "CALLCODE":
			flags.HasCallcode = true
		case "CREATE":
			flags.HasCreate = true
		case "CREATE2":
			flags.HasCreate2 = true
		case "ORIGIN":
			flags.HasOrigin = true
		case "STATICCALL":
			flags.HasStaticcall = true
		case "CALL":
			if i >= 1 {
				prev := d.Instructions[i-1]
				if (prev.Mnemonic == "PUSH2" || prev.Mnemonic == "PUSH3") && prev.Operand != nil &&
					prev.Operand.Int64() == 2300 {
					flags.HasSendOrTransfer = true
				}
			}
		}
	}
	return flags
}

func extractStrings(bytecodeHex string) []StringLiteral {
	hexStr := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(bytecodeHex)), "0x")
	bc, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil
	}
	out := []StringLiteral{}
	current := []byte{}
	start := 0
	flush := func() {
		if len(current) >= 6 {
			text := string(current)
			if !allHexChars(strings.ToLower(text)) {
				out = append(out, StringLiteral{
					Offset: start, Value: text, Encoding: "ascii", Length: len(text),
				})
			}
		}
		current = current[:0]
	}
	for i, b := range bc {
		if b >= 0x20 && b <= 0x7e {
			if len(current) == 0 {
				start = i
			}
			current = append(current, b)
		} else {
			flush()
		}
	}
	flush()
	return out
}

func opcodeFrequency(d disasm.Result) []KV {
	counts := map[string]int{}
	for _, ins := range d.Instructions {
		counts[ins.Mnemonic]++
	}
	return sortedDesc(counts)
}

func categoryFrequency(d disasm.Result) []KV {
	counts := map[string]int{}
	for _, ins := range d.Instructions {
		counts[disasm.Lookup(ins.Opcode).Category]++
	}
	return sortedDesc(counts)
}

func sortedDesc(m map[string]int) []KV {
	out := make([]KV, 0, len(m))
	for k, v := range m {
		out = append(out, KV{Key: k, Value: v})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Value != out[j].Value {
			return out[i].Value > out[j].Value
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func hasOpcode(d disasm.Result, op string) bool {
	for _, ins := range d.Instructions {
		if ins.Mnemonic == op {
			return true
		}
	}
	return false
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func allHexChars(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
