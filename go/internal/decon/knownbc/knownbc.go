// Package knownbc fingerprints known bytecode patterns (proxies, OZ libraries,
// guards). Faithful port of Python evm_decon/known_bytecodes.py.
//
// Detection is substring matching over the lowercased runtime bytecode hex
// (0x stripped), identical to the Python reference, so token output is
// byte-for-byte comparable for counter-evidence parity.
package knownbc

import (
	"sort"
	"strings"
)

// ── ERC-1967 well-known storage slot constants (keccak(string)-1) ──────────
const (
	erc1967ImplementationSlot = "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
	erc1967AdminSlot          = "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
	erc1967BeaconSlot         = "a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
	erc1967RollbackSlot       = "4910fdfa16fed3260ed0e7147f7cc6da11a60208b5b9406d12a635614ffd9143"

	erc1167Prefix   = "363d3d373d3d3d363d73"
	erc1167Suffix   = "5af43d82803e903d91602b57fd5bf3"
	vyperProxyPrefix = "366000600037611000600036600073"

	uupsSelector = "52d1902d"

	upgradeToSelector        = "3659cfe6"
	upgradeToAndCallSelector = "4f1ef286"
	changeAdminSelector      = "8f283970"
	adminSelector            = "f851a440"
	implementationSelector   = "5c60da1b"

	diamondCutSelector      = "1f931c1c"
	diamondFacetsSelector   = "7a0ed627"
	diamondFacetSelectors   = "adfca15e"
	diamondFacetAddresses   = "52ef6b2c"
	diamondFacetAddress     = "cdffacc6"

	safeMasterCopySelector = "a619486e"
	safeSingletonSelector  = "736bf590"
	safeSetupSelector      = "b63e800d"

	comptrollerImplSelector = "bb82aa5e"
	setPendingImplSelector  = "b71d1a0c"
	acceptImplSelector      = "e992a041"

	proxyTypeSelector = "4555d5c9"

	ozOwnerSelector              = "8da5cb5b"
	ozTransferOwnershipSelector  = "f2fde38b"
	ozRenounceOwnershipSelector  = "715018a6"
	ozPendingOwnerSelector       = "e30c3978"
	ozAcceptOwnershipSelector    = "79ba5097"
	ozHasRoleSelector            = "91d14854"
	ozGrantRoleSelector          = "2f2ff15d"
	ozRevokeRoleSelector         = "d547741f"
	ozRenounceRoleSelector       = "36568abe"
	ozGetRoleAdminSelector       = "248a9ca3"
	ozPausedSelector             = "5c975abb"
	ozPauseSelector              = "8456cb59"
	ozUnpauseSelector            = "3f4ba83a"
	ozTimelockGetMinDelay        = "f27a0c92"
	ozTimelockSchedule           = "01d5062a"
	ozTimelockExecute            = "134008d3"

	ozInitSlotV5 = "f0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00"

	// Bridge selectors — cross-chain import/relay surfaces.
	bridgeSubmitImportsSelector     = "e03a0460" // submitImports(bytes)
	bridgeProveImportsSelector      = "7f00c7a6" // proveImports(bytes,bytes)
	bridgeProcessTxSelector         = "8f84aa09" // processTransactions(bytes)
	bridgeRelayMessageSelector      = "d764ad0b" // relayMessage(uint256,address,address,uint256,uint256,bytes)
	bridgeExecuteMessageSelector    = "21d800ec" // executeMessage(bytes,bytes)
	bridgeFinalizeDepositSelector   = "1532ec34" // finalizeDeposit(address,address,uint256)
	bridgeClaimSelector             = "2e7ba6ef" // claim(uint256,address,uint256,bytes32[])
	bridgeReceiveMessageSelector    = "46b4a769" // receiveMessage(bytes)
	bridgeOnMessageReceivedSelector = "34d5386d" // onMessageReceived(address,uint64,bytes)
)

// Result mirrors Python BytecodeFingerprint.
type Result struct {
	Tags      []string
	ProxyType string

	HasERC1967ImplSlot    bool
	HasERC1967AdminSlot   bool
	HasERC1967BeaconSlot  bool
	HasERC1967RollbackSlot bool

	HasProxyForwarding bool
	HasUUPS            bool
	HasERC1167Clone    bool

	HasDiamond            bool
	HasGnosisSafe         bool
	HasCompoundUnitroller bool
	HasEIP897             bool
	HasSlot0Proxy         bool
	HasVyperProxy         bool

	HasReentrancyGuardConstants bool
	HasInitializerPattern       bool
	HasTwoStepUpgrade           bool

	HasOZOwnable      bool
	HasOZOwnable2Step bool
	HasOZAccessControl bool
	HasOZPausable     bool
	HasOZTimelock     bool
	HasSafeERC20      bool

	ImplementationAddress  string
	ProxySelectorsFound    []string
	DiamondLoupeSelectors  int

	HasBridgePattern       bool
	BridgeSelectorsFound   []string
}

// Fingerprint analyzes raw bytecode hex for known patterns.
func Fingerprint(bytecodeHex string) Result {
	bc := strings.TrimSpace(strings.ReplaceAll(strings.ToLower(bytecodeHex), "0x", ""))
	r := Result{}

	detectERC1967(bc, &r)
	detectProxyForwarding(bc, &r)
	detectERC1167(bc, &r)
	detectVyperProxy(bc, &r)
	detectUUPS(bc, &r)
	detectProxySelectors(bc, &r)
	detectDiamond(bc, &r)
	detectGnosisSafe(bc, &r)
	detectCompoundUnitroller(bc, &r)
	detectEIP897(bc, &r)
	detectSlot0Proxy(bc, &r)
	detectOZOwnable(bc, &r)
	detectOZOwnable2Step(bc, &r)
	detectOZAccessControl(bc, &r)
	detectOZPausable(bc, &r)
	detectOZTimelock(bc, &r)
	detectSafeERC20(bc, &r)
	detectReentrancyGuard(bc, &r)
	detectInitializer(bc, &r)
	detectBridge(bc, &r)
	classifyProxyType(&r)
	buildTags(&r)
	return r
}

func detectERC1967(bc string, r *Result) {
	if strings.Contains(bc, erc1967ImplementationSlot) {
		r.HasERC1967ImplSlot = true
	}
	if strings.Contains(bc, erc1967AdminSlot) {
		r.HasERC1967AdminSlot = true
	}
	if strings.Contains(bc, erc1967BeaconSlot) {
		r.HasERC1967BeaconSlot = true
	}
	if strings.Contains(bc, erc1967RollbackSlot) {
		r.HasERC1967RollbackSlot = true
	}
}

func detectProxyForwarding(bc string, r *Result) {
	if !(strings.Contains(bc, "37") && strings.Contains(bc, "f4") && strings.Contains(bc, "3e")) {
		return
	}
	dcPos := strings.Index(bc, "f4")
	for dcPos != -1 {
		windowEnd := dcPos + 60
		if windowEnd > len(bc) {
			windowEnd = len(bc)
		}
		window := bc[dcPos:windowEnd]
		rdcPos := strings.Index(window, "3e")
		if rdcPos != -1 {
			start := dcPos + rdcPos
			end := start + 40
			if end > len(bc) {
				end = len(bc)
			}
			afterRdc := bc[start:end]
			if strings.Contains(afterRdc, "fd") && strings.Contains(afterRdc, "f3") {
				r.HasProxyForwarding = true
				break
			}
		}
		next := strings.Index(bc[dcPos+2:], "f4")
		if next == -1 {
			break
		}
		dcPos = dcPos + 2 + next
	}
}

func extractCloneAddr(bc, prefix string, r *Result) {
	prefixPos := strings.Index(bc, prefix)
	if prefixPos == -1 {
		return
	}
	addrStart := prefixPos + len(prefix)
	addrEnd := addrStart + 40
	if addrEnd <= len(bc) {
		addr := bc[addrStart:addrEnd]
		if len(addr) == 40 && addr != strings.Repeat("0", 40) {
			r.ImplementationAddress = "0x" + addr
		}
	}
}

func detectERC1167(bc string, r *Result) {
	if strings.Contains(bc, erc1167Prefix) && strings.Contains(bc, erc1167Suffix) {
		r.HasERC1167Clone = true
		extractCloneAddr(bc, erc1167Prefix, r)
	}
}

func detectVyperProxy(bc string, r *Result) {
	if strings.Contains(bc, vyperProxyPrefix) {
		r.HasVyperProxy = true
		r.HasERC1167Clone = true
		extractCloneAddr(bc, vyperProxyPrefix, r)
	}
}

func detectDiamond(bc string, r *Result) {
	loupe := []string{diamondFacetsSelector, diamondFacetSelectors, diamondFacetAddresses, diamondFacetAddress}
	names := []string{"facets()", "facetFunctionSelectors(address)", "facetAddresses()", "facetAddress(bytes4)"}
	loupeCount := 0
	for _, s := range loupe {
		if strings.Contains(bc, s) {
			loupeCount++
		}
	}
	hasDiamondCut := strings.Contains(bc, diamondCutSelector)
	r.DiamondLoupeSelectors = loupeCount
	if loupeCount >= 3 || (loupeCount >= 2 && hasDiamondCut) {
		r.HasDiamond = true
		if hasDiamondCut {
			r.ProxySelectorsFound = append(r.ProxySelectorsFound, "diamondCut(...)")
		}
		for i, s := range loupe {
			if strings.Contains(bc, s) {
				r.ProxySelectorsFound = append(r.ProxySelectorsFound, names[i])
			}
		}
	}
}

func detectGnosisSafe(bc string, r *Result) {
	hasMasterCopy := strings.Contains(bc, safeMasterCopySelector)
	hasSingleton := strings.Contains(bc, safeSingletonSelector)
	hasSetup := strings.Contains(bc, safeSetupSelector)
	if hasMasterCopy || hasSingleton {
		r.HasGnosisSafe = true
		if hasMasterCopy {
			r.ProxySelectorsFound = append(r.ProxySelectorsFound, "masterCopy()")
		}
		if hasSingleton {
			r.ProxySelectorsFound = append(r.ProxySelectorsFound, "singleton()")
		}
		if hasSetup {
			r.ProxySelectorsFound = append(r.ProxySelectorsFound, "setup(...)")
		}
	} else if hasSetup && strings.Contains(bc, "f4") {
		if strings.Contains(bc, "600054") {
			r.HasGnosisSafe = true
			r.ProxySelectorsFound = append(r.ProxySelectorsFound, "setup(...)")
		}
	}
}

func detectCompoundUnitroller(bc string, r *Result) {
	hasComptrollerImpl := strings.Contains(bc, comptrollerImplSelector)
	hasSetPending := strings.Contains(bc, setPendingImplSelector)
	hasAccept := strings.Contains(bc, acceptImplSelector)
	count := b2i(hasComptrollerImpl) + b2i(hasSetPending) + b2i(hasAccept)
	if count >= 2 {
		r.HasCompoundUnitroller = true
		r.HasTwoStepUpgrade = true
		if hasComptrollerImpl {
			r.ProxySelectorsFound = append(r.ProxySelectorsFound, "comptrollerImplementation()")
		}
		if hasSetPending {
			r.ProxySelectorsFound = append(r.ProxySelectorsFound, "_setPendingImplementation(address)")
		}
		if hasAccept {
			r.ProxySelectorsFound = append(r.ProxySelectorsFound, "_acceptImplementation()")
		}
	}
}

func detectEIP897(bc string, r *Result) {
	hasProxyType := strings.Contains(bc, proxyTypeSelector)
	hasImpl := strings.Contains(bc, implementationSelector)
	if hasProxyType && hasImpl {
		r.HasEIP897 = true
		r.ProxySelectorsFound = append(r.ProxySelectorsFound, "proxyType()")
	} else if hasProxyType && strings.Contains(bc, "f4") {
		r.HasEIP897 = true
		r.ProxySelectorsFound = append(r.ProxySelectorsFound, "proxyType()")
	}
}

func detectOZOwnable(bc string, r *Result) {
	if strings.Contains(bc, ozOwnerSelector) && strings.Contains(bc, ozTransferOwnershipSelector) {
		r.HasOZOwnable = true
	}
}

func detectOZOwnable2Step(bc string, r *Result) {
	if strings.Contains(bc, ozPendingOwnerSelector) && strings.Contains(bc, ozAcceptOwnershipSelector) {
		r.HasOZOwnable2Step = true
		r.HasTwoStepUpgrade = true
	}
}

func detectOZAccessControl(bc string, r *Result) {
	sels := []string{ozHasRoleSelector, ozGrantRoleSelector, ozRevokeRoleSelector, ozRenounceRoleSelector, ozGetRoleAdminSelector}
	count := 0
	for _, s := range sels {
		if strings.Contains(bc, s) {
			count++
		}
	}
	if count >= 3 {
		r.HasOZAccessControl = true
	}
}

func detectOZPausable(bc string, r *Result) {
	hasPaused := strings.Contains(bc, ozPausedSelector)
	hasAction := strings.Contains(bc, ozPauseSelector) || strings.Contains(bc, ozUnpauseSelector)
	if hasPaused && hasAction {
		r.HasOZPausable = true
	}
}

func detectOZTimelock(bc string, r *Result) {
	hasMinDelay := strings.Contains(bc, ozTimelockGetMinDelay)
	hasSchedOrExec := strings.Contains(bc, ozTimelockSchedule) || strings.Contains(bc, ozTimelockExecute)
	if hasMinDelay && hasSchedOrExec {
		r.HasOZTimelock = true
	}
}

func detectSafeERC20(bc string, r *Result) {
	bcLen := len(bc)
	for pos := 0; pos < bcLen-6; pos += 2 {
		if bc[pos:pos+2] == "f1" {
			end := pos + 40
			if end > bcLen {
				end = bcLen
			}
			window := bc[pos:end]
			rdsPos := strings.Index(window, "3d")
			if rdsPos != -1 {
				if strings.Index(window[rdsPos:], "15") != -1 {
					r.HasSafeERC20 = true
					return
				}
			}
		}
	}
}

func detectSlot0Proxy(bc string, r *Result) {
	if r.HasGnosisSafe || r.HasERC1167Clone || r.HasERC1967ImplSlot {
		return
	}
	pattern := "600054"
	pos := strings.Index(bc, pattern)
	for pos != -1 {
		windowEnd := pos + 120
		if windowEnd > len(bc) {
			windowEnd = len(bc)
		}
		window := bc[pos:windowEnd]
		if strings.Contains(window, "f4") {
			lo := pos - 40
			if lo < 0 {
				lo = 0
			}
			extEnd := pos + 120
			if extEnd > len(bc) {
				extEnd = len(bc)
			}
			extended := bc[lo:extEnd]
			if strings.Contains(extended, "36") || strings.Contains(extended, "37") {
				r.HasSlot0Proxy = true
				break
			}
		}
		next := strings.Index(bc[pos+6:], pattern)
		if next == -1 {
			break
		}
		pos = pos + 6 + next
	}
}

func detectUUPS(bc string, r *Result) {
	if strings.Contains(bc, uupsSelector) {
		r.HasUUPS = true
	}
}

func detectProxySelectors(bc string, r *Result) {
	// Ordered to match Python dict insertion order.
	pairs := []struct{ sel, name string }{
		{upgradeToSelector, "upgradeTo(address)"},
		{upgradeToAndCallSelector, "upgradeToAndCall(address,bytes)"},
		{changeAdminSelector, "changeAdmin(address)"},
		{adminSelector, "admin()"},
		{implementationSelector, "implementation()"},
	}
	for _, p := range pairs {
		if strings.Contains(bc, p.sel) {
			r.ProxySelectorsFound = append(r.ProxySelectorsFound, p.name)
		}
	}
}

func detectReentrancyGuard(bc string, r *Result) {
	if strings.Contains(bc, "600155") && strings.Contains(bc, "600255") {
		r.HasReentrancyGuardConstants = true
	}
}

func detectInitializer(bc string, r *Result) {
	if strings.Contains(bc, ozInitSlotV5) {
		r.HasInitializerPattern = true
	} else if strings.Contains(bc, "60ff") {
		r.HasInitializerPattern = true
	}
}

func detectBridge(bc string, r *Result) {
	bridgeSelectors := []struct {
		sel  string
		name string
	}{
		{bridgeSubmitImportsSelector, "submitImports"},
		{bridgeProveImportsSelector, "proveImports"},
		{bridgeProcessTxSelector, "processTransactions"},
		{bridgeRelayMessageSelector, "relayMessage"},
		{bridgeExecuteMessageSelector, "executeMessage"},
		{bridgeFinalizeDepositSelector, "finalizeDeposit"},
		{bridgeClaimSelector, "claim"},
		{bridgeReceiveMessageSelector, "receiveMessage"},
		{bridgeOnMessageReceivedSelector, "onMessageReceived"},
	}
	for _, s := range bridgeSelectors {
		if strings.Contains(bc, s.sel) {
			r.BridgeSelectorsFound = append(r.BridgeSelectorsFound, s.name)
		}
	}
	if len(r.BridgeSelectorsFound) >= 2 {
		r.HasBridgePattern = true
	}
}

func classifyProxyType(r *Result) {
	switch {
	case r.HasERC1167Clone:
		r.ProxyType = "ERC1167_CLONE"
	case r.HasDiamond:
		r.ProxyType = "DIAMOND_PROXY"
	case r.HasGnosisSafe:
		r.ProxyType = "GNOSIS_SAFE_PROXY"
	case r.HasCompoundUnitroller:
		r.ProxyType = "COMPOUND_UNITROLLER"
	case r.HasProxyForwarding && r.HasERC1967ImplSlot:
		switch {
		case r.HasERC1967AdminSlot:
			if r.HasUUPS {
				r.ProxyType = "UUPS_PROXY"
			} else {
				r.ProxyType = "TRANSPARENT_PROXY"
			}
		case r.HasERC1967BeaconSlot:
			r.ProxyType = "BEACON_PROXY"
		case r.HasUUPS:
			r.ProxyType = "UUPS_PROXY"
		default:
			r.ProxyType = "ERC1967_PROXY"
		}
	case r.HasUUPS && r.HasERC1967ImplSlot:
		r.ProxyType = "UUPS_PROXY"
	case r.HasEIP897:
		r.ProxyType = "EIP897_DELEGATE_PROXY"
	case r.HasERC1967ImplSlot:
		r.ProxyType = "ERC1967_PROXY"
	case r.HasSlot0Proxy:
		r.ProxyType = "SLOT0_PROXY"
	case r.HasVyperProxy:
		r.ProxyType = "VYPER_MINIMAL_PROXY"
	case r.HasProxyForwarding:
		r.ProxyType = "GENERIC_PROXY"
	}
}

func buildTags(r *Result) {
	var tags []string
	add := func(t ...string) { tags = append(tags, t...) }

	if r.HasERC1967ImplSlot {
		add("ERC1967_PROXY", "ERC-1967")
	}
	if r.HasERC1967AdminSlot {
		add("ERC1967_ADMIN_SLOT", "proxy_admin_guard")
	}
	if r.HasERC1967BeaconSlot {
		add("ERC1967_BEACON_SLOT")
	}
	if r.HasProxyForwarding {
		add("PROXY_FORWARDING_PATTERN", "PROXY_FORWARDING_DELEGATECALL",
			"assembly_return_value_handling", "verified_return_check_cross_block")
	}
	if r.HasERC1167Clone {
		add("ERC1167_CLONE", "erc1167_fixed_clone_target")
	}
	if r.HasVyperProxy {
		add("VYPER_MINIMAL_PROXY")
	}
	if r.HasDiamond {
		add("DIAMOND_PROXY", "EIP2535_DIAMOND", "DIAMOND_FACET_ROUTING",
			"proxy_safe_delegatecall", "fixed_delegatecall_target")
	}
	if r.HasGnosisSafe {
		add("GNOSIS_SAFE_PROXY", "SAFE_PROXY", "SLOT0_PROXY", "proxy_safe_delegatecall")
	}
	if r.HasCompoundUnitroller {
		add("COMPOUND_UNITROLLER", "TWO_STEP_UPGRADE", "proxy_safe_delegatecall")
	}
	if r.HasEIP897 {
		add("EIP897_DELEGATE_PROXY")
	}
	if r.HasSlot0Proxy {
		add("SLOT0_PROXY", "GENERIC_STORAGE_PROXY")
	}
	if r.HasTwoStepUpgrade {
		add("TWO_STEP_UPGRADE", "two_step_acceptance_by_new_admin")
	}
	if r.ProxyType != "" {
		add(r.ProxyType)
		safeTypes := map[string]bool{
			"TRANSPARENT_PROXY": true, "UUPS_PROXY": true, "BEACON_PROXY": true,
			"ERC1967_PROXY": true, "ERC1167_CLONE": true, "DIAMOND_PROXY": true,
			"GNOSIS_SAFE_PROXY": true, "COMPOUND_UNITROLLER": true,
			"EIP897_DELEGATE_PROXY": true, "VYPER_MINIMAL_PROXY": true,
		}
		if safeTypes[r.ProxyType] {
			add("KNOWN_SAFE_PROXY_PATTERN")
		}
	}
	if r.HasUUPS {
		add("UUPS_PATTERN")
	}
	// NOTE: Previously this emitted "admin_guarded_function" + "ADMIN_GUARD"
	// whenever the admin slot was present AND proxy forwarding was detected.
	// That's wrong: the admin slot constant in bytecode doesn't prove the
	// upgrade path is actually gated by an admin check. It was suppressing
	// every ERC-1967 proxy rule (both proxy.* and init.*) before it could
	// fire. Removed. Strong-guard tokens (OZ_OWNABLE2STEP, OZ_ACCESS_CONTROL,
	// OZ_TIMELOCK_CONTROLLER) still correctly suppress.
	if r.HasReentrancyGuardConstants {
		add("REENTRANCY_GUARD", "reentrancy_guard", "mutex_lock", "OZ_REENTRANCY_GUARD")
	}
	if r.HasInitializerPattern {
		// Only emit INITIALIZABLE (descriptive). Don't emit "initializer_guard"
		// because HasInitializerPattern triggers on mere presence of the OZ init
		// slot constant or 0x60ff — it doesn't prove the initializer is actually
		// guarded. Emitting the guard tag was suppressing init.* rules on every
		// Initializable contract, producing 0 findings.
		add("INITIALIZABLE")
	}
	if len(r.ProxySelectorsFound) > 0 {
		add("PROXY_UPGRADE_SELECTORS")
	}
	if r.ImplementationAddress != "" {
		add("IMPLEMENTATION_ADDRESS_EXTRACTED")
	}
	if r.HasOZOwnable {
		add("OZ_OWNABLE", "owner_or_admin_guard")
	}
	if r.HasOZOwnable2Step {
		add("OZ_OWNABLE2STEP", "two_step_acceptance_by_new_admin", "owner_or_admin_guard")
	}
	if r.HasOZAccessControl {
		add("OZ_ACCESS_CONTROL", "role_admin_guard", "STRONG_AUTH_GUARD")
	}
	if r.HasOZPausable {
		add("OZ_PAUSABLE", "pause_guard")
	}
	if r.HasOZTimelock {
		add("OZ_TIMELOCK_CONTROLLER", "timelock_or_governance_guard", "timelock_guard")
	}
	if r.HasSafeERC20 {
		add("SAFE_ERC20_USAGE", "safeTransfer")
	}
	if r.HasBridgePattern {
		add("BRIDGE_PATTERN", "CROSS_CHAIN_BRIDGE", "bridge_import_surface")
	}
	allSafe := map[string]bool{
		"TRANSPARENT_PROXY": true, "UUPS_PROXY": true, "BEACON_PROXY": true,
		"ERC1967_PROXY": true, "DIAMOND_PROXY": true, "GNOSIS_SAFE_PROXY": true,
		"COMPOUND_UNITROLLER": true, "EIP897_DELEGATE_PROXY": true,
	}
	if allSafe[r.ProxyType] {
		add("SSTORE_BEFORE_CALL_ONLY", "proxy_safe_delegatecall")
	}

	seen := map[string]struct{}{}
	uniq := make([]string, 0, len(tags))
	for _, t := range tags {
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		uniq = append(uniq, t)
	}
	sort.Strings(uniq)
	r.Tags = uniq
}

// LibraryFingerprints mirrors audit_json._library_fingerprints — structured
// state-model entries consumed as counter-evidence tokens. Order matches the
// Python emission order exactly.
func (r Result) LibraryFingerprints() []map[string]any {
	entries := []map[string]any{}
	add := func(id, kind string, confidence float64, refs ...string) {
		rf := make([]any, len(refs))
		for i, s := range refs {
			rf[i] = s
		}
		entries = append(entries, map[string]any{
			"id":            id,
			"kind":          kind,
			"evidence_refs": rf,
			"confidence":    confidence,
		})
	}
	if r.HasERC1967ImplSlot {
		add("ERC1967_PROXY", "proxy", 0.95, "erc1967_impl_slot")
	}
	if r.HasERC1167Clone {
		add("ERC1167_CLONE", "proxy", 0.98, "erc1167_prefix_suffix")
	}
	if r.HasUUPS {
		add("EIP1822_UUPS", "proxy", 0.90, "proxiableUUID_selector")
	}
	if r.HasDiamond {
		add("DIAMOND_PROXY", "proxy", 0.92, "diamond_loupe_selectors")
	}
	if r.HasGnosisSafe {
		add("GNOSIS_SAFE_PROXY", "proxy", 0.90, "gnosis_safe_selectors")
	}
	if r.HasCompoundUnitroller {
		add("COMPOUND_UNITROLLER", "proxy", 0.88, "unitroller_selectors")
	}
	if r.HasOZOwnable {
		add("OZ_OWNABLE", "library", 0.88, "owner_selector", "transferOwnership_selector")
	}
	if r.HasOZOwnable2Step {
		add("OZ_OWNABLE2STEP", "library", 0.92, "pendingOwner_selector", "acceptOwnership_selector")
		add("two_step_acceptance_by_new_admin", "guard", 0.92, "pendingOwner_selector", "acceptOwnership_selector")
	}
	if r.HasOZAccessControl {
		add("OZ_ACCESS_CONTROL", "library", 0.90, "hasRole_selector", "grantRole_selector")
		add("role_admin_guard", "guard", 0.90, "hasRole_selector")
	}
	if r.HasOZPausable {
		add("OZ_PAUSABLE", "library", 0.88, "paused_selector", "pause_selector")
	}
	if r.HasOZTimelock {
		add("OZ_TIMELOCK_CONTROLLER", "library", 0.90, "getMinDelay_selector", "schedule_selector")
		add("timelock_or_governance_guard", "guard", 0.90, "getMinDelay_selector")
	}
	if r.HasSafeERC20 {
		add("SAFE_ERC20_USAGE", "library", 0.82, "returndatasize_check_after_call")
		add("safeTransfer", "guard", 0.82, "returndatasize_check_after_call")
	}
	if r.HasReentrancyGuardConstants {
		add("OZ_REENTRANCY_GUARD", "library", 0.85, "reentrancy_store1_store2_pattern")
	}
	if r.HasInitializerPattern {
		add("INITIALIZABLE", "library", 0.85, "oz_init_slot_or_ff_constant")
	}
	return entries
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
