package knownbc

import (
	"sort"
	"strings"
	"testing"
)

// Token tables guard byte-for-byte parity with Python evm_decon.known_bytecodes.
func TestFingerprintTokens(t *testing.T) {
	cases := []struct {
		name       string
		hex        string
		wantTokens []string // must all be present in result.Tags
		wantProxy  string
	}{
		{
			name:       "erc1167_clone",
			hex:        "363d3d373d3d3d363d73bebebebebebebebebebebebebebebebebebebebe5af43d82803e903d91602b57fd5bf3",
			wantTokens: []string{"ERC1167_CLONE", "erc1167_fixed_clone_target", "KNOWN_SAFE_PROXY_PATTERN", "IMPLEMENTATION_ADDRESS_EXTRACTED"},
			wantProxy:  "ERC1167_CLONE",
		},
		{
			name:       "ownable2step",
			hex:        "e30c397879ba50978da5cb5bf2fde38b",
			wantTokens: []string{"OZ_OWNABLE", "OZ_OWNABLE2STEP", "two_step_acceptance_by_new_admin", "owner_or_admin_guard"},
		},
		{
			name:       "access_control",
			hex:        "91d148542f2ff15dd547741f36568abe248a9ca3",
			wantTokens: []string{"OZ_ACCESS_CONTROL", "role_admin_guard", "STRONG_AUTH_GUARD"},
		},
		{
			name:       "reentrancy_guard",
			hex:        "600155600255",
			wantTokens: []string{"OZ_REENTRANCY_GUARD", "REENTRANCY_GUARD", "reentrancy_guard", "mutex_lock"},
		},
		{
			name:       "pausable",
			hex:        "5c975abb8456cb59",
			wantTokens: []string{"OZ_PAUSABLE", "pause_guard"},
		},
		{
			name:       "timelock",
			hex:        "f27a0c9201d5062a",
			wantTokens: []string{"OZ_TIMELOCK_CONTROLLER", "timelock_or_governance_guard", "timelock_guard"},
		},
		{
			name:       "negative",
			hex:        "6080604052348015",
			wantTokens: nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Fingerprint(c.hex)
			has := map[string]struct{}{}
			for _, tag := range r.Tags {
				has[tag] = struct{}{}
			}
			for _, want := range c.wantTokens {
				if _, ok := has[want]; !ok {
					t.Errorf("missing token %q; got %v", want, r.Tags)
				}
			}
			if c.wantProxy != "" && r.ProxyType != c.wantProxy {
				t.Errorf("ProxyType = %q, want %q", r.ProxyType, c.wantProxy)
			}
			if !sort.StringsAreSorted(r.Tags) {
				t.Errorf("Tags not sorted: %v", r.Tags)
			}
		})
	}
}

func TestLibraryFingerprintsOrderAndConfidence(t *testing.T) {
	r := Fingerprint("0xe30c397879ba50978da5cb5bf2fde38b")
	entries := r.LibraryFingerprints()
	if len(entries) == 0 {
		t.Fatal("expected library fingerprint entries")
	}
	// OZ_OWNABLE must precede OZ_OWNABLE2STEP (Python emission order).
	order := []string{}
	for _, e := range entries {
		order = append(order, e["id"].(string))
	}
	joined := strings.Join(order, ",")
	if !strings.Contains(joined, "OZ_OWNABLE2STEP") {
		t.Fatalf("expected OZ_OWNABLE2STEP, got %v", order)
	}
	for _, e := range entries {
		if e["id"] == "OZ_OWNABLE2STEP" {
			if e["confidence"].(float64) != 0.92 {
				t.Errorf("OZ_OWNABLE2STEP confidence = %v, want 0.92", e["confidence"])
			}
		}
	}
}
