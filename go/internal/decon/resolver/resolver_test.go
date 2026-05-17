package resolver

import "testing"

func TestKnownSelectors(t *testing.T) {
	if FunctionsCount() == 0 {
		t.Fatal("embedded function signature DB empty")
	}
	// transfer(address,uint256) = 0xa9059cbb is a near-universal entry;
	// accept either 0x-prefixed or bare lookup form.
	if Function("0xa9059cbb") == "" && Function("a9059cbb") == "" {
		t.Errorf("expected resolution for transfer selector, got empty")
	}
	if ResolveAll([]string{"0xa9059cbb"}) == nil {
		t.Errorf("ResolveAll returned nil map")
	}
}
