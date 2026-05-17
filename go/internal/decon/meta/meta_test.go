package meta

import "testing"

func TestExtractNoMetadata(t *testing.T) {
	r := Extract("608060405200")
	if r.Found {
		t.Errorf("did not expect CBOR metadata in bare runtime")
	}
}
