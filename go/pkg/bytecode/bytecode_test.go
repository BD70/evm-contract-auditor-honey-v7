package bytecode

import "testing"

func TestNormalize(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"0x6080", "6080", false},
		{"0X6080", "6080", false},
		{"  6080  ", "6080", false},
		{"6080AB", "6080ab", false},
		{"0x", "", false},
		{"60z0", "", true},
		{"608", "", true},
	}
	for _, c := range cases {
		got, err := Normalize(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("Normalize(%q) expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("Normalize(%q) unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("Normalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDecodeRoundTrip(t *testing.T) {
	b, err := Decode("0x6080fe")
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if len(b) != 3 || b[0] != 0x60 || b[2] != 0xfe {
		t.Fatalf("Decode mismatch: %x", b)
	}
}
