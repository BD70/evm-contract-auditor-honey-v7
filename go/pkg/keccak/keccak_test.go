package keccak

import "testing"

// Ethereum Keccak-256 (0x01 padding), not NIST SHA3-256 (0x06). The empty-input
// digest is the canonical guard against accidentally swapping the padding.
func TestHashHexKnownVectors(t *testing.T) {
	cases := []struct {
		in   []byte
		want string
	}{
		{[]byte(""), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},
		{[]byte("abc"), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"},
	}
	for _, c := range cases {
		if got := HashHex(c.in); got != c.want {
			t.Errorf("HashHex(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestHashLength(t *testing.T) {
	if n := len(Hash([]byte("x"))); n != 32 {
		t.Fatalf("Hash length = %d, want 32", n)
	}
}
