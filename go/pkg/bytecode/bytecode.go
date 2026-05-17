// Package bytecode contains shared hex-decoding helpers used by both decon and
// check binaries.
package bytecode

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Normalize strips whitespace and the optional 0x prefix from a hex string,
// lowercases it, and validates that every character is hex.
func Normalize(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	s = strings.ToLower(s)
	if len(s)%2 != 0 {
		return "", fmt.Errorf("hex length must be even, got %d", len(s))
	}
	for _, c := range s {
		if !isHex(c) {
			return "", fmt.Errorf("non-hex character %q in bytecode", c)
		}
	}
	return s, nil
}

// Decode normalizes raw and returns the decoded byte slice.
func Decode(raw string) ([]byte, error) {
	s, err := Normalize(raw)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(s)
}

// SHA256Hex returns the hex sha256 of the normalized bytecode bytes.
func SHA256Hex(raw string) (string, error) {
	b, err := Decode(raw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func isHex(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}
