package pipeline

import (
	"encoding/hex"
	"fmt"
	"strings"
)

func normalizeAndValidate(s string) (string, error) {
	clean := strings.TrimSpace(s)
	clean = strings.TrimPrefix(clean, "0x")
	clean = strings.TrimPrefix(clean, "0X")
	clean = strings.ReplaceAll(clean, " ", "")
	clean = strings.ReplaceAll(clean, "\n", "")
	if len(clean)%2 != 0 {
		return "", fmt.Errorf("hex length must be even")
	}
	for _, c := range clean {
		ok := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !ok {
			return "", fmt.Errorf("non-hex character %q", c)
		}
	}
	return strings.ToLower(clean), nil
}

func hexToBytes(s string) ([]byte, error) {
	return hex.DecodeString(s)
}
