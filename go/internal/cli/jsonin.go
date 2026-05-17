package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

// LoadJSONFile reads a JSON file into a map. Numbers are decoded with UseNumber
// then converted: integers → int64, floats → float64. Mirrors Python's json
// module behavior (ints as ints, floats as floats).
func LoadJSONFile(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	v = ConvertJSONNumbers(v)
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("expected JSON object at top level of %s", path)
	}
	return m, nil
}

// ConvertJSONNumbers walks the decoded tree and replaces json.Number with
// int64 (when integral) or float64.
func ConvertJSONNumbers(v any) any {
	switch t := v.(type) {
	case json.Number:
		s := t.String()
		if isIntegerLiteral(s) {
			if i, err := strconv.ParseInt(s, 10, 64); err == nil {
				return i
			}
		}
		if f, err := t.Float64(); err == nil {
			return f
		}
		return s
	case map[string]any:
		for k, val := range t {
			t[k] = ConvertJSONNumbers(val)
		}
		return t
	case []any:
		for i, val := range t {
			t[i] = ConvertJSONNumbers(val)
		}
		return t
	}
	return v
}

func isIntegerLiteral(s string) bool {
	if len(s) == 0 {
		return false
	}
	i := 0
	if s[0] == '-' || s[0] == '+' {
		i++
	}
	if i == len(s) {
		return false
	}
	for ; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
