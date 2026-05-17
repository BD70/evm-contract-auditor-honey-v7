// Package loader loads detector rule files (.json / .yaml / .yml).
// Mirrors evm_check.rule_loader.
package loader

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// SupportedDetectorVersions mirrors evm_core.schemas.DETECTOR_SCHEMA_SUPPORTED_VERSIONS.
var SupportedDetectorVersions = map[string]struct{}{
	"1.0.0": {},
	"1.1.0": {},
}

// LoadRules reads a rule file or directory recursively, returning a flat list
// of detector dicts in stable filesystem-sorted order.
func LoadRules(path string) ([]map[string]any, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("rules path: %w", err)
	}
	files := []string{}
	if info.IsDir() {
		err := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(p))
			if ext == ".json" || ext == ".yaml" || ext == ".yml" {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		sort.Strings(files)
	} else {
		files = []string{path}
	}

	rules := []map[string]any{}
	for _, f := range files {
		data, err := LoadRuleFile(f)
		if err != nil {
			return nil, err
		}
		switch t := data.(type) {
		case []any:
			for _, item := range t {
				if m, ok := item.(map[string]any); ok {
					rules = append(rules, m)
				}
			}
		case map[string]any:
			rules = append(rules, t)
		}
	}
	return rules, nil
}

// LoadRuleFile reads a single rule file and parses JSON or YAML based on extension.
func LoadRuleFile(path string) (any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var data any
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".json" {
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.UseNumber()
		if err := dec.Decode(&data); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		data = ConvertNumbers(data)
	} else {
		if err := yaml.Unmarshal(raw, &data); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		data = NormalizeYAML(data)
	}
	if m, ok := data.(map[string]any); ok {
		validateSchemaVersion(m, filepath.Base(path))
	}
	return data, nil
}

func validateSchemaVersion(m map[string]any, name string) {
	v, ok := m["schema_version"]
	if !ok || v == nil {
		return
	}
	ver, _ := v.(string)
	if _, supported := SupportedDetectorVersions[ver]; !supported {
		fmt.Fprintf(os.Stderr, "warning: detector %s has schema_version=%q; supported: 1.0.0/1.1.0. continuing.\n", name, ver)
	}
}

// ConvertNumbers walks the decoded JSON tree converting json.Number into
// int64 (when integral) or float64. Mirrors Python's json module which
// preserves the int/float distinction.
func ConvertNumbers(v any) any {
	switch t := v.(type) {
	case json.Number:
		s := t.String()
		if isIntLiteral(s) {
			if i, err := t.Int64(); err == nil {
				return i
			}
		}
		if f, err := t.Float64(); err == nil {
			return f
		}
		return s
	case map[string]any:
		for k, val := range t {
			t[k] = ConvertNumbers(val)
		}
		return t
	case []any:
		for i, val := range t {
			t[i] = ConvertNumbers(val)
		}
		return t
	}
	return v
}

func isIntLiteral(s string) bool {
	if s == "" {
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

// NormalizeYAML coerces yaml.v3's map[interface{}]interface{} into map[string]any.
func NormalizeYAML(v any) any {
	switch t := v.(type) {
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			ks := fmt.Sprintf("%v", k)
			out[ks] = NormalizeYAML(val)
		}
		return out
	case map[string]any:
		for k, val := range t {
			t[k] = NormalizeYAML(val)
		}
		return t
	case []any:
		for i, val := range t {
			t[i] = NormalizeYAML(val)
		}
		return t
	}
	return v
}
