package check

import (
	"encoding/json"
	"sort"
	"strconv"
)

// AsMap returns m if v is a map[string]any, else an empty map. Mirrors
// Python's .get(field, {}) idiom.
func AsMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

// AsList returns v as []any or an empty slice.
func AsList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return nil
}

// AsStringList coerces v to []string. Non-string entries are dropped.
func AsStringList(v any) []string {
	out := []string{}
	switch t := v.(type) {
	case []string:
		return append([]string{}, t...)
	case []any:
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// AsString returns v as string or "".
func AsString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// AsBool returns v as bool, default false.
func AsBool(v any) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}

// AsFloat coerces numeric JSON values to float64.
func AsFloat(v any, def float64) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case float32:
		return float64(t)
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case json.Number:
		f, err := t.Float64()
		if err == nil {
			return f
		}
	case string:
		f, err := strconv.ParseFloat(t, 64)
		if err == nil {
			return f
		}
	}
	return def
}

// AsInt coerces numeric JSON values to int.
func AsInt(v any, def int) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case int64:
		return int(t)
	case json.Number:
		i, err := t.Int64()
		if err == nil {
			return int(i)
		}
	case string:
		i, err := strconv.Atoi(t)
		if err == nil {
			return i
		}
	}
	return def
}

// SetFromList returns a set built from a []string-ish value.
func SetFromList(v any) map[string]struct{} {
	out := map[string]struct{}{}
	for _, s := range AsStringList(v) {
		out[s] = struct{}{}
	}
	return out
}

// SortedSet returns the keys of s in sorted order.
func SortedSet(s map[string]struct{}) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// SortedFilter returns sorted strings from configured present in set s.
func SortedFilter(s map[string]struct{}, configured []string) []string {
	out := []string{}
	for _, t := range configured {
		if _, ok := s[t]; ok {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	// Dedup
	if len(out) > 1 {
		dedup := out[:1]
		for _, v := range out[1:] {
			if v != dedup[len(dedup)-1] {
				dedup = append(dedup, v)
			}
		}
		out = dedup
	}
	return out
}

// IntersectAny reports whether a and b share at least one element.
func IntersectAny(a, b map[string]struct{}) bool {
	if len(a) > len(b) {
		a, b = b, a
	}
	for k := range a {
		if _, ok := b[k]; ok {
			return true
		}
	}
	return false
}

// Intersection returns sorted intersection of a and b.
func Intersection(a, b map[string]struct{}) []string {
	out := []string{}
	for k := range a {
		if _, ok := b[k]; ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// SameMajor reports whether two semver-ish strings share a major.
func SameMajor(a, b string) bool {
	return major(a) == major(b)
}

func major(v string) string {
	for i, c := range v {
		if c == '.' {
			return v[:i]
		}
	}
	return v
}
