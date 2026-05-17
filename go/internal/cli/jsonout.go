// Package cli holds shared CLI helpers used by every binary.
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

// EncodePythonCompat emits v as JSON with Python's `json.dumps(..., indent=2,
// sort_keys=True)` formatting:
//   - 2-space indent, ": " key separator, ",\n" item separator
//   - sorted map keys
//   - ensure_ascii=True (\uXXXX escaping for any non-ASCII rune)
//   - float formatting matches repr(): integers render as `1.0`, etc.
//   - HTML-special chars (<, >, &) are NOT escaped (matches Python default).
func EncodePythonCompat(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encodeValue(&buf, v, 0); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// WritePythonJSON writes v to dest using Python-compatible formatting plus a
// trailing newline.
func WritePythonJSON(dest io.Writer, v any) error {
	b, err := EncodePythonCompat(v)
	if err != nil {
		return err
	}
	if _, err := dest.Write(b); err != nil {
		return err
	}
	if _, err := dest.Write([]byte("\n")); err != nil {
		return err
	}
	return nil
}

// WriteJSONOutput writes v to file (if path != "") or stdout.
func WriteJSONOutput(v any, path string) error {
	if path == "" {
		return WritePythonJSON(os.Stdout, v)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return WritePythonJSON(f, v)
}

func indent(buf *bytes.Buffer, level int) {
	for i := 0; i < level; i++ {
		buf.WriteString("  ")
	}
}

func encodeValue(buf *bytes.Buffer, v any, level int) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		encodeString(buf, t)
	case json.Number:
		buf.WriteString(string(t))
	case float64:
		buf.WriteString(formatFloat(t))
	case float32:
		buf.WriteString(formatFloat(float64(t)))
	case int:
		buf.WriteString(strconv.Itoa(t))
	case int64:
		buf.WriteString(strconv.FormatInt(t, 10))
	case int32:
		buf.WriteString(strconv.FormatInt(int64(t), 10))
	case uint64:
		buf.WriteString(strconv.FormatUint(t, 10))
	case map[string]any:
		if t == nil {
			buf.WriteString("null")
			return nil
		}
		return encodeMap(buf, t, level)
	case []any:
		if t == nil {
			buf.WriteString("null")
			return nil
		}
		return encodeList(buf, t, level)
	case []string:
		conv := make([]any, len(t))
		for i, s := range t {
			conv[i] = s
		}
		return encodeList(buf, conv, level)
	default:
		// Fall back through encoding/json so any tagged struct still works.
		raw, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("encode %T: %w", v, err)
		}
		var anyVal any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&anyVal); err != nil {
			return err
		}
		return encodeValue(buf, anyVal, level)
	}
	return nil
}

func encodeMap(buf *bytes.Buffer, m map[string]any, level int) error {
	if len(m) == 0 {
		buf.WriteString("{}")
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	buf.WriteString("{\n")
	for i, k := range keys {
		indent(buf, level+1)
		encodeString(buf, k)
		buf.WriteString(": ")
		if err := encodeValue(buf, m[k], level+1); err != nil {
			return err
		}
		if i < len(keys)-1 {
			buf.WriteString(",")
		}
		buf.WriteString("\n")
	}
	indent(buf, level)
	buf.WriteString("}")
	return nil
}

func encodeList(buf *bytes.Buffer, l []any, level int) error {
	if len(l) == 0 {
		buf.WriteString("[]")
		return nil
	}
	buf.WriteString("[\n")
	for i, item := range l {
		indent(buf, level+1)
		if err := encodeValue(buf, item, level+1); err != nil {
			return err
		}
		if i < len(l)-1 {
			buf.WriteString(",")
		}
		buf.WriteString("\n")
	}
	indent(buf, level)
	buf.WriteString("]")
	return nil
}

func encodeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			buf.WriteString(`\\`)
		case '"':
			buf.WriteString(`\"`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else if r < 0x7f {
				buf.WriteRune(r)
			} else if r <= 0xFFFF {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				// Surrogate pair (matches Python ensure_ascii=True for non-BMP).
				r -= 0x10000
				hi := 0xD800 + ((r >> 10) & 0x3FF)
				lo := 0xDC00 + (r & 0x3FF)
				fmt.Fprintf(buf, `\u%04x\u%04x`, hi, lo)
			}
		}
	}
	buf.WriteByte('"')
}

// formatFloat mirrors Python repr() float format used by json.dumps:
//   - integers render with `.0` (e.g. 1.0)
//   - non-integers use shortest round-trip representation (Go's 'g' close enough)
func formatFloat(f float64) string {
	if f == float64(int64(f)) {
		return strconv.FormatInt(int64(f), 10) + ".0"
	}
	s := strconv.FormatFloat(f, 'g', -1, 64)
	// Python emits exponents as `1e+20`, Go emits `1e+20` too. Lowercase 'e' matches.
	if !strings.ContainsAny(s, ".eE") {
		s += ".0"
	}
	return s
}
