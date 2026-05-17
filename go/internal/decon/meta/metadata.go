// Package meta extracts Solidity CBOR metadata from runtime bytecode.
// Mirrors evm_decon/metadata.py.
package meta

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// CompilerInfo identifies the compiler that produced the bytecode.
type CompilerInfo struct {
	Name       string  // "solc" / "vyper" / "unknown"
	Version    string  // e.g. "0.8.20"
	RawVersion []byte  // raw 3-byte version, when present
}

// Result mirrors evm_decon.metadata.MetadataResult.
type Result struct {
	Found               bool
	Compiler            *CompilerInfo
	HashProtocol        string // "ipfs" | "bzzr0" | "bzzr1"
	HashValue           string
	CBORLength          int
	CBORRaw             []byte
	MetadataStartOffset int
	Experimental        bool
	RawDecoded          map[string]any
	Errors              []string
}

// Extract parses Solidity-style trailing CBOR metadata from a hex bytecode
// string. Returns Result with Found=false (and a populated Errors slice) on any
// failure path; never returns an error.
func Extract(bytecodeHex string) Result {
	clean := normalize(bytecodeHex)
	bc, err := hex.DecodeString(clean)
	if err != nil {
		return Result{Errors: []string{"Invalid hex"}}
	}
	if len(bc) < 4 {
		return Result{Errors: []string{"Bytecode too short for metadata"}}
	}
	cborLen := int(binary.BigEndian.Uint16(bc[len(bc)-2:]))
	if cborLen == 0 || cborLen+2 > len(bc) {
		return Result{CBORLength: cborLen, Errors: []string{"CBOR length invalid or exceeds bytecode"}}
	}
	cborStart := len(bc) - 2 - cborLen
	cborData := bc[cborStart : len(bc)-2]
	if len(cborData) == 0 || (cborData[0]&0xe0)>>5 != 5 {
		return Result{
			CBORLength: cborLen, CBORRaw: cborData, MetadataStartOffset: cborStart,
			Errors: []string{"CBOR data doesn't start with map marker"},
		}
	}
	decoded, ok := decodeCBORMap(cborData)
	if !ok {
		return Result{
			CBORLength: cborLen, CBORRaw: cborData, MetadataStartOffset: cborStart,
			Errors: []string{"Failed to decode CBOR"},
		}
	}

	res := Result{
		Found:               true,
		CBORLength:          cborLen,
		CBORRaw:             cborData,
		MetadataStartOffset: cborStart,
		RawDecoded:          map[string]any{},
	}
	if v, ok := decoded["solc"]; ok {
		ci := &CompilerInfo{Name: "solc"}
		if b, ok := v.([]byte); ok && len(b) == 3 {
			ci.Version = fmt.Sprintf("%d.%d.%d", b[0], b[1], b[2])
			ci.RawVersion = b
		} else if b, ok := v.([]byte); ok {
			ci.Version = hex.EncodeToString(b)
			ci.RawVersion = b
		} else {
			ci.Version = fmt.Sprint(v)
		}
		res.Compiler = ci
	}
	for _, proto := range []string{"ipfs", "bzzr1", "bzzr0"} {
		if v, ok := decoded[proto]; ok {
			res.HashProtocol = proto
			if b, ok := v.([]byte); ok {
				res.HashValue = hex.EncodeToString(b)
			} else {
				res.HashValue = fmt.Sprint(v)
			}
			break
		}
	}
	if v, ok := decoded["experimental"].(bool); ok {
		res.Experimental = v
	}
	for k, v := range decoded {
		if b, ok := v.([]byte); ok {
			res.RawDecoded[k] = hex.EncodeToString(b)
		} else {
			res.RawDecoded[k] = v
		}
	}
	return res
}

func decodeCBORMap(data []byte) (map[string]any, bool) {
	if len(data) < 2 {
		return nil, false
	}
	out := map[string]any{}
	pos := 0
	if (data[pos]&0xe0)>>5 != 5 {
		return nil, false
	}
	numPairs := int(data[pos] & 0x1f)
	pos++
	for i := 0; i < numPairs; i++ {
		if pos >= len(data) {
			break
		}
		key, npos, ok := readString(data, pos)
		if !ok {
			break
		}
		pos = npos
		if pos >= len(data) {
			break
		}
		val, npos, ok := readValue(data, pos)
		if !ok {
			break
		}
		out[key] = val
		pos = npos
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

func readLen(data []byte, pos int, additional int) (int, int, bool) {
	switch {
	case additional <= 23:
		return additional, pos, true
	case additional == 24:
		if pos >= len(data) {
			return 0, 0, false
		}
		return int(data[pos]), pos + 1, true
	case additional == 25:
		if pos+2 > len(data) {
			return 0, 0, false
		}
		return int(binary.BigEndian.Uint16(data[pos : pos+2])), pos + 2, true
	}
	return 0, 0, false
}

func readString(data []byte, pos int) (string, int, bool) {
	major := (data[pos] & 0xe0) >> 5
	additional := int(data[pos] & 0x1f)
	pos++
	if major != 2 && major != 3 {
		return "", 0, false
	}
	length, npos, ok := readLen(data, pos, additional)
	if !ok {
		return "", 0, false
	}
	pos = npos
	if pos+length > len(data) {
		return "", 0, false
	}
	s := string(data[pos : pos+length])
	return s, pos + length, true
}

func readValue(data []byte, pos int) (any, int, bool) {
	major := (data[pos] & 0xe0) >> 5
	additional := int(data[pos] & 0x1f)
	switch major {
	case 0: // unsigned integer
		pos++
		return readUInt(data, pos, additional)
	case 2: // byte string
		pos++
		length, npos, ok := readLen(data, pos, additional)
		if !ok {
			return nil, 0, false
		}
		pos = npos
		if pos+length > len(data) {
			return nil, 0, false
		}
		return append([]byte(nil), data[pos:pos+length]...), pos + length, true
	case 3: // text string
		pos++
		length, npos, ok := readLen(data, pos, additional)
		if !ok {
			return nil, 0, false
		}
		pos = npos
		if pos+length > len(data) {
			return nil, 0, false
		}
		return string(data[pos : pos+length]), pos + length, true
	case 7: // simple values
		pos++
		switch additional {
		case 20:
			return false, pos, true
		case 21:
			return true, pos, true
		case 22:
			return nil, pos, true
		}
		return nil, pos, true
	}
	return nil, pos + 1, true
}

func readUInt(data []byte, pos int, additional int) (any, int, bool) {
	switch {
	case additional <= 23:
		return additional, pos, true
	case additional == 24:
		if pos >= len(data) {
			return nil, 0, false
		}
		return int(data[pos]), pos + 1, true
	case additional == 25:
		if pos+2 > len(data) {
			return nil, 0, false
		}
		return int(binary.BigEndian.Uint16(data[pos : pos+2])), pos + 2, true
	}
	return nil, 0, false
}

func normalize(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\n", "")
	return strings.ToLower(s)
}
