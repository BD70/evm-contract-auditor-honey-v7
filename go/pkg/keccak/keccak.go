// Package keccak wraps Keccak-256 utilities used for storage slot inference.
package keccak

import (
	"encoding/hex"

	"golang.org/x/crypto/sha3"
)

// Hash returns Keccak-256(data).
func Hash(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}

// HashHex returns hex-encoded Keccak-256(data).
func HashHex(data []byte) string {
	return hex.EncodeToString(Hash(data))
}

// MappingSlot returns keccak256(key || slot) — the canonical Solidity mapping
// storage layout. Inputs must be 32-byte big-endian buffers.
func MappingSlot(key, slot []byte) []byte {
	buf := make([]byte, 0, len(key)+len(slot))
	buf = append(buf, key...)
	buf = append(buf, slot...)
	return Hash(buf)
}

// ArraySlot returns keccak256(slot) — the base offset of a Solidity dynamic
// array's data region.
func ArraySlot(slot []byte) []byte {
	return Hash(slot)
}
