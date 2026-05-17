// Package resolver maps 4-byte function selectors and 32-byte event topics to
// human-readable signatures. Bundles a static catalog of common ERC/OZ/DeFi
// signatures (offline, no network). Optional remote fallback (4byte.directory)
// can be plumbed via Resolver.Remote.
package resolver

import (
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
)

//go:embed data/known_functions.json
var knownFunctionsJSON []byte

//go:embed data/known_events.json
var knownEventsJSON []byte

var (
	once       sync.Once
	functions  map[string]string
	events     map[string]string
)

func load() {
	once.Do(func() {
		_ = json.Unmarshal(knownFunctionsJSON, &functions)
		_ = json.Unmarshal(knownEventsJSON, &events)
		if functions == nil {
			functions = map[string]string{}
		}
		if events == nil {
			events = map[string]string{}
		}
	})
}

// Function returns the text signature for a 4-byte selector ("0xabcdef01" or
// "abcdef01"). Returns "" if unknown.
func Function(selector string) string {
	load()
	k := normalizeSelector(selector)
	return functions[k]
}

// Event returns the text signature for a 32-byte event topic.
func Event(topic string) string {
	load()
	return events[strings.ToLower(strings.TrimPrefix(topic, "0x"))]
}

// ResolveAll returns selector→signature for the given selectors using the
// embedded catalog. Unresolved selectors are absent from the result.
func ResolveAll(selectors []string) map[string]string {
	load()
	out := map[string]string{}
	for _, s := range selectors {
		k := normalizeSelector(s)
		if sig, ok := functions[k]; ok {
			out["0x"+k] = sig
		}
	}
	return out
}

// FunctionsCount + EventsCount expose catalog size for diagnostics.
func FunctionsCount() int { load(); return len(functions) }
func EventsCount() int    { load(); return len(events) }

func normalizeSelector(s string) string {
	s = strings.ToLower(strings.TrimPrefix(s, "0x"))
	return s
}
