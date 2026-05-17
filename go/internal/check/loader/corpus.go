package loader

import (
	"fmt"
	"os"
	"path/filepath"

	chk "github.com/evm-auditor/evm-auditor/internal/check"
)

// LoadCorpusManifest mirrors evm_check.corpus_loader.load_corpus_manifest.
func LoadCorpusManifest(path string, expectedRuleID string) (map[string]any, error) {
	manifestPath := filepath.Join(path, "corpus.json")
	if _, err := os.Stat(manifestPath); err != nil {
		return nil, fmt.Errorf("missing corpus manifest: %s", manifestPath)
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}
	var v any
	if err := decodeJSON(raw, &v); err != nil {
		return nil, fmt.Errorf("parse %s: %w", manifestPath, err)
	}
	v = ConvertNumbers(v)
	corpus, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("corpus manifest must be a JSON object: %s", manifestPath)
	}
	validation := chk.ValidateCorpus(corpus, expectedRuleID)
	if !validation["ok"].(bool) {
		errs := validation["errors"].([]string)
		return nil, fmt.Errorf("%s", joinSemi(errs))
	}
	return corpus, nil
}

func decodeJSON(raw []byte, v *any) error {
	dec := newDecoder(raw)
	return dec.Decode(v)
}

func joinSemi(items []string) string {
	out := ""
	for i, s := range items {
		if i > 0 {
			out += "; "
		}
		out += s
	}
	return out
}
