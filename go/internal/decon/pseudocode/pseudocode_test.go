package pseudocode

import (
	"strings"
	"testing"

	"github.com/evm-auditor/evm-auditor/internal/decon/builder"
	"github.com/evm-auditor/evm-auditor/internal/decon/pipeline"
)

func TestRenderSmoke(t *testing.T) {
	fixtures := []string{
		"0x363d3d373d3d3d363d73bebebebebebebebebebebebebebebebebebebebe5af43d82803e903d91602b57fd5bf3",
		"0x6080604052e30c397879ba50978da5cb5bf2fde38b91d148542f2ff15dd547741f00",
		"0x60003560e01c80638da5cb5b1461001257005b00",
	}
	for _, h := range fixtures {
		art, err := pipeline.Analyze(h, pipeline.Options{NoResolve: true})
		if err != nil {
			t.Fatalf("Analyze(%s): %v", h[:10], err)
		}
		report := Render(builder.Build(art))
		for _, want := range []string{
			"EVM SEMANTIC DECONSTRUCTION REPORT",
			"1. CONTRACT IDENTITY",
			"2. INTERFACE TABLE",
			"3. SEMANTIC ARCHITECTURE",
			"4. STORAGE LAYOUT",
			"5. FUNCTION CARDS",
			"6. RISK SUMMARY",
		} {
			if !strings.Contains(report, want) {
				t.Errorf("fixture %s: report missing section %q", h[:12], want)
			}
		}
		// Determinism: same input → identical output.
		if Render(builder.Build(art)) != report {
			t.Errorf("fixture %s: non-deterministic render", h[:12])
		}
	}
}
