// Command evm-audit deconstructs bytecode and runs deterministic vulnerability
// rules. Drop-in replacement for `python3 -m evm_audit`.
//
// During Phases 1–4 the binary delegates the EVM deconstruction stage to the
// existing Python `evm_decon` CLI via subprocess. Phase 3 replaces that with an
// in-process Go pipeline.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/evm-auditor/evm-auditor/internal/audit"
	chk "github.com/evm-auditor/evm-auditor/internal/check"
	"github.com/evm-auditor/evm-auditor/internal/check/apijson"
	"github.com/evm-auditor/evm-auditor/internal/check/llmjudge"
	"github.com/evm-auditor/evm-auditor/internal/check/loader"
	"github.com/evm-auditor/evm-auditor/internal/check/sarif"
	"github.com/evm-auditor/evm-auditor/internal/cli"
	"github.com/evm-auditor/evm-auditor/internal/version"
)

func main() {
	var (
		file             string
		hex              string
		rules            string
		format           string
		output           string
		noResolve        bool
		noProfiles       bool
		profileDirs      []string
		llmJudge         bool
		llmJudgeRefresh  bool
		chainContext     string
		eof              bool
		proxyShell       bool
		stepBudgetMs     int
		strictOutput     bool
	)
	root := &cobra.Command{
		Use:           "evm-audit",
		Short:         "Deconstruct bytecode and run deterministic vulnerability rules.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       "evm_audit " + version.Version,
		RunE: func(cmd *cobra.Command, args []string) error {
			if file == "" && hex == "" {
				return fmt.Errorf("one of --file or --hex is required")
			}
			var chainCtx map[string]any
			if chainContext != "" {
				if err := json.Unmarshal([]byte(chainContext), &chainCtx); err != nil {
					return fmt.Errorf("--chain-context is not valid JSON: %w", err)
				}
			}
			bytecodePath := file
			bytecodeHex := hex
			inputKind := "hex_file"
			inputValue := bytecodePath
			tempPath := ""
			if hex != "" {
				p, err := writeTempHex(hex)
				if err != nil {
					return err
				}
				tempPath = p
				bytecodePath = p
				inputKind = "hex_string"
				inputValue = "<inline_hex>"
			} else {
				raw, err := os.ReadFile(bytecodePath)
				if err != nil {
					return err
				}
				bytecodeHex = trim(string(raw))
			}
			defer func() {
				if tempPath != "" {
					_ = os.Remove(tempPath)
				}
			}()

			opts := audit.Options{
				NoResolve:    noResolve,
				NoProfiles:   noProfiles,
				ProfileDirs:  profileDirs,
				EOF:          eof,
				ProxyShell:   proxyShell,
				StepBudgetMs: stepBudgetMs,
				RulesPath:    rules,
				BytecodePath: bytecodePath,
				BytecodeHex:  bytecodeHex,
				InputKind:    inputKind,
			}
			behavior, checker, err := audit.AuditBytecode(opts)
			if err != nil {
				return err
			}
			if llmJudge {
				cfg := llmjudge.LoadConfig(llmJudgeRefresh)
				if !llmjudge.IsAvailable(cfg) {
					fmt.Fprintf(os.Stderr, "warning: LLM judge requested but server at %s is unreachable; skipping\n", cfg.BaseURL)
				} else {
					rs, err := loader.LoadRules(rules)
					if err != nil {
						return err
					}
					byID := map[string]map[string]any{}
					for _, r := range rs {
						id := chk.AsString(chk.AsMap(r["rule"])["id"])
						byID[id] = r
					}
					findings := []map[string]any{}
					for _, f := range chk.AsList(checker["findings"]) {
						findings = append(findings, chk.AsMap(f))
					}
					judged := llmjudge.RunJudgePass(findings, behavior, byID, cfg)
					out := make([]any, len(judged))
					for i, f := range judged {
						out[i] = f
					}
					checker = copyMap(checker)
					checker["findings"] = out
					checker["llm_judge_model"] = cfg.Model
					checker["llm_judge_base_url"] = cfg.BaseURL
				}
			}

			var doc any
			switch format {
			case "sarif":
				doc = sarif.ToSARIF(checker)
			case "api-json":
				doc = apijson.ToAPIJSON(behavior, checker, inputKind, inputValue, bytecodeHex, chainCtx)
			default:
				behavior["checker_findings"] = checker["findings"]
				behavior["checker_trace"] = checker["trace"]
				doc = behavior
			}
			if strictOutput {
				if err := validateStrictOutput(format, doc); err != nil {
					fmt.Fprintf(os.Stderr, "strict-output violation: %v\n", err)
					os.Exit(2)
				}
			}
			return cli.WriteJSONOutput(doc, output)
		},
	}

	root.Flags().StringVar(&file, "file", "", "Path to bytecode hex file")
	root.Flags().StringVar(&hex, "hex", "", "Raw runtime bytecode hex string")
	root.Flags().StringVar(&rules, "rules", "", "Rule file or directory")
	root.Flags().StringVar(&format, "format", "json", "Output format: json | sarif | api-json")
	root.Flags().StringVarP(&output, "output", "o", "", "Write audit result to file")
	root.Flags().BoolVar(&noResolve, "no-resolve", false, "Disable external selector API calls")
	root.Flags().BoolVar(&noProfiles, "no-profiles", false, "Disable default data profile loading")
	root.Flags().StringSliceVar(&profileDirs, "profiles-dir", nil, "Directory containing contract profile JSON files")
	root.Flags().BoolVar(&llmJudge, "llm-judge", false, "Pass findings through a local LLM judge")
	root.Flags().BoolVar(&llmJudgeRefresh, "llm-judge-refresh", false, "Ignore cached judge results")
	root.Flags().StringVar(&chainContext, "chain-context", "", "JSON object with chain metadata")
	root.Flags().BoolVar(&eof, "eof", false, "Input is EIP-3541 EOF format")
	root.Flags().BoolVar(&proxyShell, "proxy-shell", false, "Input is a known proxy shell")
	root.Flags().IntVar(&stepBudgetMs, "step-budget-ms", 0, "Soft per-step wall-clock budget in ms")
	root.Flags().BoolVar(&strictOutput, "strict-output", false, "Validate output schema before write; exit 2 on violation")
	root.Flags().MarkHidden("profile-dir") //nolint:errcheck — alias

	_ = root.MarkFlagRequired("rules")

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func validateStrictOutput(format string, doc any) error {
	m, ok := doc.(map[string]any)
	if !ok {
		return nil // sarif or other typed struct — skip map validation
	}
	switch format {
	case "api-json":
		required := []string{"schema", "findings", "input", "ok"}
		for _, k := range required {
			if _, exists := m[k]; !exists {
				return fmt.Errorf("api-json missing required field %q", k)
			}
		}
		schemaVal, _ := m["schema"].(string)
		if schemaVal == "" {
			return fmt.Errorf("api-json field \"schema\" is empty")
		}
	default:
		required := []string{"bytecode_md5", "functions", "tags"}
		for _, k := range required {
			if _, exists := m[k]; !exists {
				return fmt.Errorf("behavior output missing required field %q", k)
			}
		}
	}
	return nil
}

func writeTempHex(raw string) (string, error) {
	normalized := trim(raw)
	if len(normalized) < 2 || normalized[0:2] != "0x" {
		normalized = "0x" + normalized
	}
	f, err := os.CreateTemp("", "evm-audit-*.hex")
	if err != nil {
		return "", err
	}
	if _, err := f.WriteString(normalized + "\n"); err != nil {
		f.Close()
		return "", err
	}
	f.Close()
	return f.Name(), nil
}

func trim(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t' || s[0] == '\n' || s[0] == '\r') {
		s = s[1:]
	}
	for len(s) > 0 {
		c := s[len(s)-1]
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			break
		}
		s = s[:len(s)-1]
	}
	return s
}

func copyMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
