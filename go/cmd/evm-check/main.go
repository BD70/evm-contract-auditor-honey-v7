// Command evm-check runs deterministic vulnerability detectors against an
// evm-audit behavior JSON file. Drop-in replacement for `python3 -m evm_check`.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/evm-auditor/evm-auditor/internal/check/engine"
	"github.com/evm-auditor/evm-auditor/internal/check/loader"
	"github.com/evm-auditor/evm-auditor/internal/check/sarif"
	"github.com/evm-auditor/evm-auditor/internal/cli"
	"github.com/evm-auditor/evm-auditor/internal/version"
)

func main() {
	var (
		facts            string
		rules            string
		format           string
		output           string
		llmJudge         bool
		llmJudgeRefresh  bool
	)

	root := &cobra.Command{
		Use:           "evm-check",
		Short:         "Run deterministic vulnerability rules against evm-audit behavior JSON.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.Version,
		RunE: func(cmd *cobra.Command, args []string) error {
			audit, err := cli.LoadJSONFile(facts)
			if err != nil {
				return err
			}
			rs, err := loader.LoadRules(rules)
			if err != nil {
				return err
			}
			result, err := engine.CheckAudit(audit, rs)
			if err != nil {
				return err
			}
			if llmJudge {
				fmt.Fprintln(os.Stderr, "warning: --llm-judge not yet implemented in Go port; skipping")
				_ = llmJudgeRefresh
			}
			var out any = result
			if format == "sarif" {
				out = sarif.ToSARIF(result)
			}
			return cli.WriteJSONOutput(out, output)
		},
	}

	root.Flags().StringVar(&facts, "facts", "", "Path to evm-audit behavior JSON")
	root.Flags().StringVar(&rules, "rules", "", "Rule file or directory")
	root.Flags().StringVar(&format, "format", "json", "Output format: json | sarif")
	root.Flags().StringVarP(&output, "output", "o", "", "Write checker result to file")
	root.Flags().BoolVar(&llmJudge, "llm-judge", false, "Pass findings through a local LLM judge (not yet implemented in Go port)")
	root.Flags().BoolVar(&llmJudgeRefresh, "llm-judge-refresh", false, "Ignore cached judge results and re-query the model")
	_ = root.MarkFlagRequired("facts")
	_ = root.MarkFlagRequired("rules")

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
