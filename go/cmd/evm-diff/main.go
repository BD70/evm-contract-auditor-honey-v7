// Command evm-diff compares a source-truth fixture against an evm-audit
// behavior JSON. Drop-in replacement for `python3 -m evm_diff`.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/evm-auditor/evm-auditor/internal/cli"
	"github.com/evm-auditor/evm-auditor/internal/diff"
	"github.com/evm-auditor/evm-auditor/internal/version"
)

func main() {
	var sourceTruth, auditJSON, output string
	root := &cobra.Command{
		Use:           "evm-diff",
		Short:         "Compare source-derived test truth against evm-audit behavior JSON.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.Version,
		RunE: func(cmd *cobra.Command, args []string) error {
			truth, err := cli.LoadJSONFile(sourceTruth)
			if err != nil {
				return err
			}
			audit, err := cli.LoadJSONFile(auditJSON)
			if err != nil {
				return err
			}
			result := diff.DiffTruth(truth, audit)
			if err := cli.WriteJSONOutput(result, output); err != nil {
				return err
			}
			if !result["ok"].(bool) {
				os.Exit(1)
			}
			return nil
		},
	}
	root.Flags().StringVar(&sourceTruth, "source-truth", "", "Truth fixture JSON")
	root.Flags().StringVar(&auditJSON, "audit-json", "", "Audit behavior JSON")
	root.Flags().StringVarP(&output, "output", "o", "", "Write diff result to file")
	_ = root.MarkFlagRequired("source-truth")
	_ = root.MarkFlagRequired("audit-json")

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
