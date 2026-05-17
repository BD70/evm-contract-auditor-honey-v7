// Command evm-rule is the detector workbench (init / test / validate / doctor /
// explain). Drop-in replacement for `python3 -m evm_rule`.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/evm-auditor/evm-auditor/internal/cli"
	"github.com/evm-auditor/evm-auditor/internal/rule"
	"github.com/evm-auditor/evm-auditor/internal/version"
)

func main() {
	root := &cobra.Command{
		Use:           "evm-rule",
		Short:         "Detector workbench for deterministic evm-audit checks.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.Version,
	}

	// init
	var initOutDir, initCorpusDir string
	initCmd := &cobra.Command{
		Use:   "init <rule_id>",
		Short: "Create a detector template and paired corpus manifest",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := rule.Init(args[0], initOutDir, initCorpusDir)
			if err != nil {
				return err
			}
			return cli.WritePythonJSON(os.Stdout, result)
		},
	}
	initCmd.Flags().StringVar(&initOutDir, "output-dir", "rules", "")
	initCmd.Flags().StringVar(&initCorpusDir, "corpus-dir", "corpus", "")
	root.AddCommand(initCmd)

	// test
	root.AddCommand(&cobra.Command{
		Use:   "test <rule> <corpus>",
		Short: "Run a detector against a fixture corpus",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			result, ok, err := rule.Test(args[0], args[1])
			if err != nil {
				return err
			}
			if err := cli.WritePythonJSON(os.Stdout, result); err != nil {
				return err
			}
			if !ok {
				os.Exit(1)
			}
			return nil
		},
	})

	// explain
	root.AddCommand(&cobra.Command{
		Use:   "explain <rule> <audit_json>",
		Short: "Show why a detector matched or did not match an audit JSON",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := rule.Explain(args[0], args[1])
			if err != nil {
				return err
			}
			return cli.WritePythonJSON(os.Stdout, result)
		},
	})

	// validate
	root.AddCommand(&cobra.Command{
		Use:   "validate <rule>",
		Short: "Validate detector schema, corpus mapping, and proof policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := rule.Validate(args[0])
			if err != nil {
				return err
			}
			if err := cli.WritePythonJSON(os.Stdout, result); err != nil {
				return err
			}
			if !result["ok"].(bool) {
				os.Exit(1)
			}
			return nil
		},
	})

	// doctor
	root.AddCommand(&cobra.Command{
		Use:   "doctor <rule>",
		Short: "Find shallow-detector anti-patterns",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := rule.Doctor(args[0])
			if err != nil {
				return err
			}
			return cli.WritePythonJSON(os.Stdout, result)
		},
	})

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
