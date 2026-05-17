// Command evm-decon runs the EVM bytecode deconstruction pipeline and emits
// behavior JSON v2.
//
// Status: foundation stages wired (disasm/blocks/selectors/metadata/patterns/
// stacksim/cfg). Function slicing, ABI recovery, storage layout, semantic
// patterns, and full audit_json output are pending — the current --format json
// emits a schema-valid skeleton only. Use `python3 -m evm_decon` for full
// audits until those stages land.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/evm-auditor/evm-auditor/internal/cli"
	"github.com/evm-auditor/evm-auditor/internal/decon/builder"
	"github.com/evm-auditor/evm-auditor/internal/decon/pipeline"
	"github.com/evm-auditor/evm-auditor/internal/decon/pseudocode"
	"github.com/evm-auditor/evm-auditor/internal/version"
)

func main() {
	var (
		file        string
		hexStr      string
		format      string
		output      string
		noResolve   bool
		noProfiles  bool
		noBlocks    bool
		noDeep      bool
		eof         bool
		proxyShell  bool
		profileDirs []string
	)
	root := &cobra.Command{
		Use:           "evm-decon",
		Short:         "Deconstruct EVM bytecode into behavior JSON v2.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.Version,
		RunE: func(cmd *cobra.Command, args []string) error {
			if file == "" && hexStr == "" {
				return fmt.Errorf("one of --file or --hex is required")
			}
			bytecode := hexStr
			if file != "" {
				raw, err := os.ReadFile(file)
				if err != nil {
					return err
				}
				bytecode = trimSpace(string(raw))
			}
			art, err := pipeline.Analyze(bytecode, pipeline.Options{
				NoResolve:   noResolve,
				NoProfiles:  noProfiles,
				NoBlocks:    noBlocks,
				NoDeep:      noDeep,
				EOFFormat:   eof,
				ProxyShell:  proxyShell,
				ProfileDirs: profileDirs,
			})
			if err != nil {
				return err
			}
			switch format {
			case "json":
				return cli.WriteJSONOutput(builder.Build(art), output)
			case "semantic":
				report := pseudocode.Render(builder.Build(art))
				if output != "" {
					return os.WriteFile(output, []byte(report), 0o644)
				}
				fmt.Print(report)
				return nil
			default:
				return fmt.Errorf("unsupported format: %s", format)
			}
		},
	}
	root.Flags().StringVar(&file, "file", "", "Path to bytecode hex file")
	root.Flags().StringVar(&hexStr, "hex", "", "Raw runtime bytecode hex string")
	root.Flags().StringVar(&format, "format", "semantic", "Output format: json | semantic")
	root.Flags().StringVarP(&output, "output", "o", "", "Write to file instead of stdout")
	root.Flags().BoolVar(&noResolve, "no-resolve", false, "Disable external selector API calls")
	root.Flags().BoolVar(&noProfiles, "no-profiles", false, "Disable default data profile loading")
	root.Flags().BoolVar(&noBlocks, "no-blocks", false, "Skip basic-block analysis")
	root.Flags().BoolVar(&noDeep, "no-deep", false, "Skip stack sim, CFG, pseudocode")
	root.Flags().BoolVar(&eof, "eof", false, "Input bytecode is EIP-3541 EOF format")
	root.Flags().BoolVar(&proxyShell, "proxy-shell", false, "Input is a known proxy shell")
	root.Flags().StringSliceVar(&profileDirs, "profiles-dir", nil, "Profile directories")

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func trimSpace(s string) string {
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
