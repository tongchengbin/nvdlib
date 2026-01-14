package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

type rootFlags struct {
	APIKey string
	Delay  float64
	Proxy  string
	Output string
	Pretty bool
	Debug  bool
}

func NewRootCmd() *cobra.Command {
	var rf rootFlags

	cmd := &cobra.Command{
		Use:   "nvd",
		Short: "NVD (NIST) API v2 command-line client",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Validate delay rules (match nvdlib behavior)
			if rf.Delay != 0 {
				if rf.APIKey == "" {
					return fmt.Errorf("--delay requires --api-key; without an API key the default delay is 6 seconds")
				}
				if rf.Delay < 0.6 {
					return fmt.Errorf("--delay must be >= 0.6 seconds when using --api-key")
				}
			}
			return nil
		},
	}

	cmd.PersistentFlags().StringVar(&rf.APIKey, "api-key", "", "NVD API key (sets apiKey header)")
	cmd.PersistentFlags().Float64Var(&rf.Delay, "delay", 0, "Delay between requests in seconds (requires --api-key; must be >= 0.6)")
	cmd.PersistentFlags().StringVar(&rf.Proxy, "proxy", "", "HTTP proxy URL, e.g. http://127.0.0.1:8080")
	cmd.PersistentFlags().StringVar(&rf.Output, "output", "json", "Output format: json|jsonl")
	cmd.PersistentFlags().BoolVar(&rf.Pretty, "pretty", true, "Pretty-print JSON")
	cmd.PersistentFlags().BoolVar(&rf.Debug, "debug", false, "Enable debug logging to stderr")

	cmd.AddCommand(newCVECmd(&rf))
	cmd.AddCommand(newCPECmd(&rf))

	cmd.SetOut(os.Stdout)
	cmd.SetErr(os.Stderr)

	return cmd
}
