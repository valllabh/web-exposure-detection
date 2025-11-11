package cmd

import (
	"fmt"
	"strings"

	"web-exposure-detection/internal/cli"
	"web-exposure-detection/pkg/webexposure"

	"github.com/spf13/cobra"
)

// discoverCmd represents the discover command
var discoverCmd = &cobra.Command{
	Use:   "discover [domains...]",
	Short: "Discover domains without running vulnerability scans",
	Long: `Discover subdomains and related domains using passive enumeration,
certificate transparency logs, and keyword filtering. Does not run Nuclei scans.

Results are cached in results/{domain}/domain-scan.json for use by scan and report commands.

Examples:
  web-exposure-detection discover example.com
  web-exposure-detection discover example.com --domain-keywords "examplecorp,exampleinc"
  web-exposure-detection discover example.com --force`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Parse domain arguments - handle both space-separated and comma-separated
		var domains []string
		for _, arg := range args {
			// Split by comma in case user passed comma-separated domains
			parts := strings.Split(arg, ",")
			for _, part := range parts {
				cleaned := strings.TrimSpace(part)
				if cleaned != "" {
					domains = append(domains, cleaned)
				}
			}
		}

		if len(domains) == 0 {
			return fmt.Errorf("no valid domains provided")
		}

		// Get domain-keywords flag
		domainKeywords, err := cmd.Flags().GetStringSlice("domain-keywords")
		if err != nil {
			return fmt.Errorf("failed to get domain-keywords flag: %w", err)
		}

		// Get force flag
		force, err := cmd.Flags().GetBool("force")
		if err != nil {
			return fmt.Errorf("failed to get force flag: %w", err)
		}

		// Get debug flag
		debug, err := cmd.Flags().GetBool("debug")
		if err != nil {
			return fmt.Errorf("failed to get debug flag: %w", err)
		}

		// Get silent flag
		silent, err := cmd.Flags().GetBool("silent")
		if err != nil {
			return fmt.Errorf("failed to get silent flag: %w", err)
		}

		// Create scanner
		scanner, err := webexposure.New()
		if err != nil {
			return fmt.Errorf("failed to create scanner: %w", err)
		}

		// Set debug and silent flags on scanner
		scanner.SetDebug(debug)
		scanner.SetSilent(silent)

		// Set up CLI progress handler for command line interface
		progressHandler := cli.NewCLIProgressHandler()
		scanner.SetProgressCallback(progressHandler)

		// Run discovery with CLI interface using new flow architecture
		logger.Info().Msgf("Starting domain discovery for: %v", domains)
		if len(domainKeywords) > 0 {
			logger.Info().Msgf("Using domain keywords: %v", domainKeywords)
		}
		if debug {
			logger.Info().Msg("Debug mode: enabled")
		}

		// Use new flow architecture - loop through domains
		// Note: Discovery command is just for discovery, doesn't need full scan flow
		// But for now, we'll still use the legacy RunDiscoveryOnly method which already has caching
		// since it works well for the discover-only use case
		err = scanner.RunDiscoveryOnly(domains, domainKeywords, force)
		if err != nil {
			return fmt.Errorf("discovery failed: %w", err)
		}

		logger.Info().Msg("Discovery completed successfully")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(discoverCmd)

	// Add domain-keywords flag
	discoverCmd.Flags().StringSlice("domain-keywords", []string{},
		"Optional keywords for SSL certificate domain filtering (default: auto-extracted from domain names)")

	// Add force flag
	discoverCmd.Flags().BoolP("force", "f", false,
		"Force fresh domain discovery by clearing cache")

	// Add silent flag
	discoverCmd.Flags().BoolP("silent", "s", false,
		"Enable silent mode (suppress info messages, show warnings and errors only)")
}
