package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"web-exposure-detection/internal/cli"
	"web-exposure-detection/pkg/webexposure"
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
  web-exposure-detection discover example.com --keywords "examplecorp,exampleinc"
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

		// Get keywords flag
		keywords, err := cmd.Flags().GetStringSlice("keywords")
		if err != nil {
			return fmt.Errorf("failed to get keywords flag: %w", err)
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

		// Create scanner
		scanner, err := webexposure.New()
		if err != nil {
			return fmt.Errorf("failed to create scanner: %w", err)
		}

		// Set up CLI progress handler for command line interface (no verbose for discover command)
		progressHandler := cli.NewCLIProgressHandler(false)
		scanner.SetProgressCallback(progressHandler)

		// Set debug flag on scanner
		scanner.SetDebug(debug)

		// Run discovery with CLI interface
		fmt.Printf("Starting domain discovery for: %v\n", domains)
		if len(keywords) > 0 {
			fmt.Printf("Using keywords: %v\n", keywords)
		}
		if debug {
			fmt.Printf("Debug mode: enabled\n")
		}

		err = scanner.RunDiscoveryOnly(domains, keywords, force)
		if err != nil {
			return fmt.Errorf("discovery failed: %w", err)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(discoverCmd)

	// Add keywords flag
	discoverCmd.Flags().StringSliceP("keywords", "k", []string{},
		"Optional keywords for SSL certificate domain filtering (default: auto-extracted from domain names)")

	// Add force flag
	discoverCmd.Flags().BoolP("force", "f", false,
		"Force fresh domain discovery by clearing cache")
}
