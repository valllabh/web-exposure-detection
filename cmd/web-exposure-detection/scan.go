package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"web-exposure-detection/internal/cli"
	"web-exposure-detection/pkg/webexposure"
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan [domains...]",
	Short: "Scan domains for web exposure vulnerabilities",
	Long: `Scan one or more domains for web exposure vulnerabilities using 
domain discovery and Nuclei templates. Generates a JSON report in the current directory.

Examples:
  web-exposure-detection scan example.com
  web-exposure-detection scan example.com --keywords "staging,prod"
  web-exposure-detection scan example.com --templates "openapi,swagger-api"
  web-exposure-detection scan domain1.com domain2.com --templates "live-domain"`,
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

		// Get templates flag
		templates, err := cmd.Flags().GetStringSlice("templates")
		if err != nil {
			return fmt.Errorf("failed to get templates flag: %w", err)
		}

		// Create scanner
		scanner, err := webexposure.New()
		if err != nil {
			return fmt.Errorf("failed to create scanner: %w", err)
		}

		// Set up CLI progress handler for command line interface
		progressHandler := cli.NewCLIProgressHandler()
		scanner.SetProgressCallback(progressHandler)

		// Run scan with CLI interface
		fmt.Printf("Starting web exposure scan for: %v\n", domains)
		if len(keywords) > 0 {
			fmt.Printf("Using keywords: %v\n", keywords)
		}
		if len(templates) > 0 {
			fmt.Printf("Using specific templates: %v\n", templates)
		}

		err = scanner.ScanWithOptions(domains, keywords, templates, force)
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		fmt.Printf("Scan completed successfully\n")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	// Add keywords flag
	scanCmd.Flags().StringSliceP("keywords", "k", []string{},
		"Optional keywords for SSL certificate domain filtering (default: auto-extracted from domain names)")

	// Add force flag
	scanCmd.Flags().BoolP("force", "f", false,
		"Force fresh domain scan by clearing cache")

	// Add templates flag
	scanCmd.Flags().StringSliceP("templates", "t", []string{},
		"Specify specific Nuclei templates to use (comma-separated). If not specified, uses all templates with tech tag excluding ssl")
}
