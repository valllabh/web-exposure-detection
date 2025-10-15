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
  web-exposure-detection scan example.com --domain-keywords "examplecorp,exampleinc"
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

		// Get templates flag
		templates, err := cmd.Flags().GetStringSlice("templates")
		if err != nil {
			return fmt.Errorf("failed to get templates flag: %w", err)
		}

		// Get preset flag
		presetStr, err := cmd.Flags().GetString("preset")
		if err != nil {
			return fmt.Errorf("failed to get preset flag: %w", err)
		}

		// Convert preset string to ScanPreset type
		var preset webexposure.ScanPreset
		switch presetStr {
		case "fast":
			preset = webexposure.PresetFast
		case "slow":
			preset = webexposure.PresetSlow
		default:
			preset = webexposure.PresetSlow // Default to slow
		}

		// Get verbose flag
		verbose, err := cmd.Flags().GetBool("verbose")
		if err != nil {
			return fmt.Errorf("failed to get verbose flag: %w", err)
		}

		// Get debug flag
		debug, err := cmd.Flags().GetBool("debug")
		if err != nil {
			return fmt.Errorf("failed to get debug flag: %w", err)
		}

		// Get skip-discovery flag
		skipDiscovery, err := cmd.Flags().GetBool("skip-discovery")
		if err != nil {
			return fmt.Errorf("failed to get skip-discovery flag: %w", err)
		}

		// Create scanner
		scanner, err := webexposure.New()
		if err != nil {
			return fmt.Errorf("failed to create scanner: %w", err)
		}

		// Set up CLI progress handler for command line interface
		progressHandler := cli.NewCLIProgressHandler(verbose)
		scanner.SetProgressCallback(progressHandler)

		// Run scan with CLI interface
		fmt.Printf("Starting web exposure scan for: %v\n", domains)
		if len(domainKeywords) > 0 {
			fmt.Printf("Using domain keywords: %v\n", domainKeywords)
		}
		if len(templates) > 0 {
			fmt.Printf("Using specific templates: %v\n", templates)
		}
		fmt.Printf("Using preset: %s\n", presetStr)
		if verbose {
			fmt.Printf("Verbose mode: enabled\n")
		}
		if debug {
			fmt.Printf("Debug mode: enabled\n")
		}
		if skipDiscovery {
			fmt.Printf("Skip discovery: enabled (will scan only provided domains)\n")
		}

		// Set verbose and debug flags on scanner
		scanner.SetVerbose(verbose)
		scanner.SetDebug(debug)

		err = scanner.ScanWithPreset(domains, domainKeywords, templates, force, preset, skipDiscovery)
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		fmt.Printf("Scan completed successfully\n")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	// Add domain-keywords flag
	scanCmd.Flags().StringSlice("domain-keywords", []string{},
		"Optional keywords for SSL certificate domain filtering (default: auto-extracted from domain names)")

	// Add force flag
	scanCmd.Flags().BoolP("force", "f", false,
		"Force fresh domain scan by clearing cache")

	// Add templates flag
	scanCmd.Flags().StringSliceP("templates", "t", []string{},
		"Specify specific Nuclei templates to use (comma-separated). If not specified, uses all templates with tech tag excluding ssl")

	// Add preset flag
	scanCmd.Flags().StringP("preset", "p", "slow",
		"Scan speed preset: 'slow' (default, stable) or 'fast' (aggressive, faster)")

	// Add verbose flag
	scanCmd.Flags().BoolP("verbose", "v", false,
		"Enable verbose output for detailed scan progress")

	// Add skip-discovery flag
	scanCmd.Flags().Bool("skip-discovery", false,
		"Skip domain discovery and scan only the provided domain(s)")
}
