package cmd

import (
	"fmt"
	"strings"

	"web-exposure-detection/internal/cli"
	"web-exposure-detection/pkg/webexposure"
	_ "web-exposure-detection/pkg/webexposure/nuclei" // Import for DSL init

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var logger = webexposure.GetLogger()

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

		// Get discovery control flags from Viper (respects priority: flag > env > config > default)
		skipDiscoveryAll := viper.GetBool("discovery.skip_all")
		skipDiscoveryPassive := viper.GetBool("discovery.skip_passive")
		skipDiscoveryCertificate := viper.GetBool("discovery.skip_certificate")

		// Get PDF generator from config/flag
		pdfGenerator := viper.GetString("pdf_generator")

		// Create scanner with configured PDF generator
		scanner, err := webexposure.NewWithPDFGenerator(pdfGenerator)
		if err != nil {
			return fmt.Errorf("failed to create scanner: %w", err)
		}

		// Set debug and silent flags on scanner
		scanner.SetDebug(debug)
		scanner.SetSilent(silent)

		// Set up CLI progress handler for command line interface
		progressHandler := cli.NewCLIProgressHandler()
		scanner.SetProgressCallback(progressHandler)

		// Run scan with CLI interface
		logger.Info().Msgf("Starting web exposure scan for: %v", domains)
		if len(domainKeywords) > 0 {
			logger.Info().Msgf("Using domain keywords: %v", domainKeywords)
		}
		if len(templates) > 0 {
			logger.Info().Msgf("Using specific templates: %v", templates)
		}
		logger.Info().Msgf("Using preset: %s", presetStr)
		if debug {
			logger.Info().Msg("Debug mode: enabled")
		}
		if silent {
			logger.Info().Msg("Silent mode: enabled")
		}

		// Log discovery configuration
		if skipDiscoveryAll {
			logger.Info().Msg("Discovery: Skipping all (scanning only provided domains)")
		} else if skipDiscoveryPassive && skipDiscoveryCertificate {
			logger.Info().Msg("Discovery: Skipping passive and certificate (scanning only provided domains)")
		} else if skipDiscoveryPassive {
			logger.Info().Msg("Discovery: Passive disabled, certificate enabled")
		} else if skipDiscoveryCertificate {
			logger.Info().Msg("Discovery: Passive enabled, certificate disabled")
		} else {
			logger.Info().Msg("Discovery: Full discovery enabled (passive + certificate)")
		}

		err = scanner.ScanWithPreset(domains, domainKeywords, templates, force, preset, skipDiscoveryAll, skipDiscoveryPassive, skipDiscoveryCertificate)
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		logger.Info().Msg("Scan completed successfully")
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
		"Specify specific Nuclei templates to use (comma-separated). If not specified, uses all templates")

	// Add preset flag
	scanCmd.Flags().StringP("preset", "p", "slow",
		"Scan speed preset: 'slow' (default, stable) or 'fast' (aggressive, faster)")

	// Add silent flag
	scanCmd.Flags().BoolP("silent", "s", false,
		"Enable silent mode (suppress info messages, show warnings and errors only)")

	// Add discovery control flags
	scanCmd.Flags().Bool("skip-discovery-all", false,
		"Skip all domain discovery (scan only provided domains)")
	scanCmd.Flags().Bool("skip-discovery-passive", false,
		"Skip passive subdomain enumeration (subfinder)")
	scanCmd.Flags().Bool("skip-discovery-certificate", false,
		"Skip certificate domain extraction")

	// Bind discovery flags to viper
	viper.BindPFlag("discovery.skip_all", scanCmd.Flags().Lookup("skip-discovery-all"))
	viper.BindPFlag("discovery.skip_passive", scanCmd.Flags().Lookup("skip-discovery-passive"))
	viper.BindPFlag("discovery.skip_certificate", scanCmd.Flags().Lookup("skip-discovery-certificate"))

	// Bind scan flags to viper
	viper.BindPFlag("scan.preset", scanCmd.Flags().Lookup("preset"))
	viper.BindPFlag("scan.force", scanCmd.Flags().Lookup("force"))
}
