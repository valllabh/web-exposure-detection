package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"web-exposure-detection/internal/cli"
	"web-exposure-detection/pkg/webexposure"
)

// reportCmd represents the report command
var reportCmd = &cobra.Command{
	Use:   "report [domains...]",
	Short: "Regenerate report from existing scan results",
	Long: `Regenerate JSON report from existing Nuclei scan results without running
new domain discovery or vulnerability scans. Uses cached results from previous scan.

Examples:
  web-exposure-detection report example.com
  web-exposure-detection report domain1.com domain2.com`,
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

		// Create scanner
		scanner, err := webexposure.New()
		if err != nil {
			return fmt.Errorf("failed to create scanner: %w", err)
		}

		// Set up CLI progress handler for command line interface
		progressHandler := cli.NewCLIProgressHandler()
		scanner.SetProgressCallback(progressHandler)

		// Generate report from existing results
		fmt.Printf("Regenerating report for: %v\n", domains)

		err = scanner.GenerateReportFromExistingResults(domains)
		if err != nil {
			return fmt.Errorf("report generation failed: %w", err)
		}

		fmt.Printf("Report generated successfully\n")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(reportCmd)
}