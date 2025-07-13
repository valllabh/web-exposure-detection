package cmd

import (
	"fmt"

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
  web-exposure-detection scan domain1.com domain2.com`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Get keywords flag
		keywords, err := cmd.Flags().GetStringSlice("keywords")
		if err != nil {
			return fmt.Errorf("failed to get keywords flag: %w", err)
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
		fmt.Printf("🎯 Starting web exposure scan for: %v\n", args)
		if len(keywords) > 0 {
			fmt.Printf("📋 Using keywords: %v\n", keywords)
		}
		
		err = scanner.Scan(args, keywords)
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}
		
		fmt.Printf("✅ Scan completed successfully\n")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	
	// Add keywords flag
	scanCmd.Flags().StringSliceP("keywords", "k", []string{}, 
		"Optional keywords for SSL certificate domain filtering (default: auto-extracted from domain names)")
}