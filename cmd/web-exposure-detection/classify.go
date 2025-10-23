package cmd

import (
	"encoding/json"
	"fmt"

	"web-exposure-detection/pkg/webexposure"

	"github.com/spf13/cobra"
)

// classifyCmd represents the classify command
var classifyCmd = &cobra.Command{
	Use:   "classify [domain]",
	Short: "Classify a domain's industry vertical and compliance requirements",
	Long: `Classify a domain's industry vertical using OpenRouter API.
Returns industry category, sub-industry, and applicable compliance frameworks.

Requires OPENROUTER_API_KEY environment variable or config file.

Examples:
  web-exposure-detection classify example.com
  web-exposure-detection classify shopify.com
  web-exposure-detection classify --debug healthcare.gov`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := args[0]

		// Get debug flag
		debug, err := cmd.Flags().GetBool("debug")
		if err != nil {
			return fmt.Errorf("failed to get debug flag: %w", err)
		}

		// Get force flag
		force, err := cmd.Flags().GetBool("force")
		if err != nil {
			return fmt.Errorf("failed to get force flag: %w", err)
		}

		// Configure logger
		if debug {
			webexposure.GetLogger().Debug().Msg("Debug mode enabled for industry classification")
		}

		logger.Info().Msgf("Classifying domain: %s", domain)

		// Use cache file in results directory
		cacheFile := fmt.Sprintf("results/%s/industry-classification.json", domain)

		// Classify domain with caching
		result, err := webexposure.ClassifyDomainIndustryWithCache(domain, cacheFile, force)
		if err != nil {
			return fmt.Errorf("classification failed: %w", err)
		}

		// Pretty print result
		jsonBytes, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to format result: %w", err)
		}

		fmt.Println(string(jsonBytes))

		// Summary output
		logger.Info().Msgf("✓ Industry: %s", result.Industry)
		if result.SubIndustry != "" {
			logger.Info().Msgf("✓ Sub-industry: %s", result.SubIndustry)
		}
		if len(result.Compliances) > 0 {
			logger.Info().Msgf("✓ Compliances: %v", result.Compliances)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(classifyCmd)

	// Add force flag to clear cache
	classifyCmd.Flags().BoolP("force", "f", false, "Force fresh classification by clearing cache")
}
