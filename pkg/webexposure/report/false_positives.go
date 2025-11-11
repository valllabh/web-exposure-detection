package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"web-exposure-detection/pkg/webexposure/common"
	"web-exposure-detection/pkg/webexposure/findings"
	"web-exposure-detection/pkg/webexposure/logger"
	"web-exposure-detection/pkg/webexposure/nuclei"
)

// GenerateFalsePositivesTemplate creates a false-positives.json template with all findings
// This is called after nuclei scan to create a template that users can edit
func GenerateFalsePositivesTemplate(domain string, grouped *nuclei.GroupedResults) error {
	log := logger.GetLogger()

	// Create results directory if it doesn't exist
	resultsDir := filepath.Join("results", domain)
	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		return fmt.Errorf("failed to create results directory: %w", err)
	}

	fpFile := filepath.Join(resultsDir, "false-positives.json")

	// Check if file already exists
	if _, err := os.Stat(fpFile); err == nil {
		log.Debug().Msgf("False positives file already exists for %s, skipping generation", domain)
		return nil
	}

	log.Debug().Msgf("Generating false positives template for %s", domain)

	// Collect all unique findings from all domains (includes both findings and technologies)
	findingsSet := make(map[string]bool)

	for _, domainResults := range grouped.Domains {
		for _, templateResult := range domainResults {
			if templateResult.Findings != nil {
				for slug := range templateResult.Findings {
					findingsSet[slug] = true
				}
			}
		}
	}

	log.Debug().Msgf("Collected %d unique findings for false positive template", len(findingsSet))

	// Convert to sorted list of entries
	entries := make([]*common.FalsePositiveEntry, 0, len(findingsSet))
	for slug := range findingsSet {
		item := findings.NewFindingItem(slug)
		entries = append(entries, &common.FalsePositiveEntry{
			Slug:        slug,
			DisplayName: item.GetDisplayName(),
			MarkedFP:    false,
			Reason:      "",
		})
	}

	// Sort by display name for readability
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].DisplayName < entries[j].DisplayName
	})

	// Create false positive list
	fpList := &common.FalsePositiveList{
		Domain:         domain,
		Updated:        time.Now().UTC().Format(time.RFC3339),
		FalsePositives: entries,
	}

	// Write to file
	data, err := json.MarshalIndent(fpList, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal false positives: %w", err)
	}

	if err := os.WriteFile(fpFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write false positives file: %w", err)
	}

	log.Info().Msgf("Created false positives template: %s (%d findings)", fpFile, len(entries))
	return nil
}

// LoadFalsePositives loads the false-positives.json file for a domain
// Returns a set of slugs that are marked as false positives
func LoadFalsePositives(domain string) map[string]bool {
	log := logger.GetLogger()
	fpFile := filepath.Join("results", domain, "false-positives.json")

	// Check if file exists
	if _, err := os.Stat(fpFile); os.IsNotExist(err) {
		log.Debug().Msgf("No false positives file found for %s", domain)
		return make(map[string]bool)
	}

	// Read file
	data, err := os.ReadFile(fpFile)
	if err != nil {
		log.Warning().Msgf("Failed to read false positives file for %s: %v", domain, err)
		return make(map[string]bool)
	}

	// Parse JSON
	var fpList common.FalsePositiveList
	if err := json.Unmarshal(data, &fpList); err != nil {
		log.Warning().Msgf("Failed to parse false positives file for %s: %v", domain, err)
		return make(map[string]bool)
	}

	// Build set of false positive slugs
	fpSet := make(map[string]bool)
	fpCount := 0
	for _, entry := range fpList.FalsePositives {
		if entry.MarkedFP {
			fpSet[entry.Slug] = true
			fpCount++
		}
	}

	if fpCount > 0 {
		log.Info().Msgf("Loaded %d false positives for %s", fpCount, domain)
	} else {
		log.Debug().Msgf("No false positives marked for %s", domain)
	}

	return fpSet
}
