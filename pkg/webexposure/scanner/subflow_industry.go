package scanner

import (
	"fmt"
	"os"
	"path/filepath"

	"web-exposure-detection/pkg/webexposure/industry"
	"web-exposure-detection/pkg/webexposure/logger"
)

// runIndustryClassificationSubflow executes industry classification subflow with caching
// Cache: results/{domain}/industry-classification.json
// Dependencies: None (Level 0 subflow)
func (s *scanner) runIndustryClassificationSubflow(domain string, force bool) (*industry.IndustryClassification, error) {
	log := logger.GetLogger()
	resultsDir := filepath.Join("results", domain)
	cacheFile := filepath.Join(resultsDir, "industry-classification.json")

	// Create results directory
	if err := os.MkdirAll(resultsDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create results directory: %w", err)
	}

	// Step 1: Use industry package's built-in caching
	// Industry package already handles cache checks and force flag
	classification, err := industry.ClassifyDomainIndustryWithCache(domain, cacheFile, force)
	if err != nil {
		return nil, fmt.Errorf("industry classification failed: %w", err)
	}

	// Store in scanner state for other subflows to access
	s.industryClassification = classification

	log.Info().Msgf("Industry: %s, Sub-industry: %s", classification.Industry, classification.SubIndustry)

	// Step 5: Return result
	return classification, nil
}
