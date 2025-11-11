package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"

	"web-exposure-detection/pkg/webexposure/common"
	"web-exposure-detection/pkg/webexposure/logger"
	"web-exposure-detection/pkg/webexposure/nuclei"
)

// runNucleiScanSubflow executes Nuclei scan subflow with caching
// Cache: results/{domain}/nuclei-results/results.json
// Dependencies: Discovery Subflow (Level 1 subflow)
func (s *scanner) runNucleiScanSubflow(domain string, force bool, keywords []string, templates []string, skipPassive bool, skipCertificate bool, preset common.ScanPreset) ([]*output.ResultEvent, error) {
	log := logger.GetLogger()
	resultsDir := filepath.Join("results", domain)
	nucleiResultsDir := filepath.Join(resultsDir, "nuclei-results")
	cacheFile := filepath.Join(nucleiResultsDir, "results.json")

	// Create nuclei results directory
	if err := os.MkdirAll(nucleiResultsDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create nuclei results directory: %w", err)
	}

	// Step 1: Check cache (unless force=true)
	if !force {
		if _, err := os.Stat(cacheFile); err == nil {
			log.Info().Msg("Using cached Nuclei scan results")
			// Cache exists, return empty results (next subflows will load from cache file directly)
			// We don't need to return actual results since Report JSON subflow loads from file
			return []*output.ResultEvent{}, nil
		}
		log.Debug().Msg("Nuclei cache miss, executing subflow")
	} else {
		log.Info().Msg("Force flag set, regenerating Nuclei scan")
		// Remove cache files if they exist
		os.RemoveAll(nucleiResultsDir)
		os.MkdirAll(nucleiResultsDir, 0750)
	}

	// Step 2: Call dependency subflow - Discovery (with same force flag)
	discoveredDomains, err := s.runDiscoverySubflow(domain, force, keywords, skipPassive, skipCertificate)
	if err != nil {
		return nil, fmt.Errorf("discovery subflow dependency failed: %w", err)
	}

	if len(discoveredDomains) == 0 {
		return nil, fmt.Errorf("no live domains found to scan")
	}

	// Extract URLs from discovered domains
	var discoveredURLs []string
	for domainURL := range discoveredDomains {
		discoveredURLs = append(discoveredURLs, domainURL)
	}

	// Step 3: Execute Nuclei scan
	log.Info().Msgf("Running Nuclei scan on %d targets", len(discoveredURLs))

	// Extract embedded templates to temporary directory
	tempTemplatesDir, err := s.extractEmbeddedTemplates()
	if err != nil {
		return nil, fmt.Errorf("failed to extract templates: %w", err)
	}

	// Prepare Nuclei options
	nucleiOptions := &nuclei.NucleiOptions{
		TemplatesPath:       tempTemplatesDir,
		SpecificTemplates:   templates,
		IncludeTags:         []string{},
		ExcludeTags:         []string{},
		Headless:            true,
		OmitTemplate:        false,
		OmitResponse:        false,
		FollowHostRedirects: true,
		ShowMatchLine:       true,
		ResultsWriter:       filepath.Join(nucleiResultsDir, "results.jsonl"),
		Debug:               s.debug,
		Silent:              s.silent,
	}

	// Apply preset configuration
	applyPresetToNucleiOptions(nucleiOptions, preset)

	// Run Nuclei scan
	results, err := s.RunNucleiScan(discoveredURLs, nucleiOptions)
	if err != nil {
		return nil, fmt.Errorf("nuclei scan execution failed: %w", err)
	}

	// Wait for nuclei cleanup
	time.Sleep(2 * time.Second)
	log.Debug().Msg("Nuclei cleanup delay completed")

	// Step 4: Save to cache (convert JSONL to JSON)
	jsonlFile := filepath.Join(nucleiResultsDir, "results.jsonl")
	if err := s.convertJSONLToJSON(jsonlFile, cacheFile); err != nil {
		log.Warning().Msgf("Failed to save Nuclei cache: %v", err)
	} else {
		log.Debug().Msgf("Saved Nuclei cache to %s", cacheFile)
		log.Info().Msg("JSONL results converted to JSON format")
	}

	log.Info().Msgf("Nuclei scan complete: %d results", len(results))

	// Step 5: Return result
	return results, nil
}
