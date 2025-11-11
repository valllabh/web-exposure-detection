package scanner

import (
	"fmt"
	"os"
	"path/filepath"

	"web-exposure-detection/pkg/webexposure/common"
	"web-exposure-detection/pkg/webexposure/logger"
	"web-exposure-detection/pkg/webexposure/truinsights"
)

// runTRUInsightsSubflow executes TRU Insights generation subflow with caching
// Cache: results/{domain}/tru-insights-TAS.json
// Dependencies: Discovery, Industry Classification, Nuclei Scan (Level 2 subflow)
// Note: Discovery is optional - if skipDiscoveryAll=true and no cache exists, will skip TRU insights
func (s *scanner) runTRUInsightsSubflow(domain string, force bool, keywords []string, templates []string, skipPassive bool, skipCertificate bool, skipDiscoveryAll bool, preset common.ScanPreset) (*truinsights.TRUInsightsResult, error) {
	log := logger.GetLogger()
	resultsDir := filepath.Join("results", domain)
	cacheFile := filepath.Join(resultsDir, "tru-insights-TAS.json")
	discoveryFile := filepath.Join(resultsDir, "domain-discovery-result.json")

	// Create results directory
	if err := os.MkdirAll(resultsDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create results directory: %w", err)
	}

	// Step 1: Check cache (unless force=true)
	if !force {
		if _, err := os.Stat(cacheFile); err == nil {
			log.Info().Msg("Using cached TRU Insights")
			// truinsights package will handle loading from cache
			// We just return nil to indicate cache exists
			return nil, nil
		}
		log.Debug().Msg("TRU Insights cache miss, executing subflow")
	} else {
		log.Info().Msg("Force flag set, regenerating TRU Insights")
		// Remove cache files if they exist
		os.Remove(cacheFile)
		os.Remove(filepath.Join(resultsDir, "tru-insights-metadata.json"))
		if s.debug {
			os.Remove(filepath.Join(resultsDir, "tru-insights-prompt.md"))
		}
	}

	// Step 2: Call dependency subflows (with same force flag)
	// These subflows handle their own caching, so if force=false they'll use cache

	// 2a. Discovery (conditional based on skip flags)
	// If discovery is skipped, check if cached discovery exists
	var err error
	if skipDiscoveryAll {
		if _, err := os.Stat(discoveryFile); err != nil {
			log.Warning().Msg("Discovery skipped and no cached discovery found - skipping TRU insights generation")
			return nil, fmt.Errorf("TRU insights requires discovery results but discovery was skipped and no cache exists")
		}
		log.Debug().Msg("Discovery skipped but cached results exist, using cache for TRU insights")
	} else {
		// Run discovery normally
		_, err = s.runDiscoverySubflow(domain, force, keywords, skipPassive, skipCertificate)
		if err != nil {
			return nil, fmt.Errorf("discovery subflow dependency failed: %w", err)
		}
	}

	// 2b. Industry Classification (non-blocking)
	_, err = s.runIndustryClassificationSubflow(domain, force)
	if err != nil {
		log.Warning().Msgf("Industry classification subflow failed: %v", err)
		// Non-blocking, continue without industry info
	}

	// 2c. Nuclei Scan
	_, err = s.runNucleiScanSubflow(domain, force, keywords, templates, skipPassive, skipCertificate, preset)
	if err != nil {
		return nil, fmt.Errorf("nuclei scan subflow dependency failed: %w", err)
	}

	// Step 3: Execute TRU Insights generation
	log.Info().Msg("Generating TRU Insights")

	generator, err := truinsights.NewGenerator()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize TRU insights generator: %w", err)
	}

	result, err := generator.GenerateWithDebug(domain, false, s.debug)
	if err != nil {
		return nil, fmt.Errorf("TRU insights generation failed: %w", err)
	}

	log.Info().Msg("TRU Insights generated successfully")

	// Step 4: Cache is automatically saved by truinsights package
	log.Debug().Msgf("TRU Insights saved to %s", cacheFile)

	// Step 5: Return result
	return result, nil
}
