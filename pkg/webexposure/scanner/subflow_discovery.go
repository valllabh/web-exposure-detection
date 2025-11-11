package scanner

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/valllabh/domain-scan/pkg/domainscan"

	"web-exposure-detection/pkg/webexposure/logger"
)

// runDiscoverySubflow executes domain discovery subflow with caching
// Cache: results/{domain}/domain-discovery-result.json
// Dependencies: None (Level 0 subflow)
func (s *scanner) runDiscoverySubflow(domain string, force bool, keywords []string, skipPassive bool, skipCertificate bool) (map[string]*domainscan.DomainEntry, error) {
	log := logger.GetLogger()
	resultsDir := filepath.Join("results", domain)
	cacheFile := filepath.Join(resultsDir, "domain-discovery-result.json")

	// Create results directory
	if err := os.MkdirAll(resultsDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create results directory: %w", err)
	}

	// Step 1: Check cache (unless force=true)
	if !force {
		if discoveryResult, err := s.loadDiscoveryResult(cacheFile); err == nil {
			s.lastDiscoveryResult = discoveryResult

			// Extract live domain entries from the cached result
			liveDomains := make(map[string]*domainscan.DomainEntry)
			for domainURL, entry := range discoveryResult.Domains {
				if entry.Status > 0 || entry.Reachable {
					liveDomains[domainURL] = entry
				}
			}

			log.Info().Msgf("Using cached discovery results: %d domains", len(liveDomains))
			return liveDomains, nil
		}
		log.Debug().Msg("Discovery cache miss, executing subflow")
	} else {
		log.Info().Msg("Force flag set, regenerating discovery")
		// Remove cache file if exists
		if err := os.Remove(cacheFile); err != nil && !os.IsNotExist(err) {
			log.Warning().Msgf("Failed to remove discovery cache: %v", err)
		}
	}

	// Step 2: No dependencies (Level 0 subflow)

	// Step 3: Execute discovery
	log.Info().Msg("Running fresh domain discovery")
	discoveredDomains, err := s.DiscoverDomainsWithProtocol([]string{domain}, keywords, skipPassive, skipCertificate)
	if err != nil {
		return nil, fmt.Errorf("domain discovery failed: %w", err)
	}

	// Step 4: Save to cache
	if s.lastDiscoveryResult != nil {
		if err := s.saveDiscoveryResult(s.lastDiscoveryResult, cacheFile); err != nil {
			log.Warning().Msgf("Failed to save discovery cache: %v", err)
		} else {
			log.Debug().Msgf("Saved discovery cache to %s", cacheFile)
		}
	}

	// Step 5: Return result
	return discoveredDomains, nil
}
