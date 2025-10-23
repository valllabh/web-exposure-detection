package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/valllabh/domain-scan/pkg/domainscan"
	"web-exposure-detection/pkg/webexposure/logger"
)

// Domain Discovery Functions
// This file contains all domain discovery-related functionality following Single Responsibility Principle

// DiscoverDomains discovers subdomains using domain-scan SDK
func (s *scanner) DiscoverDomains(domains []string, keywords []string, skipPassive bool, skipCertificate bool) ([]string, error) {
	log := logger.GetLogger()
	log.Debug().Msgf("DiscoverDomains called: domains=%v, keywords=%v, skipPassive=%v, skipCertificate=%v", domains, keywords, skipPassive, skipCertificate)

	// Notify progress callback if set
	if s.progress != nil {
		s.progress.OnDomainDiscoveryStart(domains, keywords)
	}

	var allDiscovered []string

	// Convert original domains to HTTPS URLs (default assumption)
	for _, domain := range domains {
		// Try HTTPS first for original domains
		httpsURL := "https://" + domain
		allDiscovered = append(allDiscovered, httpsURL)
	}

	// Use domain-scan SDK with controlled comprehensive discovery
	config := domainscan.DefaultConfig()
	// Configure for controlled comprehensive mode with timeout safety
	config.Discovery.Timeout = 20 * time.Minute
	config.Keywords = keywords

	// Apply discovery skip flags
	config.Discovery.EnablePassive = !skipPassive
	config.Discovery.EnableCertificate = !skipCertificate

	log.Debug().Msgf("Discovery config: passive=%v, certificate=%v", config.Discovery.EnablePassive, config.Discovery.EnableCertificate)

	domainScanner := domainscan.New(config)
	log.Debug().Msgf("Initialized domain-scan SDK with timeout=%v", config.Discovery.Timeout)

	// Set up real progress tracking from domain-scan SDK
	if s.progress != nil {
		domainScanner.SetProgressCallback(&domainScanProgressAdapter{
			webExposureProgress: s.progress,
		})
	}

	// Create context with timeout for safety - increased for complete sister domain discovery
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// Create controlled comprehensive scan request
	scanReq := &domainscan.ScanRequest{
		Domains:  domains,
		Keywords: keywords,
		Timeout:  10 * time.Minute,
	}

	// Run comprehensive domain discovery with real progress tracking
	result, err := domainScanner.ScanWithOptions(ctx, scanReq)

	if err != nil {
		// Return original domains as HTTPS URLs if scan fails
		log.Warning().Msgf("Domain scan failed, using original domains only: %v", err)
		if s.progress != nil {
			s.progress.OnDomainDiscoveryComplete(len(allDiscovered), len(domains), 0)
		}
		return allDiscovered, nil
	}

	// Store the full result for metrics calculation
	s.lastDiscoveryResult = result

	log.Debug().Msgf("Domain scan completed: found %d live domains", len(result.Domains))

	// Track seen clean domains to avoid duplicates
	seenDomains := make(map[string]bool)
	for _, url := range allDiscovered {
		clean := extractDomainFromURL(url)
		seenDomains[clean] = true
	}

	// Extract all discovered domains from the result with protocol information
	for domainURL, entry := range result.Domains {
		// Include domains that are HTTP-accessible (Status > 0) OR explicitly marked as Reachable
		if entry.Status > 0 || entry.Reachable {
			// Extract clean domain for deduplication check
			cleanDomain := extractDomainFromURL(domainURL)
			if cleanDomain != "" && !seenDomains[cleanDomain] {
				// Use the full URL with protocol from domain-scan
				allDiscovered = append(allDiscovered, domainURL)
				seenDomains[cleanDomain] = true
			}
		}
	}

	// Notify progress callback of completion
	if s.progress != nil {
		s.progress.OnDomainDiscoveryComplete(len(allDiscovered), len(domains), len(allDiscovered)-len(domains))
	}

	log.Info().Msgf("Domain discovery completed: %d total domains (%d original, %d discovered)",
		len(allDiscovered), len(domains), len(allDiscovered)-len(domains))

	return allDiscovered, nil
}

// DiscoverDomainsWithProtocol performs domain discovery preserving protocol information
func (s *scanner) DiscoverDomainsWithProtocol(domains []string, keywords []string, skipPassive bool, skipCertificate bool) (map[string]*domainscan.DomainEntry, error) {
	log := logger.GetLogger()
	log.Debug().Msgf("DiscoverDomainsWithProtocol called: domains=%v, keywords=%v, skipPassive=%v, skipCertificate=%v", domains, keywords, skipPassive, skipCertificate)

	// Notify progress callback if set
	if s.progress != nil {
		s.progress.OnDomainDiscoveryStart(domains, keywords)
	}

	// Use domain-scan SDK with controlled comprehensive discovery
	config := domainscan.DefaultConfig()
	config.Discovery.Timeout = 20 * time.Minute
	config.Keywords = keywords

	// Apply discovery skip flags
	config.Discovery.EnablePassive = !skipPassive
	config.Discovery.EnableCertificate = !skipCertificate

	log.Debug().Msgf("Discovery config: passive=%v, certificate=%v", config.Discovery.EnablePassive, config.Discovery.EnableCertificate)

	domainScanner := domainscan.New(config)

	// Set up real progress tracking from domain-scan SDK
	if s.progress != nil {
		domainScanner.SetProgressCallback(&domainScanProgressAdapter{
			webExposureProgress: s.progress,
		})
	}

	// Create context with timeout for safety - increased for complete sister domain discovery
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// Create controlled comprehensive scan request
	scanReq := &domainscan.ScanRequest{
		Domains:  domains,
		Keywords: keywords,
		Timeout:  10 * time.Minute,
	}

	// Run comprehensive domain discovery with real progress tracking
	result, err := domainScanner.ScanWithOptions(ctx, scanReq)

	if err != nil {
		// Return original domains with default HTTPS assumption as DomainEntry objects
		log.Warning().Msgf("Domain scan failed, using HTTPS fallback for %d domains: %v", len(domains), err)
		fallbackDomains := make(map[string]*domainscan.DomainEntry)
		for _, domain := range domains {
			httpsURL := "https://" + domain
			fallbackDomains[httpsURL] = &domainscan.DomainEntry{
				Reachable: true, // Assume reachable for fallback
			}
		}

		if s.progress != nil {
			s.progress.OnDomainDiscoveryComplete(len(fallbackDomains), len(domains), 0)
		}
		return fallbackDomains, nil
	}

	// Store the full result for metrics calculation
	s.lastDiscoveryResult = result

	log.Debug().Msgf("Domain scan completed: found %d live domains with protocol info", len(result.Domains))

	// Filter only live/accessible domains and return the DomainEntry map directly
	liveDomains := make(map[string]*domainscan.DomainEntry)
	for domainURL, entry := range result.Domains {
		// Include domains that are HTTP-accessible (Status > 0) OR explicitly marked as Reachable
		if entry.Status > 0 || entry.Reachable {
			liveDomains[domainURL] = entry
		}
	}

	// Notify progress callback of completion
	if s.progress != nil {
		s.progress.OnDomainDiscoveryComplete(len(liveDomains), len(domains), len(liveDomains)-len(domains))
	}

	log.Info().Msgf("Domain discovery with protocol completed: %d live domains", len(liveDomains))

	return liveDomains, nil
}

// discoverDomainsWithProtocolCached handles domain discovery with caching support (protocol aware)
func (s *scanner) discoverDomainsWithProtocolCached(domains []string, keywords []string, skipPassive bool, skipCertificate bool, resultsDir string, force bool) (map[string]*domainscan.DomainEntry, error) {
	log := logger.GetLogger()
	discoveryResultFile := filepath.Join(resultsDir, "domain-discovery-result.json")

	// If force flag is set, remove cache file
	if force {
		log.Info().Msg("Force flag enabled: clearing domain discovery cache")
		if err := os.Remove(discoveryResultFile); err != nil && !os.IsNotExist(err) {
			log.Warning().Msgf("Failed to clear cache file: %v", err)
		}
	}

	// Try to load from cache first (if not force)
	if !force {
		if discoveryResult, err := s.loadDiscoveryResult(discoveryResultFile); err == nil {
			s.lastDiscoveryResult = discoveryResult

			// Extract live domain entries from the cached result
			liveDomains := make(map[string]*domainscan.DomainEntry)
			for domainURL, entry := range discoveryResult.Domains {
				if entry.Status > 0 || entry.Reachable {
					liveDomains[domainURL] = entry
				}
			}

			log.Info().Msgf("Using cached discovery results: %d domains (skipping fresh discovery)", len(liveDomains))

			// Skip progress callbacks when using cache - they are misleading
			return liveDomains, nil
		} else {
			log.Debug().Msgf("Cache miss: %v", err)
		}
	}

	// Perform fresh domain discovery
	log.Info().Msg("Running fresh domain discovery")
	discoveredDomains, err := s.DiscoverDomainsWithProtocol(domains, keywords, skipPassive, skipCertificate)
	if err != nil {
		return nil, err
	}

	// Save full discovery result (includes all domain details and metrics)
	if s.lastDiscoveryResult != nil {
		if err := s.saveDiscoveryResult(s.lastDiscoveryResult, discoveryResultFile); err != nil {
			log.Warning().Msgf("Failed to save discovery result: %v", err)
		} else {
			log.Debug().Msgf("Saved discovery result to %s", discoveryResultFile)
		}
	}

	return discoveredDomains, nil
}

// discoverDomainsWithCache handles domain discovery with caching support
func (s *scanner) discoverDomainsWithCache(domains []string, keywords []string, resultsDir string, force bool) ([]string, error) {
	log := logger.GetLogger()
	discoveryResultFile := filepath.Join(resultsDir, "domain-discovery-result.json")

	// If force flag is set, remove cache file
	if force {
		log.Debug().Msgf("Clearing domain discovery cache: %s", discoveryResultFile)
		if err := os.Remove(discoveryResultFile); err != nil && !os.IsNotExist(err) {
			log.Error().Msgf("Failed to clear cache file: %v", err)
			return nil, fmt.Errorf("failed to clear cache: %w", err)
		}
	}

	// Try to load from cache first
	if !force {
		if discoveryResult, err := s.loadDiscoveryResult(discoveryResultFile); err == nil {
			s.lastDiscoveryResult = discoveryResult
			log.Debug().Msgf("Cache hit: loaded discovery result with %d domains", len(discoveryResult.Domains))

			// Extract live domain URLs from the result
			cachedDomains := s.extractLiveURLsFromResult(discoveryResult)
			log.Debug().Msgf("Extracted %d live URLs from cache", len(cachedDomains))

			if s.progress != nil {
				s.progress.OnDomainDiscoveryStart(domains, keywords)
				s.progress.OnDomainDiscoveryComplete(len(cachedDomains), len(domains), len(cachedDomains)-len(domains))
			}
			return cachedDomains, nil
		} else {
			log.Debug().Msgf("Cache miss or invalid cache: %v", err)
		}
	}

	// Perform fresh domain discovery (no skip flags in cached path, use defaults)
	discoveredDomains, err := s.DiscoverDomains(domains, keywords, false, false)
	if err != nil {
		return nil, err
	}

	// Save full discovery result (includes all domain details and metrics)
	if s.lastDiscoveryResult != nil {
		if err := s.saveDiscoveryResult(s.lastDiscoveryResult, discoveryResultFile); err != nil {
			log.Warning().Msgf("Failed to save discovery result: %v", err)
		} else {
			log.Debug().Msgf("Saved discovery result to %s", discoveryResultFile)
		}
	}

	return discoveredDomains, nil
}

// extractLiveURLsFromResult extracts live/accessible domain URLs from AssetDiscoveryResult
func (s *scanner) extractLiveURLsFromResult(result *domainscan.AssetDiscoveryResult) []string {
	var urls []string
	for domainURL, entry := range result.Domains {
		// Include domains that are HTTP-accessible (Status > 0) OR explicitly marked as Reachable
		if entry.Status > 0 || entry.Reachable {
			urls = append(urls, domainURL)
		}
	}
	return urls
}

// extractDomainFromURL extracts clean domain from URL
// e.g., "https://example.com:443" -> "example.com"
func extractDomainFromURL(url string) string {
	domain := url
	if strings.HasPrefix(domain, "http://") {
		domain = strings.TrimPrefix(domain, "http://")
	} else if strings.HasPrefix(domain, "https://") {
		domain = strings.TrimPrefix(domain, "https://")
	}
	// Remove port
	if idx := strings.Index(domain, ":"); idx > 0 {
		domain = domain[:idx]
	}
	// Remove path
	if idx := strings.Index(domain, "/"); idx > 0 {
		domain = domain[:idx]
	}
	return domain
}

// createDirectDomainList creates domain list with provided domains (skips discovery)
func (s *scanner) createDirectDomainList(domains []string, resultsDir string) ([]string, error) {
	log := logger.GetLogger()
	log.Debug().Msgf("Creating direct domain list for %d domains (skipping discovery)", len(domains))

	discoveryResultFile := filepath.Join(resultsDir, "domain-discovery-result.json")

	// Convert domains to HTTPS URLs and create DomainEntry objects
	var urls []string
	domainEntries := make(map[string]*domainscan.DomainEntry)

	for _, domain := range domains {
		httpsURL := "https://" + domain
		urls = append(urls, httpsURL)

		// Create a basic DomainEntry (assumed reachable, no passive scan)
		domainEntries[httpsURL] = &domainscan.DomainEntry{
			Domain:    httpsURL,
			Status:    200, // Assume reachable
			Reachable: true,
			Sources:   nil, // No passive sources for direct input domains
		}
	}

	// Create minimal AssetDiscoveryResult
	result := &domainscan.AssetDiscoveryResult{
		Domains: domainEntries,
	}

	s.lastDiscoveryResult = result

	// Save discovery result
	if err := s.saveDiscoveryResult(result, discoveryResultFile); err != nil {
		log.Error().Msgf("Failed to save discovery result to %s: %v", discoveryResultFile, err)
		return nil, fmt.Errorf("failed to save discovery result: %w", err)
	}

	// Notify progress callback if set
	if s.progress != nil {
		s.progress.OnDomainDiscoveryStart(domains, []string{})
		s.progress.OnDomainDiscoveryComplete(len(urls), len(domains), 0)
	}

	log.Info().Msg("Skipped discovery - using provided domains only")
	log.Info().Msgf("Total domains: %d", len(urls))
	log.Info().Msgf("Results saved to: %s", discoveryResultFile)

	return urls, nil
}

// saveDiscoveryResult saves the full AssetDiscoveryResult to file for metrics calculation
func (s *scanner) saveDiscoveryResult(result *domainscan.AssetDiscoveryResult, filePath string) error {
	log := logger.GetLogger()
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Error().Msgf("Failed to marshal discovery result: %v", err)
		return err
	}

	if err := os.WriteFile(filePath, data, 0600); err != nil {
		log.Error().Msgf("Failed to write discovery result file %s: %v", filePath, err)
		return err
	}

	return nil
}

// loadDiscoveryResult loads the full AssetDiscoveryResult from file
func (s *scanner) loadDiscoveryResult(filePath string) (*domainscan.AssetDiscoveryResult, error) {
	log := logger.GetLogger()
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Debug().Msgf("Failed to read discovery result file %s: %v", filePath, err)
		return nil, err
	}

	var result domainscan.AssetDiscoveryResult
	if err := json.Unmarshal(data, &result); err != nil {
		log.Warning().Msgf("Failed to unmarshal discovery result file %s: %v", filePath, err)
		return nil, err
	}

	return &result, nil
}
