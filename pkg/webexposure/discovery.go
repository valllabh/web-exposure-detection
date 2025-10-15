package webexposure

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/valllabh/domain-scan/pkg/domainscan"
)

// Domain Discovery Functions
// This file contains all domain discovery-related functionality following Single Responsibility Principle

// DiscoverDomains discovers subdomains using domain-scan SDK
func (s *scanner) DiscoverDomains(domains []string, keywords []string) ([]string, error) {
	logger := GetLogger()
	logger.Debug().Msgf("DiscoverDomains called: domains=%v, keywords=%v", domains, keywords)

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

	domainScanner := domainscan.New(config)
	logger.Debug().Msgf("Initialized domain-scan SDK with timeout=%v", config.Discovery.Timeout)

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
		logger.Warning().Msgf("Domain scan failed, using original domains only: %v", err)
		if s.progress != nil {
			s.progress.OnDomainDiscoveryComplete(len(allDiscovered), len(domains), 0)
		}
		return allDiscovered, nil
	}

	logger.Debug().Msgf("Domain scan completed: found %d live domains", len(result.Domains))

	// Track seen clean domains to avoid duplicates
	seenDomains := make(map[string]bool)
	for _, url := range allDiscovered {
		clean := extractDomainFromURL(url)
		seenDomains[clean] = true
	}

	// Extract all discovered domains from the result with protocol information
	for domainURL, entry := range result.Domains {
		if entry.IsLive {
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

	logger.Info().Msgf("Domain discovery completed: %d total domains (%d original, %d discovered)",
		len(allDiscovered), len(domains), len(allDiscovered)-len(domains))

	return allDiscovered, nil
}

// DiscoverDomainsWithProtocol performs domain discovery preserving protocol information
func (s *scanner) DiscoverDomainsWithProtocol(domains []string, keywords []string) (map[string]*domainscan.DomainEntry, error) {
	logger := GetLogger()
	logger.Debug().Msgf("DiscoverDomainsWithProtocol called: domains=%v, keywords=%v", domains, keywords)

	// Notify progress callback if set
	if s.progress != nil {
		s.progress.OnDomainDiscoveryStart(domains, keywords)
	}

	// Use domain-scan SDK with controlled comprehensive discovery
	config := domainscan.DefaultConfig()
	config.Discovery.Timeout = 20 * time.Minute
	config.Keywords = keywords

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
		logger.Warning().Msgf("Domain scan failed, using HTTPS fallback for %d domains: %v", len(domains), err)
		fallbackDomains := make(map[string]*domainscan.DomainEntry)
		for _, domain := range domains {
			httpsURL := "https://" + domain
			fallbackDomains[httpsURL] = &domainscan.DomainEntry{
				IsLive: true, // Assume live for fallback
			}
		}

		if s.progress != nil {
			s.progress.OnDomainDiscoveryComplete(len(fallbackDomains), len(domains), 0)
		}
		return fallbackDomains, nil
	}

	logger.Debug().Msgf("Domain scan completed: found %d live domains with protocol info", len(result.Domains))

	// Filter only live domains and return the DomainEntry map directly
	liveDomains := make(map[string]*domainscan.DomainEntry)
	for domainURL, entry := range result.Domains {
		if entry.IsLive {
			liveDomains[domainURL] = entry
		}
	}

	// Notify progress callback of completion
	if s.progress != nil {
		s.progress.OnDomainDiscoveryComplete(len(liveDomains), len(domains), len(liveDomains)-len(domains))
	}

	logger.Info().Msgf("Domain discovery with protocol completed: %d live domains", len(liveDomains))

	return liveDomains, nil
}

// discoverDomainsWithCache handles domain discovery with caching support
func (s *scanner) discoverDomainsWithCache(domains []string, keywords []string, resultsDir string, force bool) ([]string, error) {
	logger := GetLogger()
	cacheFile := filepath.Join(resultsDir, "domain-scan.json")

	// If force flag is set, remove cache file
	if force {
		logger.Debug().Msgf("Clearing domain cache: %s", cacheFile)
		if err := os.Remove(cacheFile); err != nil && !os.IsNotExist(err) {
			logger.Error().Msgf("Failed to clear cache file: %v", err)
			return nil, fmt.Errorf("failed to clear cache: %w", err)
		}
	}

	// Try to load from cache first
	if !force {
		if cachedDomains, err := s.loadDomainsFromCache(cacheFile); err == nil {
			logger.Debug().Msgf("Cache hit: loaded %d domains from %s", len(cachedDomains), cacheFile)
			if s.progress != nil {
				s.progress.OnDomainDiscoveryStart(domains, keywords)
				s.progress.OnDomainDiscoveryComplete(len(cachedDomains), len(domains), len(cachedDomains)-len(domains))
			}
			return cachedDomains, nil
		} else {
			logger.Debug().Msgf("Cache miss or invalid cache: %v", err)
		}
	}

	// Perform fresh domain discovery
	discoveredDomains, err := s.DiscoverDomains(domains, keywords)
	if err != nil {
		return nil, err
	}

	// Save to cache
	if err := s.saveDomainsToCache(discoveredDomains, cacheFile); err != nil {
		// Log warning but don't fail the scan
		logger.Warning().Msgf("Failed to save domain cache: %v", err)
	} else {
		logger.Debug().Msgf("Saved %d domains to cache: %s", len(discoveredDomains), cacheFile)
	}

	return discoveredDomains, nil
}

// loadDomainsFromCache loads domains from cache file
func (s *scanner) loadDomainsFromCache(cacheFile string) ([]string, error) {
	logger := GetLogger()
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		logger.Debug().Msgf("Failed to read cache file %s: %v", cacheFile, err)
		return nil, err
	}

	var domains []string
	if err := json.Unmarshal(data, &domains); err != nil {
		logger.Warning().Msgf("Failed to unmarshal cache file %s: %v", cacheFile, err)
		return nil, err
	}

	return domains, nil
}

// saveDomainsToCache saves domains to cache file
func (s *scanner) saveDomainsToCache(domains []string, cacheFile string) error {
	logger := GetLogger()
	data, err := json.MarshalIndent(domains, "", "  ")
	if err != nil {
		logger.Error().Msgf("Failed to marshal domains for cache: %v", err)
		return err
	}

	if err := os.WriteFile(cacheFile, data, 0644); err != nil {
		logger.Error().Msgf("Failed to write cache file %s: %v", cacheFile, err)
		return err
	}

	return nil
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

// createDirectDomainList creates a domain-scan.json with provided domains (skips discovery)
func (s *scanner) createDirectDomainList(domains []string, resultsDir string) ([]string, error) {
	logger := GetLogger()
	logger.Debug().Msgf("Creating direct domain list for %d domains (skipping discovery)", len(domains))

	cacheFile := filepath.Join(resultsDir, "domain-scan.json")

	// Convert domains to HTTPS URLs (default assumption)
	var urls []string
	for _, domain := range domains {
		httpsURL := "https://" + domain
		urls = append(urls, httpsURL)
	}

	// Save to cache file
	if err := s.saveDomainsToCache(urls, cacheFile); err != nil {
		logger.Error().Msgf("Failed to save domain list to %s: %v", cacheFile, err)
		return nil, fmt.Errorf("failed to save domain list: %w", err)
	}

	// Notify progress callback if set
	if s.progress != nil {
		s.progress.OnDomainDiscoveryStart(domains, []string{})
		s.progress.OnDomainDiscoveryComplete(len(urls), len(domains), 0)
	}

	logger.Info().Msg("Skipped discovery - using provided domains only")
	logger.Info().Msgf("Total domains: %d", len(urls))
	logger.Info().Msgf("Results saved to: %s", cacheFile)

	return urls, nil
}
