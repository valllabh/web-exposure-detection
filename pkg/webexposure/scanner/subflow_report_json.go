package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"web-exposure-detection/pkg/webexposure/common"
	"web-exposure-detection/pkg/webexposure/industry"
	"web-exposure-detection/pkg/webexposure/logger"
	"web-exposure-detection/pkg/webexposure/report"
)

// runReportJSONSubflow executes report JSON generation subflow with caching
// Cache: results/{domain}/web-exposure-result.json
// Dependencies: TRU Insights Subflow (Level 3 subflow)
func (s *scanner) runReportJSONSubflow(domain string, force bool, keywords []string, templates []string, skipPassive bool, skipCertificate bool, preset common.ScanPreset) (*common.ExposureReport, error) {
	log := logger.GetLogger()
	resultsDir := filepath.Join("results", domain)
	cacheFile := filepath.Join(resultsDir, "web-exposure-result.json")

	// Create results directory
	if err := os.MkdirAll(resultsDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create results directory: %w", err)
	}

	// Generate false positives template if it doesn't exist (do this before cache check)
	fpFile := filepath.Join(resultsDir, "false-positives.json")
	if _, err := os.Stat(fpFile); os.IsNotExist(err) {
		// Load nuclei results to generate FP template
		if groupedResults, err := s.loadExistingNucleiResults(resultsDir); err == nil {
			if err := report.GenerateFalsePositivesTemplate(domain, groupedResults); err != nil {
				log.Warning().Msgf("Failed to generate false positives template: %v", err)
			}
		} else {
			log.Debug().Msgf("No nuclei results found yet for FP generation: %v", err)
		}
	}

	// Step 1: Check cache (unless force=true)
	if !force {
		if data, err := os.ReadFile(cacheFile); err == nil {
			var cachedReport common.ExposureReport
			if err := json.Unmarshal(data, &cachedReport); err == nil {
				log.Info().Msg("Using cached report JSON")
				return &cachedReport, nil
			}
		}
		log.Debug().Msg("Report JSON cache miss, executing subflow")
	} else {
		log.Info().Msg("Force flag set, regenerating report JSON")
		os.Remove(cacheFile)
	}

	// Step 2: Call dependency subflow - TRU Insights (with same force flag)
	// TRU Insights subflow handles all its dependencies (Discovery, Industry, Nuclei)
	skipDiscoveryAll := skipPassive && skipCertificate
	_, err := s.runTRUInsightsSubflow(domain, force, keywords, templates, skipPassive, skipCertificate, skipDiscoveryAll, preset)
	if err != nil {
		log.Warning().Msgf("TRU Insights subflow failed: %v (continuing without TRU insights)", err)
		// Non-blocking, continue without TRU insights
	}

	// Step 3: Load existing Nuclei results (already grouped in cache file)
	log.Info().Msg("Loading Nuclei results")
	groupedResults, err := s.loadExistingNucleiResults(resultsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load nuclei results: %w", err)
	}

	// Load discovery result for domain metrics (if available)
	discoveryResultFile := filepath.Join(resultsDir, "domain-discovery-result.json")
	if discoveryResult, err := s.loadDiscoveryResult(discoveryResultFile); err == nil {
		s.lastDiscoveryResult = discoveryResult
		log.Debug().Msgf("Loaded discovery result: %d domains", len(discoveryResult.Domains))
	} else {
		log.Debug().Msgf("Discovery result not found: %v", err)
	}

	// Load industry classification from cache (if available)
	industryFile := filepath.Join(resultsDir, "industry-classification.json")
	if classification, err := industry.ClassifyDomainIndustryWithCache(domain, industryFile, false); err == nil {
		s.industryClassification = classification
		log.Debug().Msgf("Loaded industry classification: %s - %s", classification.Industry, classification.SubIndustry)
	} else {
		log.Debug().Msgf("Industry classification not found: %v", err)
	}

	// Step 4: Execute report generation
	log.Info().Msg("Generating report JSON")

	// Convert industry classification to IndustryInfo
	var industryInfo *common.IndustryInfo
	if s.industryClassification != nil {
		industryInfo = &common.IndustryInfo{
			CompanyName:      s.industryClassification.CompanyName,
			ParentCompany:    s.industryClassification.ParentCompany,
			Subsidiaries:     s.industryClassification.Subsidiaries,
			Industry:         s.industryClassification.Industry,
			SubIndustry:      s.industryClassification.SubIndustry,
			Compliances:      s.industryClassification.Compliances,
			HeadquartersCity: s.industryClassification.HeadquartersCity,
			OperatingRegions: s.industryClassification.OperatingRegions,
			PrimaryRegion:    s.industryClassification.PrimaryRegion,
		}
	}

	// Generate report structure
	expReport, err := report.GenerateReport(groupedResults, domain, industryInfo, s.lastDiscoveryResult)
	if err != nil {
		return nil, fmt.Errorf("report generation failed: %w", err)
	}

	// Step 4: Save to cache
	reportJSON, err := json.MarshalIndent(expReport, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal report: %w", err)
	}

	if err := os.WriteFile(cacheFile, reportJSON, 0644); err != nil {
		log.Warning().Msgf("Failed to save report JSON cache: %v", err)
	} else {
		log.Debug().Msgf("Saved report JSON cache to %s", cacheFile)
	}

	log.Info().Msg("Report JSON generated successfully")

	// Step 5: Return result
	return expReport, nil
}
