package scanner

import (
	"fmt"

	"web-exposure-detection/pkg/webexposure/common"
	"web-exposure-detection/pkg/webexposure/logger"
)

// RunCompletePipeline executes the complete scan and report generation pipeline
// This is the universal flow used by all commands
// With proper subflow caching, this can be called repeatedly safely
// Accepts multiple domains, uses first domain as primary for results storage
func (s *scanner) RunCompletePipeline(domains []string, force bool, keywords []string, templates []string, skipDiscoveryAll bool, skipDiscoveryPassive bool, skipDiscoveryCertificate bool, preset common.ScanPreset) error {
	log := logger.GetLogger()

	if len(domains) == 0 {
		return fmt.Errorf("no domains provided")
	}

	// Use first domain as primary for results storage
	primaryDomain := domains[0]
	log.Info().Msgf("Starting complete pipeline for %d domains (primary: %s)", len(domains), primaryDomain)

	// Determine skip flags
	skipPassive := skipDiscoveryPassive || skipDiscoveryAll
	skipCertificate := skipDiscoveryCertificate || skipDiscoveryAll

	// Step 1: Discovery Subflow for ALL domains (cached)
	if !skipDiscoveryAll {
		_, err := s.runMultiDomainDiscoverySubflow(domains, primaryDomain, force, keywords, skipPassive, skipCertificate)
		if err != nil {
			return fmt.Errorf("discovery subflow failed: %w", err)
		}
	} else {
		log.Info().Msg("Skipping discovery (all discovery disabled)")
	}

	// Step 2: Industry Classification Subflow (cached, non-blocking) - uses primary domain
	_, err := s.runIndustryClassificationSubflow(primaryDomain, force)
	if err != nil {
		log.Warning().Msgf("Industry classification failed: %v (continuing without industry info)", err)
		// Non-blocking, continue
	}

	// Step 3: Nuclei Scan Subflow (cached) - scans all discovered targets
	_, err = s.runNucleiScanSubflow(primaryDomain, force, keywords, templates, skipPassive, skipCertificate, preset)
	if err != nil {
		return fmt.Errorf("nuclei scan subflow failed: %w", err)
	}

	// Step 4: TRU Insights Subflow (cached, non-blocking)
	_, err = s.runTRUInsightsSubflow(primaryDomain, force, keywords, templates, skipPassive, skipCertificate, skipDiscoveryAll, preset)
	if err != nil {
		log.Warning().Msgf("TRU Insights generation failed: %v (continuing without TRU insights)", err)
		// Non-blocking, continue without TRU insights
	}

	// Step 5: Report JSON Subflow (cached)
	_, err = s.runReportJSONSubflow(primaryDomain, force, keywords, templates, skipPassive, skipCertificate, preset)
	if err != nil {
		return fmt.Errorf("report JSON generation failed: %w", err)
	}

	// Step 6: HTML Subflow (cached, non-blocking)
	_, err = s.runHTMLSubflow(primaryDomain, force, keywords, templates, skipPassive, skipCertificate, preset)
	if err != nil {
		log.Warning().Msgf("HTML generation failed: %v (continuing)", err)
		// Non-blocking for HTML, continue to try PDF
	}

	// Step 7: PDF Subflow (cached, non-blocking)
	pdfPath, err := s.runPDFSubflow(primaryDomain, force, keywords, templates, skipPassive, skipCertificate, preset)
	if err != nil {
		log.Warning().Msgf("PDF generation failed: %v", err)
		// Non-blocking, pipeline can succeed without PDF
	} else {
		log.Info().Msgf("Complete pipeline finished: %s", pdfPath)
	}

	log.Info().Msgf("Pipeline completed successfully for %d domains", len(domains))
	return nil
}
