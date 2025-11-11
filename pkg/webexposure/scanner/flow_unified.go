package scanner

import (
	"fmt"

	"web-exposure-detection/pkg/webexposure/common"
	"web-exposure-detection/pkg/webexposure/logger"
)

// RunCompletePipeline executes the complete scan and report generation pipeline
// This is the universal flow used by all commands
// With proper subflow caching, this can be called repeatedly safely
func (s *scanner) RunCompletePipeline(domain string, force bool, keywords []string, templates []string, skipDiscoveryAll bool, skipDiscoveryPassive bool, skipDiscoveryCertificate bool, preset common.ScanPreset) error {
	log := logger.GetLogger()
	log.Info().Msgf("Starting complete pipeline for domain: %s", domain)

	// Determine skip flags
	skipPassive := skipDiscoveryPassive || skipDiscoveryAll
	skipCertificate := skipDiscoveryCertificate || skipDiscoveryAll

	// Step 1: Discovery Subflow (cached)
	if !skipDiscoveryAll {
		_, err := s.runDiscoverySubflow(domain, force, keywords, skipPassive, skipCertificate)
		if err != nil {
			return fmt.Errorf("discovery subflow failed: %w", err)
		}
	} else {
		log.Info().Msg("Skipping discovery (all discovery disabled)")
	}

	// Step 2: Industry Classification Subflow (cached, non-blocking)
	_, err := s.runIndustryClassificationSubflow(domain, force)
	if err != nil {
		log.Warning().Msgf("Industry classification failed: %v (continuing without industry info)", err)
		// Non-blocking, continue
	}

	// Step 3: Nuclei Scan Subflow (cached)
	_, err = s.runNucleiScanSubflow(domain, force, keywords, templates, skipPassive, skipCertificate, preset)
	if err != nil {
		return fmt.Errorf("nuclei scan subflow failed: %w", err)
	}

	// Step 4: TRU Insights Subflow (cached, non-blocking)
	_, err = s.runTRUInsightsSubflow(domain, force, keywords, templates, skipPassive, skipCertificate, skipDiscoveryAll, preset)
	if err != nil {
		log.Warning().Msgf("TRU Insights generation failed: %v (continuing without TRU insights)", err)
		// Non-blocking, continue without TRU insights
	}

	// Step 5: Report JSON Subflow (cached)
	_, err = s.runReportJSONSubflow(domain, force, keywords, templates, skipPassive, skipCertificate, preset)
	if err != nil {
		return fmt.Errorf("report JSON generation failed: %w", err)
	}

	// Step 6: HTML Subflow (cached, non-blocking)
	_, err = s.runHTMLSubflow(domain, force, keywords, templates, skipPassive, skipCertificate, preset)
	if err != nil {
		log.Warning().Msgf("HTML generation failed: %v (continuing)", err)
		// Non-blocking for HTML, continue to try PDF
	}

	// Step 7: PDF Subflow (cached, non-blocking)
	pdfPath, err := s.runPDFSubflow(domain, force, keywords, templates, skipPassive, skipCertificate, preset)
	if err != nil {
		log.Warning().Msgf("PDF generation failed: %v", err)
		// Non-blocking, pipeline can succeed without PDF
	} else {
		log.Info().Msgf("Complete pipeline finished: %s", pdfPath)
	}

	log.Info().Msgf("Pipeline completed successfully for domain: %s", domain)
	return nil
}
