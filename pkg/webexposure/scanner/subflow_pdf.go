package scanner

import (
	"fmt"
	"os"
	"path/filepath"

	"web-exposure-detection/pkg/webexposure/common"
	"web-exposure-detection/pkg/webexposure/logger"
)

// runPDFSubflow executes PDF generation subflow (always regenerates, no caching)
// Output: results/{domain}/{domain}-appex-report.pdf and results/{domain}/{domain}-appex-report-short.pdf
// Dependencies: HTML Subflow (Level 5 subflow)
func (s *scanner) runPDFSubflow(domain string, force bool, keywords []string, templates []string, skipPassive bool, skipCertificate bool, preset common.ScanPreset) (string, error) {
	log := logger.GetLogger()
	resultsDir := filepath.Join("results", domain)
	outputFile := filepath.Join(resultsDir, domain+"-appex-report-full.pdf")
	shortOutputFile := filepath.Join(resultsDir, domain+"-appex-report-short.pdf")

	// Step 1: Always regenerate PDFs (remove existing if present)
	log.Debug().Msg("PDFs are always regenerated (no caching)")
	os.Remove(outputFile)
	os.Remove(shortOutputFile)

	// Step 2: Call dependency subflow - HTML (with same force flag)
	htmlPath, err := s.runHTMLSubflow(domain, force, keywords, templates, skipPassive, skipCertificate, preset)
	if err != nil {
		return "", fmt.Errorf("HTML subflow dependency failed: %w", err)
	}

	// Step 3: Generate short HTML report
	shortHTMLPath, err := s.runShortHTMLSubflow(domain, force, keywords, templates, skipPassive, skipCertificate, preset)
	if err != nil {
		log.Warning().Msgf("Short HTML generation failed: %v (continuing with full report only)", err)
		// Non-blocking, continue with full report
	}

	// Step 4: Execute full PDF generation
	log.Info().Msg("Generating full PDF report")
	if err := s.generatePDF(htmlPath, outputFile); err != nil {
		return "", fmt.Errorf("PDF generation failed: %w", err)
	}
	log.Info().Msgf("Full PDF report generated successfully: %s", outputFile)

	// Step 5: Execute short PDF generation if short HTML exists
	if shortHTMLPath != "" {
		log.Info().Msg("Generating short PDF report")
		if err := s.generatePDF(shortHTMLPath, shortOutputFile); err != nil {
			log.Warning().Msgf("Short PDF generation failed: %v", err)
			// Non-blocking
		} else {
			log.Info().Msgf("Short PDF report generated successfully: %s", shortOutputFile)
		}
	}

	// Clean up HTML report directories if not in debug mode
	if !s.debug {
		reportDir := filepath.Join(resultsDir, "report")
		if err := os.RemoveAll(reportDir); err != nil {
			log.Warning().Msgf("Failed to cleanup HTML report directory: %v", err)
		}
		shortReportDir := filepath.Join(resultsDir, "report-short")
		if err := os.RemoveAll(shortReportDir); err != nil {
			log.Warning().Msgf("Failed to cleanup short HTML report directory: %v", err)
		}
	} else {
		log.Debug().Msgf("HTML reports preserved at %s and %s", htmlPath, shortHTMLPath)
	}

	// Step 6: Return result (full report path)
	return outputFile, nil
}
