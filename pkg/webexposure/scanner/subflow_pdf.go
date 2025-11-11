package scanner

import (
	"fmt"
	"os"
	"path/filepath"

	"web-exposure-detection/pkg/webexposure/common"
	"web-exposure-detection/pkg/webexposure/logger"
)

// runPDFSubflow executes PDF generation subflow (always regenerates, no caching)
// Output: results/{domain}/{domain}-appex-report.pdf
// Dependencies: HTML Subflow (Level 5 subflow)
func (s *scanner) runPDFSubflow(domain string, force bool, keywords []string, templates []string, skipPassive bool, skipCertificate bool, preset common.ScanPreset) (string, error) {
	log := logger.GetLogger()
	resultsDir := filepath.Join("results", domain)
	outputFile := filepath.Join(resultsDir, domain+"-appex-report.pdf")

	// Step 1: Always regenerate PDF (remove existing if present)
	log.Debug().Msg("PDF is always regenerated (no caching)")
	os.Remove(outputFile)

	// Step 2: Call dependency subflow - HTML (with same force flag)
	htmlPath, err := s.runHTMLSubflow(domain, force, keywords, templates, skipPassive, skipCertificate, preset)
	if err != nil {
		return "", fmt.Errorf("HTML subflow dependency failed: %w", err)
	}

	// Step 3: Execute PDF generation
	log.Info().Msg("Generating PDF report")

	if err := s.generatePDF(htmlPath, outputFile); err != nil {
		return "", fmt.Errorf("PDF generation failed: %w", err)
	}

	log.Info().Msgf("PDF report generated successfully: %s", outputFile)

	// Clean up HTML report directory if not in debug mode
	if !s.debug {
		reportDir := filepath.Join(resultsDir, "report")
		if err := os.RemoveAll(reportDir); err != nil {
			log.Warning().Msgf("Failed to cleanup HTML report directory: %v", err)
		}
	} else {
		log.Debug().Msgf("HTML report preserved at %s", htmlPath)
	}

	// Step 4: Return result
	return outputFile, nil
}
