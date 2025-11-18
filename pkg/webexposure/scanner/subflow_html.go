package scanner

import (
	"fmt"
	"os"
	"path/filepath"

	"web-exposure-detection/pkg/webexposure/common"
	"web-exposure-detection/pkg/webexposure/logger"
	"web-exposure-detection/pkg/webexposure/report"
)

// runHTMLSubflow executes HTML generation subflow (always regenerates, no caching)
// Output: results/{domain}/report/index.html
// Dependencies: Report JSON Subflow (Level 4 subflow)
func (s *scanner) runHTMLSubflow(domain string, force bool, keywords []string, templates []string, skipPassive bool, skipCertificate bool, preset common.ScanPreset) (string, error) {
	log := logger.GetLogger()
	resultsDir := filepath.Join("results", domain)
	htmlDir := filepath.Join(resultsDir, "report")
	outputFile := filepath.Join(htmlDir, "index.html")

	// Step 1: Always regenerate HTML (remove existing if present)
	log.Debug().Msg("HTML is always regenerated (no caching)")
	os.RemoveAll(htmlDir)

	// Step 2: Call dependency subflow - Report JSON (with same force flag)
	expReport, err := s.runReportJSONSubflow(domain, force, keywords, templates, skipPassive, skipCertificate, preset)
	if err != nil {
		return "", fmt.Errorf("report JSON subflow dependency failed: %w", err)
	}

	// Step 3: Execute HTML generation
	log.Info().Msg("Generating HTML report")

	if err := report.GenerateHTMLReport(expReport, resultsDir); err != nil {
		return "", fmt.Errorf("HTML generation failed: %w", err)
	}

	log.Info().Msg("HTML report generated successfully")

	// Step 4: Return result
	return outputFile, nil
}

// runShortHTMLSubflow executes short HTML generation subflow (always regenerates, no caching)
// Output: results/{domain}/report-short/index.html
// Dependencies: Report JSON Subflow (Level 4 subflow)
func (s *scanner) runShortHTMLSubflow(domain string, force bool, keywords []string, templates []string, skipPassive bool, skipCertificate bool, preset common.ScanPreset) (string, error) {
	log := logger.GetLogger()
	resultsDir := filepath.Join("results", domain)
	htmlDir := filepath.Join(resultsDir, "report-short")

	// Step 1: Always regenerate short HTML (remove existing if present)
	log.Debug().Msg("Short HTML is always regenerated (no caching)")
	os.RemoveAll(htmlDir)

	// Step 2: Call dependency subflow - Report JSON (with same force flag)
	expReport, err := s.runReportJSONSubflow(domain, force, keywords, templates, skipPassive, skipCertificate, preset)
	if err != nil {
		return "", fmt.Errorf("report JSON subflow dependency failed: %w", err)
	}

	// Step 3: Execute short HTML generation
	log.Info().Msg("Generating short HTML report")

	htmlPath, err := report.GenerateShortHTMLReport(expReport, resultsDir)
	if err != nil {
		return "", fmt.Errorf("short HTML generation failed: %w", err)
	}

	log.Info().Msg("Short HTML report generated successfully")

	// Step 4: Return result
	return htmlPath, nil
}
