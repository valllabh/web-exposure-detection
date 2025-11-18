package report

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"web-exposure-detection/pkg/webexposure/common"
	"web-exposure-detection/pkg/webexposure/findings"
	"web-exposure-detection/pkg/webexposure/logger"
)

// templatesFS will be set from main package
var templatesFS embed.FS

// SetTemplatesFS sets the templates filesystem
func SetTemplatesFS(fs embed.FS) {
	templatesFS = fs
}

// GenerateHTMLReport generates a self-contained HTML report directory with all assets
func GenerateHTMLReport(report *common.ExposureReport, resultsDir string) error {
	logger := logger.GetLogger()
	logger.Debug().Msgf("Generating HTML report in %s", resultsDir)

	// Create report directory structure
	reportDir := filepath.Join(resultsDir, "report")
	assetsDir := filepath.Join(reportDir, "assets")

	// Create report directory
	if err := os.MkdirAll(reportDir, 0750); err != nil {
		return fmt.Errorf("failed to create report directory: %w", err)
	}
	logger.Info().Msgf("Created report directory: %s", reportDir)

	// Copy entire assets directory from embedded templates
	if err := copyEmbeddedDirectory(templatesFS, "templates/assets", assetsDir); err != nil {
		return fmt.Errorf("failed to copy assets directory: %w", err)
	}

	// Extract domain from resultsDir (results/{domain})
	domain := filepath.Base(resultsDir)

	// Try to load TRU insights (optional)
	truInsights, err := LoadTRUInsights(domain)
	if err != nil {
		logger.Warning().Msgf("Failed to load TRU insights: %v", err)
		// Continue without TRU insights
		truInsights = nil
	}

	// Generate HTML content with optional TRU insights
	htmlContent, err := GenerateHTMLContentWithTRU(report, truInsights)
	if err != nil {
		logger.Error().Msgf("Failed to generate HTML content: %v", err)
		return fmt.Errorf("failed to generate HTML content: %w", err)
	}

	// Write the HTML report
	htmlPath := filepath.Join(reportDir, "index.html")
	if err := os.WriteFile(htmlPath, htmlContent, 0600); err != nil {
		return fmt.Errorf("failed to write HTML report: %w", err)
	}
	logger.Info().Msgf("HTML report generated: %s", htmlPath)

	return nil
}

// GenerateHTMLContent generates the HTML content using the embedded template
func GenerateHTMLContent(report *common.ExposureReport) ([]byte, error) {
	logger := logger.GetLogger()
	logger.Debug().Msg("Reading HTML template from embedded filesystem")

	// Read the HTML template from embedded filesystem
	templateData, err := templatesFS.ReadFile("templates/report.html")
	if err != nil {
		logger.Error().Msgf("Failed to read HTML template: %v", err)
		return nil, fmt.Errorf("failed to read HTML template: %w", err)
	}

	// Parse the HTML template with custom functions
	funcMap := template.FuncMap{
		"subtract": func(a, b int) int {
			return a - b
		},
		"add": func(a, b int) int {
			return a + b
		},
		"multiply": func(a, b int) int {
			return a * b
		},
		"len": func(v interface{}) int {
			switch val := v.(type) {
			case []interface{}:
				return len(val)
			case []string:
				return len(val)
			case []common.WeaknessPattern:
				return len(val)
			case []*findings.FindingItem:
				return len(val)
			default:
				return 0
			}
		},
		"hasInfraClassification": func(classifications []string) bool {
			for _, c := range classifications {
				if c == "~webapp" || c == "~api" {
					return true
				}
			}
			return false
		},
		"markdownBold": func(text string) template.HTML {
			// Convert markdown **bold** to HTML with lighter font weight (font-semibold)
			result := text
			count := strings.Count(text, "**")
			if count%2 == 0 {
				// Even number, properly paired
				for i := 0; i < count/2; i++ {
					result = strings.Replace(result, "**", "<span class=\"font-semibold\">", 1)
					result = strings.Replace(result, "**", "</span>", 1)
				}
			}
			return template.HTML(result)
		},
		"truncate": func(s string, maxLen int) string {
			if len(s) <= maxLen {
				return s
			}
			return s[:maxLen] + "..."
		},
		"slice": func(v interface{}, start, end int) interface{} {
			switch val := v.(type) {
			case []*findings.Discovery:
				if end > len(val) {
					end = len(val)
				}
				return val[start:end]
			default:
				return v
			}
		},
	}
	tmpl, err := template.New("report").Funcs(funcMap).Parse(string(templateData))
	if err != nil {
		logger.Error().Msgf("Failed to parse HTML template: %v", err)
		return nil, fmt.Errorf("failed to parse HTML template: %w", err)
	}

	// Execute the template with report data
	var htmlBuffer bytes.Buffer
	if err := tmpl.Execute(&htmlBuffer, report); err != nil {
		logger.Error().Msgf("Failed to execute HTML template: %v", err)
		return nil, fmt.Errorf("failed to execute HTML template: %w", err)
	}

	return htmlBuffer.Bytes(), nil
}

// GenerateHTMLContentWithTRU generates HTML content with optional TRU insights
func GenerateHTMLContentWithTRU(report *common.ExposureReport, truInsights *TRUInsightsData) ([]byte, error) {
	logger := logger.GetLogger()
	logger.Debug().Msg("Reading HTML template from embedded filesystem")

	// Read the HTML template from embedded filesystem
	templateBytes, err := templatesFS.ReadFile("templates/report.html")
	if err != nil {
		logger.Error().Msgf("Failed to read HTML template: %v", err)
		return nil, fmt.Errorf("failed to read HTML template: %w", err)
	}

	// Parse the HTML template with custom functions
	funcMap := template.FuncMap{
		"subtract": func(a, b int) int {
			return a - b
		},
		"add": func(a, b int) int {
			return a + b
		},
		"multiply": func(a, b int) int {
			return a * b
		},
		"len": func(v interface{}) int {
			switch val := v.(type) {
			case []interface{}:
				return len(val)
			case []string:
				return len(val)
			case []common.WeaknessPattern:
				return len(val)
			case []*findings.FindingItem:
				return len(val)
			default:
				return 0
			}
		},
		"hasInfraClassification": func(classifications []string) bool {
			for _, c := range classifications {
				if c == "~webapp" || c == "~api" {
					return true
				}
			}
			return false
		},
		"markdownBold": func(text string) template.HTML {
			// Convert markdown **bold** to HTML with lighter font weight (font-semibold)
			result := text
			count := strings.Count(text, "**")
			if count%2 == 0 {
				// Even number, properly paired
				for i := 0; i < count/2; i++ {
					result = strings.Replace(result, "**", "<span class=\"font-semibold\">", 1)
					result = strings.Replace(result, "**", "</span>", 1)
				}
			}
			return template.HTML(result)
		},
		"truncate": func(s string, maxLen int) string {
			if len(s) <= maxLen {
				return s
			}
			return s[:maxLen] + "..."
		},
		"slice": func(v interface{}, start, end int) interface{} {
			switch val := v.(type) {
			case []*findings.Discovery:
				if end > len(val) {
					end = len(val)
				}
				return val[start:end]
			default:
				return v
			}
		},
	}
	tmpl, err := template.New("report").Funcs(funcMap).Parse(string(templateBytes))
	if err != nil {
		logger.Error().Msgf("Failed to parse HTML template: %v", err)
		return nil, fmt.Errorf("failed to parse HTML template: %w", err)
	}

	// Create a custom template data type that embeds the report
	// This maintains backward compatibility while adding TRU insights
	type TemplateData struct {
		*common.ExposureReport
		TRUInsights *TRUInsightsData
	}

	data := &TemplateData{
		ExposureReport: report,
		TRUInsights:    truInsights,
	}

	// Execute the template with combined data
	var htmlBuffer bytes.Buffer
	if err := tmpl.Execute(&htmlBuffer, data); err != nil {
		logger.Error().Msgf("Failed to execute HTML template: %v", err)
		return nil, fmt.Errorf("failed to execute HTML template: %w", err)
	}

	return htmlBuffer.Bytes(), nil
}

// GenerateShortHTMLReport generates a short version HTML report with top 5 assets only
func GenerateShortHTMLReport(report *common.ExposureReport, resultsDir string) (string, error) {
	logger := logger.GetLogger()
	logger.Debug().Msgf("Generating short HTML report in %s", resultsDir)

	// Create report directory structure
	reportDir := filepath.Join(resultsDir, "report-short")
	assetsDir := filepath.Join(reportDir, "assets")

	// Create report directory
	if err := os.MkdirAll(reportDir, 0750); err != nil {
		return "", fmt.Errorf("failed to create short report directory: %w", err)
	}
	logger.Info().Msgf("Created short report directory: %s", reportDir)

	// Copy entire assets directory from embedded templates
	if err := copyEmbeddedDirectory(templatesFS, "templates/assets", assetsDir); err != nil {
		return "", fmt.Errorf("failed to copy assets directory: %w", err)
	}

	// Extract domain from resultsDir (results/{domain})
	domain := filepath.Base(resultsDir)

	// Try to load TRU insights (optional)
	truInsights, err := LoadTRUInsights(domain)
	if err != nil {
		logger.Warning().Msgf("Failed to load TRU insights: %v", err)
		truInsights = nil
	}

	// Generate short HTML content using short template
	htmlContent, err := GenerateShortHTMLContentWithTRU(report, truInsights)
	if err != nil {
		logger.Error().Msgf("Failed to generate short HTML content: %v", err)
		return "", fmt.Errorf("failed to generate short HTML content: %w", err)
	}

	// Write the HTML report
	htmlPath := filepath.Join(reportDir, "index.html")
	if err := os.WriteFile(htmlPath, htmlContent, 0600); err != nil {
		return "", fmt.Errorf("failed to write short HTML report: %w", err)
	}
	logger.Info().Msgf("Short HTML report generated: %s", htmlPath)

	return htmlPath, nil
}

// GenerateShortHTMLContentWithTRU generates short HTML content with optional TRU insights
func GenerateShortHTMLContentWithTRU(report *common.ExposureReport, truInsights *TRUInsightsData) ([]byte, error) {
	logger := logger.GetLogger()
	logger.Debug().Msg("Reading short HTML template from embedded filesystem")

	// Read the short HTML template from embedded filesystem
	templateBytes, err := templatesFS.ReadFile("templates/report-short.html")
	if err != nil {
		logger.Error().Msgf("Failed to read short HTML template: %v", err)
		return nil, fmt.Errorf("failed to read short HTML template: %w", err)
	}

	// Parse the HTML template with custom functions (same as full report)
	funcMap := template.FuncMap{
		"subtract": func(a, b int) int {
			return a - b
		},
		"add": func(a, b int) int {
			return a + b
		},
		"multiply": func(a, b int) int {
			return a * b
		},
		"len": func(v interface{}) int {
			switch val := v.(type) {
			case []interface{}:
				return len(val)
			case []string:
				return len(val)
			case []common.WeaknessPattern:
				return len(val)
			case []*findings.FindingItem:
				return len(val)
			default:
				return 0
			}
		},
		"hasInfraClassification": func(classifications []string) bool {
			for _, c := range classifications {
				if c == "~webapp" || c == "~api" {
					return true
				}
			}
			return false
		},
		"markdownBold": func(text string) template.HTML {
			result := text
			count := strings.Count(text, "**")
			if count%2 == 0 {
				for i := 0; i < count/2; i++ {
					result = strings.Replace(result, "**", "<span class=\"font-semibold\">", 1)
					result = strings.Replace(result, "**", "</span>", 1)
				}
			}
			return template.HTML(result)
		},
		"truncate": func(s string, maxLen int) string {
			if len(s) <= maxLen {
				return s
			}
			return s[:maxLen] + "..."
		},
		"slice": func(v interface{}, start, end int) interface{} {
			switch val := v.(type) {
			case []*findings.Discovery:
				if end > len(val) {
					end = len(val)
				}
				return val[start:end]
			default:
				return v
			}
		},
	}
	tmpl, err := template.New("report-short").Funcs(funcMap).Parse(string(templateBytes))
	if err != nil {
		logger.Error().Msgf("Failed to parse short HTML template: %v", err)
		return nil, fmt.Errorf("failed to parse short HTML template: %w", err)
	}

	// Create template data with TRU insights
	type TemplateData struct {
		*common.ExposureReport
		TRUInsights *TRUInsightsData
	}

	data := &TemplateData{
		ExposureReport: report,
		TRUInsights:    truInsights,
	}

	// Execute the template
	var htmlBuffer bytes.Buffer
	if err := tmpl.Execute(&htmlBuffer, data); err != nil {
		logger.Error().Msgf("Failed to execute short HTML template: %v", err)
		return nil, fmt.Errorf("failed to execute short HTML template: %w", err)
	}

	return htmlBuffer.Bytes(), nil
}

// copyEmbeddedDirectory recursively copies a directory from embedded filesystem to destination
func copyEmbeddedDirectory(embeddedFS embed.FS, src, dst string) error {
	logger := logger.GetLogger()
	logger.Debug().Msgf("Copying embedded directory %s to %s", src, dst)

	// Create destination directory
	if err := os.MkdirAll(dst, 0750); err != nil {
		logger.Error().Msgf("Failed to create destination directory %s: %v", dst, err)
		return fmt.Errorf("failed to create destination directory %s: %w", dst, err)
	}

	// Read embedded directory entries
	entries, err := fs.ReadDir(embeddedFS, src)
	if err != nil {
		logger.Error().Msgf("Failed to read embedded directory %s: %v", src, err)
		return fmt.Errorf("failed to read embedded directory %s: %w", src, err)
	}

	// Copy each entry
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			// Recursively copy subdirectories
			if err := copyEmbeddedDirectory(embeddedFS, srcPath, dstPath); err != nil {
				return err
			}
		} else {
			// Copy files from embedded filesystem
			if err := copyEmbeddedFile(embeddedFS, srcPath, dstPath); err != nil {
				return err
			}
		}
	}

	return nil
}

// copyEmbeddedFile copies a single file from embedded filesystem to destination
func copyEmbeddedFile(embeddedFS embed.FS, src, dst string) error {
	logger := logger.GetLogger()

	// Read file from embedded filesystem
	data, err := embeddedFS.ReadFile(src)
	if err != nil {
		logger.Error().Msgf("Failed to read embedded file %s: %v", src, err)
		return fmt.Errorf("failed to read embedded file %s: %w", src, err)
	}

	// Write destination file
	if err := os.WriteFile(dst, data, 0600); err != nil {
		logger.Error().Msgf("Failed to write destination file %s: %v", dst, err)
		return fmt.Errorf("failed to write destination file %s: %w", dst, err)
	}

	return nil
}
