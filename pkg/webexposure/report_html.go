package webexposure

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"text/template"
)

// templatesFS will be set from main package

// generateHTMLReport generates a self-contained HTML report directory with all assets
func (s *scanner) generateHTMLReport(report *ExposureReport, resultsDir string) error {
	logger := GetLogger()
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

	// Generate HTML content
	htmlContent, err := generateHTMLContent(report)
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

// generateHTMLContent generates the HTML content using the embedded template
func generateHTMLContent(report *ExposureReport) ([]byte, error) {
	logger := GetLogger()
	logger.Debug().Msg("Reading HTML template from embedded filesystem")

	// Read the HTML template from embedded filesystem
	templateData, err := templatesFS.ReadFile("templates/report.html")
	if err != nil {
		logger.Error().Msgf("Failed to read HTML template: %v", err)
		return nil, fmt.Errorf("failed to read HTML template: %w", err)
	}

	// Parse the HTML template
	tmpl, err := template.New("report").Parse(string(templateData))
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

// copyEmbeddedDirectory recursively copies a directory from embedded filesystem to destination
func copyEmbeddedDirectory(embeddedFS embed.FS, src, dst string) error {
	logger := GetLogger()
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
	logger := GetLogger()

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
