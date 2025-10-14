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
var templatesFS embed.FS

// generateHTMLReport generates a self-contained HTML report directory with all assets
func (s *scanner) generateHTMLReport(report *ExposureReport, resultsDir string) error {
	// Create report directory structure
	reportDir := filepath.Join(resultsDir, "report")
	assetsDir := filepath.Join(reportDir, "assets")

	// Create report directory
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		return fmt.Errorf("failed to create report directory: %w", err)
	}

	// Copy entire assets directory from embedded templates
	if err := copyEmbeddedDirectory(templatesFS, "templates/assets", assetsDir); err != nil {
		return fmt.Errorf("failed to copy assets directory: %w", err)
	}

	// Generate HTML content
	htmlContent, err := generateHTMLContent(report)
	if err != nil {
		return fmt.Errorf("failed to generate HTML content: %w", err)
	}

	// Write the HTML report
	htmlPath := filepath.Join(reportDir, "index.html")
	if err := os.WriteFile(htmlPath, htmlContent, 0644); err != nil {
		return fmt.Errorf("failed to write HTML report: %w", err)
	}

	return nil
}

// copyDirectory recursively copies a directory from source to destination
func copyDirectory(src, dst string) error {
	// Get info about source directory
	srcInfo, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("failed to stat source directory %s: %w", src, err)
	}

	// Create destination directory with same permissions
	if err := os.MkdirAll(dst, srcInfo.Mode()); err != nil {
		return fmt.Errorf("failed to create destination directory %s: %w", dst, err)
	}

	// Read source directory entries
	entries, err := os.ReadDir(src)
	if err != nil {
		return fmt.Errorf("failed to read source directory %s: %w", src, err)
	}

	// Copy each entry
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			// Recursively copy subdirectories
			if err := copyDirectory(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			// Copy files
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}

	return nil
}

// copyFile copies a single file from source to destination
func copyFile(src, dst string) error {
	// Read source file
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("failed to read source file %s: %w", src, err)
	}

	// Get source file info for permissions
	srcInfo, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("failed to stat source file %s: %w", src, err)
	}

	// Write destination file with same permissions
	if err := os.WriteFile(dst, data, srcInfo.Mode()); err != nil {
		return fmt.Errorf("failed to write destination file %s: %w", dst, err)
	}

	return nil
}

// generateHTMLContent generates the HTML content using the embedded template
func generateHTMLContent(report *ExposureReport) ([]byte, error) {
	// Read the HTML template from embedded filesystem
	templateData, err := templatesFS.ReadFile("templates/report.html")
	if err != nil {
		return nil, fmt.Errorf("failed to read HTML template: %w", err)
	}

	// Parse the HTML template
	tmpl, err := template.New("report").Parse(string(templateData))
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML template: %w", err)
	}

	// Execute the template with report data
	var htmlBuffer bytes.Buffer
	if err := tmpl.Execute(&htmlBuffer, report); err != nil {
		return nil, fmt.Errorf("failed to execute HTML template: %w", err)
	}

	return htmlBuffer.Bytes(), nil
}

// copyEmbeddedDirectory recursively copies a directory from embedded filesystem to destination
func copyEmbeddedDirectory(embeddedFS embed.FS, src, dst string) error {
	// Create destination directory
	if err := os.MkdirAll(dst, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory %s: %w", dst, err)
	}

	// Read embedded directory entries
	entries, err := fs.ReadDir(embeddedFS, src)
	if err != nil {
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
	// Read file from embedded filesystem
	data, err := embeddedFS.ReadFile(src)
	if err != nil {
		return fmt.Errorf("failed to read embedded file %s: %w", src, err)
	}

	// Write destination file
	if err := os.WriteFile(dst, data, 0644); err != nil {
		return fmt.Errorf("failed to write destination file %s: %w", dst, err)
	}

	return nil
}