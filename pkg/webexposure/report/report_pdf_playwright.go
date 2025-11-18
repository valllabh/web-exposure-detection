package report

import (
	"fmt"
	"path/filepath"
	"web-exposure-detection/pkg/webexposure/logger"

	"github.com/playwright-community/playwright-go"

	"web-exposure-detection/pkg/webexposure/common"
)

// PlaywrightPDFGenerator implements common.PDFGenerator using playwright library
type PlaywrightPDFGenerator struct{}

// NewPlaywrightPDFGenerator creates a new playwright-based PDF generator
func NewPlaywrightPDFGenerator() common.PDFGenerator {
	return &PlaywrightPDFGenerator{}
}

// GeneratePDF generates a PDF from HTML using playwright library with Chromium
func (g *PlaywrightPDFGenerator) GeneratePDF(htmlPath, pdfPath string) error {
	logger := logger.GetLogger()
	logger.Debug().Msg("Initializing Playwright Chromium for PDF generation")

	// Install playwright if needed
	if err := playwright.Install(); err != nil {
		logger.Error().Msgf("Failed to install playwright: %v", err)
		return fmt.Errorf("failed to install playwright: %w", err)
	}

	// Start playwright
	pw, err := playwright.Run()
	if err != nil {
		logger.Error().Msgf("Failed to start playwright: %v", err)
		return fmt.Errorf("failed to start playwright: %w", err)
	}
	defer pw.Stop()

	// Launch Chromium browser (PDF generation only supported in Chromium)
	logger.Debug().Msg("Launching Chromium browser")
	browser, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(true),
	})
	if err != nil {
		logger.Error().Msgf("Failed to launch Chromium: %v", err)
		return fmt.Errorf("failed to launch Chromium: %w", err)
	}
	defer browser.Close()

	// Create new page
	page, err := browser.NewPage()
	if err != nil {
		logger.Error().Msgf("Failed to create new page: %v", err)
		return fmt.Errorf("failed to create new page: %w", err)
	}
	defer page.Close()

	// Get absolute path
	absPath, err := filepath.Abs(htmlPath)
	if err != nil {
		logger.Error().Msgf("Failed to get absolute path for HTML file: %v", err)
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Navigate to HTML file
	fileURL := "file://" + absPath
	logger.Debug().Msgf("Loading HTML from: %s", fileURL)
	if _, err := page.Goto(fileURL, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateNetworkidle,
	}); err != nil {
		logger.Error().Msgf("Failed to navigate to HTML file: %v", err)
		return fmt.Errorf("failed to navigate to HTML file: %w", err)
	}

	// Wait for page to be fully loaded and stable
	logger.Debug().Msg("Waiting for page to stabilize")
	if err := page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	}); err != nil {
		logger.Warning().Msgf("Failed to wait for network idle: %v", err)
	}

	// Generate PDF
	logger.Debug().Msg("Generating PDF")
	_, err = page.PDF(playwright.PagePdfOptions{
		Path:            playwright.String(pdfPath),
		Format:          playwright.String("A4"),
		PrintBackground: playwright.Bool(true),
		Margin: &playwright.Margin{
			Top:    playwright.String("0.39in"),
			Bottom: playwright.String("0.39in"),
			Left:   playwright.String("0.39in"),
			Right:  playwright.String("0.39in"),
		},
		PreferCSSPageSize: playwright.Bool(true),
	})
	if err != nil {
		logger.Error().Msgf("Failed to generate PDF: %v", err)
		return fmt.Errorf("failed to generate PDF: %w", err)
	}

	logger.Info().Msgf("PDF report generated successfully: %s", pdfPath)
	return nil
}
