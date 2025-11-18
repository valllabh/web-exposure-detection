package report

import (
	"fmt"
	"os"
	"path/filepath"
	"web-exposure-detection/pkg/webexposure/logger"

	"github.com/jung-kurt/gofpdf"
	"github.com/playwright-community/playwright-go"

	"web-exposure-detection/pkg/webexposure/common"
)

// PlaywrightFirefoxPDFGenerator implements common.PDFGenerator using playwright Firefox with screenshot-to-PDF
type PlaywrightFirefoxPDFGenerator struct{}

// NewPlaywrightFirefoxPDFGenerator creates a new playwright Firefox-based PDF generator
func NewPlaywrightFirefoxPDFGenerator() common.PDFGenerator {
	return &PlaywrightFirefoxPDFGenerator{}
}

// GeneratePDF generates a PDF from HTML using playwright Firefox and screenshot conversion
func (g *PlaywrightFirefoxPDFGenerator) GeneratePDF(htmlPath, pdfPath string) error {
	logger := logger.GetLogger()
	logger.Debug().Msg("Initializing Playwright Firefox for PDF generation via screenshot")

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

	// Launch Firefox browser
	logger.Debug().Msg("Launching Firefox browser")
	browser, err := pw.Firefox.Launch(playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(true),
	})
	if err != nil {
		logger.Error().Msgf("Failed to launch Firefox: %v", err)
		return fmt.Errorf("failed to launch Firefox: %w", err)
	}
	defer browser.Close()

	// Create new page
	page, err := browser.NewPage()
	if err != nil {
		logger.Error().Msgf("Failed to create new page: %v", err)
		return fmt.Errorf("failed to create new page: %w", err)
	}
	defer page.Close()

	// Set viewport to A4 size
	if err := page.SetViewportSize(794, 1123); err != nil {
		logger.Warning().Msgf("Failed to set viewport size: %v", err)
	}

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

	// Create temporary screenshot file
	screenshotPath := pdfPath + ".screenshot.png"
	defer os.Remove(screenshotPath) // Clean up screenshot after conversion

	// Take full-page screenshot
	logger.Debug().Msg("Taking full-page screenshot")
	_, err = page.Screenshot(playwright.PageScreenshotOptions{
		Path:     playwright.String(screenshotPath),
		FullPage: playwright.Bool(true),
		Type:     playwright.ScreenshotTypePng,
	})
	if err != nil {
		logger.Error().Msgf("Failed to take screenshot: %v", err)
		return fmt.Errorf("failed to take screenshot: %w", err)
	}

	// Convert screenshot to PDF
	logger.Debug().Msg("Converting screenshot to PDF")
	if err := convertImageToPDF(screenshotPath, pdfPath); err != nil {
		logger.Error().Msgf("Failed to convert screenshot to PDF: %v", err)
		return fmt.Errorf("failed to convert screenshot to PDF: %w", err)
	}

	logger.Info().Msgf("PDF report generated successfully: %s", pdfPath)
	return nil
}

// convertImageToPDF converts a PNG image to PDF maintaining A4 proportions
func convertImageToPDF(imagePath, pdfPath string) error {
	// Create new PDF in portrait orientation, A4 size
	pdf := gofpdf.New("P", "mm", "A4", "")

	// Add a page
	pdf.AddPage()

	// Get A4 dimensions in mm
	pageWidth, pageHeight := pdf.GetPageSize()

	// Register the image
	imageOptions := gofpdf.ImageOptions{
		ImageType: "PNG",
		ReadDpi:   true,
	}

	// Add image to fill the entire page
	pdf.ImageOptions(imagePath, 0, 0, pageWidth, pageHeight, false, imageOptions, 0, "")

	// Save PDF
	if err := pdf.OutputFileAndClose(pdfPath); err != nil {
		return fmt.Errorf("failed to write PDF file: %w", err)
	}

	return nil
}
