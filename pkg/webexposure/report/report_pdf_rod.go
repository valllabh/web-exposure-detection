package report

import (
	"web-exposure-detection/pkg/webexposure/logger"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"

	"web-exposure-detection/pkg/webexposure/common"
)

// RodPDFGenerator implements common.PDFGenerator using go-rod library
type RodPDFGenerator struct{}

// NewRodPDFGenerator creates a new rod-based PDF generator
func NewRodPDFGenerator() common.PDFGenerator {
	return &RodPDFGenerator{}
}

// GeneratePDF generates a PDF from HTML using rod library with Chrome
func (g *RodPDFGenerator) GeneratePDF(htmlPath, pdfPath string) error {
	logger := logger.GetLogger()
	logger.Debug().Msg("Initializing Chrome headless browser for PDF generation")

	launcher := launcher.New().Headless(true)
	defer launcher.Cleanup()
	url := launcher.MustLaunch()
	browser := rod.New().ControlURL(url).MustConnect()
	defer browser.MustClose()

	absPath, err := filepath.Abs(htmlPath)
	if err != nil {
		logger.Error().Msgf("Failed to get absolute path for HTML file: %v", err)
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	fileURL := "file://" + absPath
	logger.Debug().Msgf("Loading HTML from: %s", fileURL)
	page := browser.MustPage(fileURL)
	defer page.MustClose()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	page = page.Context(ctx)

	// Wait for page to become stable (waits for load, network idle, DOM stable with 1s timeout)
	logger.Debug().Msg("Waiting for page to stabilize")
	page.MustWaitStable()

	// Wait for next repaint to ensure fonts and CSS effects are rendered
	logger.Debug().Msg("Waiting for repaint to complete rendering")
	if err := page.WaitRepaint(); err != nil {
		logger.Warning().Msgf("Failed to wait for repaint: %v", err)
	}

	pdfData, err := page.PDF(&proto.PagePrintToPDF{
		PaperWidth:              func() *float64 { f := 8.27; return &f }(),
		PaperHeight:             func() *float64 { f := 11.69; return &f }(),
		MarginTop:               func() *float64 { f := 0.39; return &f }(),
		MarginBottom:            func() *float64 { f := 0.39; return &f }(),
		MarginLeft:              func() *float64 { f := 0.39; return &f }(),
		MarginRight:             func() *float64 { f := 0.39; return &f }(),
		PrintBackground:         true,
		Scale:                   func() *float64 { f := 1.0; return &f }(),
		GenerateTaggedPDF:       true,
		GenerateDocumentOutline: true,
		PreferCSSPageSize:       true,
	})
	if err != nil {
		logger.Error().Msgf("Failed to generate PDF from HTML: %v", err)
		return fmt.Errorf("failed to generate PDF: %w", err)
	}

	pdfBytes, err := io.ReadAll(pdfData)
	if err != nil {
		logger.Error().Msgf("Failed to read PDF data stream: %v", err)
		return fmt.Errorf("failed to read PDF data: %w", err)
	}

	err = os.WriteFile(pdfPath, pdfBytes, 0600)
	if err != nil {
		logger.Error().Msgf("Failed to write PDF file to %s: %v", pdfPath, err)
		return fmt.Errorf("failed to write PDF file: %w", err)
	}

	logger.Info().Msgf("PDF report generated successfully: %s", pdfPath)
	return nil
}
