package webexposure

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

// generatePDF generates a PDF from HTML using rod library
func (s *scanner) generatePDF(htmlPath, pdfPath string) error {
	launcher := launcher.New().Headless(true)
	defer launcher.Cleanup()
	url := launcher.MustLaunch()
	browser := rod.New().ControlURL(url).MustConnect()
	defer browser.MustClose()

	absPath, err := filepath.Abs(htmlPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	fileURL := "file://" + absPath
	page := browser.MustPage(fileURL)
	defer page.MustClose()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	page = page.Context(ctx)
	page.MustWaitLoad()

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
		return fmt.Errorf("failed to generate PDF: %w", err)
	}

	pdfBytes, err := io.ReadAll(pdfData)
	if err != nil {
		return fmt.Errorf("failed to read PDF data: %w", err)
	}

	err = os.WriteFile(pdfPath, pdfBytes, 0644)
	if err != nil {
		return fmt.Errorf("failed to write PDF file: %w", err)
	}

	return nil
}
