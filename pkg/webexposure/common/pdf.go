package common

// PDFGenerator is an interface for generating PDF files from HTML
type PDFGenerator interface {
	// GeneratePDF converts an HTML file to PDF
	GeneratePDF(htmlPath, pdfPath string) error
}

// PDFGeneratorType represents the type of PDF generator to use
type PDFGeneratorType string

const (
	PDFGeneratorRod        PDFGeneratorType = "rod"        // Default: Go Rod (Chromium)
	PDFGeneratorPlaywright PDFGeneratorType = "playwright" // Playwright Chromium
)
