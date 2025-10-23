package report

import "web-exposure-detection/pkg/webexposure/common"

// NewPDFGenerator creates a PDF generator based on type
func NewPDFGenerator(generatorType common.PDFGeneratorType) common.PDFGenerator {
	switch generatorType {
	case common.PDFGeneratorPlaywright:
		return NewPlaywrightPDFGenerator()
	default:
		return NewRodPDFGenerator()
	}
}
