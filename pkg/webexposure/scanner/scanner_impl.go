package scanner

import (
	"github.com/valllabh/domain-scan/pkg/domainscan"

	"web-exposure-detection/pkg/webexposure/industry"
	"web-exposure-detection/pkg/webexposure/common"
)

// scanner implements the common.Scanner interface
type scanner struct {
	progress                common.ProgressCallback                // Optional progress callback
	debug                   bool                                  // Debug mode - skips HTML cleanup when enabled
	silent                  bool                                  // Silent mode - suppresses info messages
	industryClassification  *industry.IndustryClassification      // Industry classification result
	pdfGenerator            common.PDFGenerator                    // PDF generator implementation (rod or playwright)
	lastDiscoveryResult     *domainscan.AssetDiscoveryResult      // Last discovery result for metrics calculation
}

// generatePDF generates a PDF from HTML file
func (s *scanner) generatePDF(htmlPath, pdfPath string) error {
	return s.pdfGenerator.GeneratePDF(htmlPath, pdfPath)
}
