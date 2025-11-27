package webexposure

import (
	"web-exposure-detection/pkg/webexposure/common"
	"web-exposure-detection/pkg/webexposure/criticality"
	"web-exposure-detection/pkg/webexposure/findings"
	"web-exposure-detection/pkg/webexposure/industry"
	"web-exposure-detection/pkg/webexposure/nuclei"
	"web-exposure-detection/pkg/webexposure/report"
	"web-exposure-detection/pkg/webexposure/scanner"
	"web-exposure-detection/pkg/webexposure/truinsights"
)

// Re-export types from subpackages for easier access

// Scanner types
type (
	Scanner          = common.Scanner
	ProgressCallback = common.ProgressCallback
	ScanPreset       = common.ScanPreset
)

// Scanner constants
const (
	PresetSlow = common.PresetSlow
	PresetFast = common.PresetFast
)

// Nuclei types
type (
	NucleiOptions  = nuclei.NucleiOptions
	GroupedResults = nuclei.GroupedResults
	StoredResult   = nuclei.StoredResult
)

// Report types
type (
	ExposureReport = common.ExposureReport
	ReportMetadata = common.ReportMetadata
	Summary        = common.Summary
	Discovery      = findings.Discovery
	APIFinding     = findings.APIFinding
	WebAppFinding  = findings.WebAppFinding
	DomainMetrics  = common.DomainMetrics
)

// Findings types
type FindingItem = findings.FindingItem

// Criticality types (moved to findings package)
type (
	Criticality             = findings.Criticality
	CriticalityFactor       = findings.CriticalityFactor
	CriticalityDistribution = findings.CriticalityDistribution
)

// Industry types
type (
	IndustryClassification = industry.IndustryClassification
	IndustryClassifier     = industry.IndustryClassifier
)

// TRU Insights types
type (
	TRUInsightsResult    = truinsights.TRUInsightsResult
	TRUInsightsGenerator = truinsights.Generator
)

// PDF types
type (
	PDFGenerator     = common.PDFGenerator
	PDFGeneratorType = common.PDFGeneratorType
)

// PDF constants
const (
	PDFGeneratorRod        = common.PDFGeneratorRod
	PDFGeneratorPlaywright = common.PDFGeneratorPlaywright
)

// Re-export key functions

// Scanner functions
var (
	New                 = scanner.New
	NewWithPDFGenerator = scanner.NewWithPDFGenerator
)

// Findings functions
var NewFindingItem = findings.NewFindingItem

// Criticality functions
var (
	CalculateCriticality = criticality.CalculateCriticality
	NewCriticalityFactor = findings.NewCriticalityFactor
)

// Industry functions (only cached version exposed)
var (
	ClassifyDomainIndustryWithCache = industry.ClassifyDomainIndustryWithCache
)

// TRU Insights functions
var (
	NewTRUInsightsGenerator = truinsights.NewGenerator
)

// PDF functions
var NewPDFGenerator = report.NewPDFGenerator

// DSL package auto-registers functions on import via init()
// No exported functions needed - just import _ "web-exposure-detection/pkg/webexposure/nuclei"

// GenerateTRUInsights generates TRU insights for a domain with caching
func GenerateTRUInsights(domain string, force bool) (*TRUInsightsResult, error) {
	return GenerateTRUInsightsWithDebug(domain, force, false)
}

// GenerateTRUInsightsWithDebug generates TRU insights with optional debug mode
func GenerateTRUInsightsWithDebug(domain string, force bool, debug bool) (*TRUInsightsResult, error) {
	generator, err := truinsights.NewGenerator()
	if err != nil {
		return nil, err
	}
	return generator.GenerateWithDebug(domain, force, debug)
}
