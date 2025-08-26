package webexposure

import (
	"strings"
	"text/template"
	"time"

	"github.com/Masterminds/sprig/v3"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
)

// Templates is an array of template strings with DSL support using Go text/template + sprig
type Templates []string

// Process executes all templates with Nuclei ResultEvent as context
func (t Templates) Process(event *output.ResultEvent) []string {
	var results []string

	for _, tmplStr := range t {
		// Create template with Sprig functions
		tmpl, err := template.New("").Funcs(sprig.TxtFuncMap()).Parse(tmplStr)
		if err != nil {
			continue // Skip invalid templates
		}

		// Execute with Nuclei event as context
		var buf strings.Builder
		if err := tmpl.Execute(&buf, event); err != nil {
			continue // Skip failed executions
		}

		if result := strings.TrimSpace(buf.String()); result != "" {
			results = append(results, result)
		}
	}
	return results
}

// TemplateMeaning defines template-based detection and finding generation
type TemplateMeaning struct {
	Label             string    `json:"label"`
	DetectionTemplate Templates `json:"detection_template"`
	FindingTemplate   Templates `json:"finding_template"`
}

// ProgressCallback provides progress updates for long-running operations (optional)
type ProgressCallback interface {
	progress.Progress
	OnDomainDiscoveryStart(domains []string, keywords []string)
	OnDomainDiscoveryProgress(found int)
	OnDomainDiscoveryComplete(total, original, new int)
	OnNucleiScanStart(targets int)
	OnNucleiScanProgress(host string, testsCompleted int)
	OnNucleiScanComplete(testsPerformed, findings int)
	OnReportGenerated(filepath string)
}

// Scanner is the main interface for web exposure detection
type Scanner interface {
	// Complete scan pipeline
	Scan(domains []string, keywords []string) error
	ScanWithOptions(domains []string, keywords []string, templates []string, force bool) error

	// Progress monitoring
	SetProgressCallback(callback ProgressCallback)

	// Individual pipeline steps
	DiscoverDomains(domains []string, keywords []string) ([]string, error)
	RunNucleiScan(targets []string, opts *NucleiOptions) ([]*output.ResultEvent, error)
	AggregateResults(results []*output.ResultEvent) (*GroupedResults, error)
	GenerateReport(grouped *GroupedResults, targetDomain string) (*ExposureReport, error)

	// Template validation
	ValidateTemplateMeanings(templatesPath string) error

	// Testing helpers
	CountIssues(grouped *GroupedResults, keys []string) int
	NormalizeAndClean(input string) []string
	ClassifyAsAPI(templates map[string]*output.ResultEvent) (string, string)
	ClassifyAsWebApp(templates map[string]*output.ResultEvent) (string, string, []string)
	WriteJSONReport(report *ExposureReport, filename string) error
}

// NucleiOptions configures the Nuclei scan
type NucleiOptions struct {
	TemplatesPath       string
	SpecificTemplates   []string
	IncludeTags         []string
	ExcludeTags         []string
	RateLimit           int
	BulkSize            int
	Concurrency         int
	Headless            bool
	OmitTemplate        bool
	FollowHostRedirects bool
	ShowMatchLine       bool
}

// GroupedResults represents Nuclei results grouped by domain and template
type GroupedResults struct {
	Domains map[string]map[string]*output.ResultEvent `json:"domains"`
}

// ExposureReport represents the final JSON report schema V1
type ExposureReport struct {
	SchemaVersion  string                `json:"schema_version"`
	ReportMetadata *ReportMetadata       `json:"report_metadata"`
	Summary        *Summary              `json:"summary"`
	Technologies   *TechnologiesDetected `json:"technologies_detected"`
	APIsFound      []*APIFinding         `json:"apis_found"`
	WebAppsFound   []*WebAppFinding      `json:"web_applications_found"`
}

// ReportMetadata contains report information
type ReportMetadata struct {
	Title        string    `json:"title"`
	Date         string    `json:"date"`
	TargetDomain string    `json:"target_domain"`
	Timestamp    time.Time `json:"timestamp"`
}

// Summary contains aggregated statistics
type Summary struct {
	TotalDomains           int `json:"total_domains"`
	LiveExposedDomains     int `json:"live_exposed_domains"`
	TotalDetections        int `json:"total_detections"`
	APIsFound              int `json:"apis_found"`
	APISpecificationsFound int `json:"api_specifications_found"`
	WebAppsFound           int `json:"web_apps_found"`
	DomainsUsingAPI        int `json:"domains_using_api"`
}

// TechnologiesDetected contains detected technologies
type TechnologiesDetected struct {
	Count        int      `json:"count"`
	Technologies []string `json:"technologies"`
}

// APIFinding represents an API discovery
type APIFinding struct {
	Domain     string `json:"domain"`
	Discovered string `json:"discovered"`
	Findings   string `json:"findings"`
}

// WebAppFinding represents a web application discovery
type WebAppFinding struct {
	Domain       string   `json:"domain"`
	Discovered   string   `json:"discovered"`
	Findings     string   `json:"findings"`
	Technologies []string `json:"technologies,omitempty"`
}

// scanner implements the Scanner interface
type scanner struct {
	meanings map[string]TemplateMeaning // Loaded from scan-template-meanings.json
	progress ProgressCallback           // Optional progress callback
}
