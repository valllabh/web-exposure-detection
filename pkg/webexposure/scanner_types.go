package webexposure

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/valllabh/domain-scan/pkg/domainscan"
)

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
	ScanWithPreset(domains []string, keywords []string, templates []string, force bool, preset ScanPreset, skipDiscovery bool) error

	// Report generation
	GenerateReportFromExistingResults(domains []string, debug bool) error

	// Domain discovery only
	RunDiscoveryOnly(domains []string, keywords []string, force bool) error

	// Progress monitoring
	SetProgressCallback(callback ProgressCallback)
	SetDebug(debug bool)
	SetSilent(silent bool)

	// Individual pipeline steps
	DiscoverDomains(domains []string, keywords []string) ([]string, error)
	RunNucleiScan(targets []string, opts *NucleiOptions) ([]*output.ResultEvent, error)

	// Enhanced methods that preserve protocol information
	DiscoverDomainsWithProtocol(domains []string, keywords []string) (map[string]*domainscan.DomainEntry, error)
	RunNucleiScanWithProtocol(targets map[string]*domainscan.DomainEntry, opts *NucleiOptions) ([]*output.ResultEvent, error)
	AggregateResults(results []*output.ResultEvent) (*GroupedResults, error)
	GenerateReport(grouped *GroupedResults, targetDomain string) (*ExposureReport, error)

	// Testing helpers
	CountIssues(grouped *GroupedResults, keys []string) int
	NormalizeAndClean(input string) []string
	WriteJSONReport(report *ExposureReport, filename string) error
}

// ScanPreset defines scan speed/aggressiveness presets
type ScanPreset string

const (
	PresetSlow ScanPreset = "slow" // Default: Conservative, stable
	PresetFast ScanPreset = "fast" // Aggressive: Faster but may be less stable
)

// scanner implements the Scanner interface
type scanner struct {
	progress ProgressCallback // Optional progress callback
	debug    bool             // Debug mode - skips HTML cleanup when enabled
	silent   bool             // Silent mode - suppresses info messages
}
