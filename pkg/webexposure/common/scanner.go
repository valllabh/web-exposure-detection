package common

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/valllabh/domain-scan/pkg/domainscan"

	"web-exposure-detection/pkg/webexposure/nuclei"
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
	ScanWithPreset(domains []string, keywords []string, templates []string, force bool, preset ScanPreset, skipDiscoveryAll bool, skipDiscoveryPassive bool, skipDiscoveryCertificate bool) error

	// Report generation
	GenerateReportFromExistingResults(domains []string, debug bool) error

	// Domain discovery only
	RunDiscoveryOnly(domains []string, keywords []string, force bool) error

	// Progress monitoring
	SetProgressCallback(callback ProgressCallback)
	SetDebug(debug bool)
	SetSilent(silent bool)

	// Individual pipeline steps (all internal steps use caching where applicable)
	RunNucleiScan(targets []string, opts *nuclei.NucleiOptions) ([]*output.ResultEvent, error)
	RunNucleiScanWithProtocol(targets map[string]*domainscan.DomainEntry, opts *nuclei.NucleiOptions) ([]*output.ResultEvent, error)
	AggregateResults(results []*output.ResultEvent) (*nuclei.GroupedResults, error)

	// Testing helpers
	CountIssues(grouped *nuclei.GroupedResults, keys []string) int
	NormalizeAndClean(input string) []string
	WriteJSONReport(report *ExposureReport, filename string) error
}

// ScanPreset defines scan speed/aggressiveness presets
type ScanPreset string

const (
	PresetSlow ScanPreset = "slow" // Default: Conservative, stable
	PresetFast ScanPreset = "fast" // Aggressive: Faster but may be less stable
)
