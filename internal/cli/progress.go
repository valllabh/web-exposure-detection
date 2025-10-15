package cli

import (
	"fmt"
	"web-exposure-detection/pkg/webexposure"
)

// CLIProgressHandler implements ProgressCallback for command line interface
type CLIProgressHandler struct {
	realProgressCount int
	requestsCount     uint64
	matchedCount      uint64
	errorCount        int64
	failedRequests    int64
	totalRequests     int64
	hostCount         int64
	rulesCount        int
	verbose           bool
}

// Progress interface implementation

func (c *CLIProgressHandler) Stop() {
	// Silent - no output
}

func (c *CLIProgressHandler) Init(hostCount int64, rulesCount int, requestCount int64) {
	c.hostCount = hostCount
	c.rulesCount = rulesCount
	c.totalRequests = requestCount
	// Silent - no output during init
}

func (c *CLIProgressHandler) AddToTotal(delta int64) {
	c.totalRequests += delta
	// Silent - no output during add
}

func (c *CLIProgressHandler) IncrementRequests() {
	c.requestsCount++
	if c.verbose && c.requestsCount%10 == 0 {
		fmt.Printf("  Requests: %d\n", c.requestsCount)
	}
}

func (c *CLIProgressHandler) SetRequests(count uint64) {
	c.requestsCount += count
	// Silent - no output during set
}

func (c *CLIProgressHandler) IncrementMatched() {
	c.matchedCount++
	if c.verbose {
		fmt.Printf("  Matches: %d\n", c.matchedCount)
	}
}

func (c *CLIProgressHandler) IncrementErrorsBy(count int64) {
	c.errorCount += count
	if c.verbose && count > 0 {
		fmt.Printf("  Errors: %d (total: %d)\n", count, c.errorCount)
	}
}

func (c *CLIProgressHandler) IncrementFailedRequestsBy(count int64) {
	c.failedRequests += count
	c.errorCount += count
	if c.verbose && count > 0 {
		fmt.Printf("  Failed requests: %d (total: %d)\n", count, c.failedRequests)
	}
}

// NewCLIProgressHandler creates a new CLI progress handler
func NewCLIProgressHandler(verbose bool) *CLIProgressHandler {
	return &CLIProgressHandler{
		realProgressCount: 0,
		verbose:           verbose,
	}
}

// OnDomainDiscoveryStart implements ProgressCallback
func (c *CLIProgressHandler) OnDomainDiscoveryStart(domains []string, keywords []string) {
	fmt.Printf("Starting domain discovery for: %v\n", domains)
	if len(keywords) > 0 {
		fmt.Printf("Using keywords: %v\n", keywords)
	}
	fmt.Printf("Running subdomain enumeration...\n")

	// Reset progress count for new discovery
	c.realProgressCount = 0
}

// OnDomainDiscoveryProgress implements ProgressCallback
func (c *CLIProgressHandler) OnDomainDiscoveryProgress(found int) {
	// Show actual progress updates
	if found > c.realProgressCount {
		fmt.Printf("Found %d live domains\n", found)
		c.realProgressCount = found
	}
}

// OnDomainDiscoveryComplete implements ProgressCallback
func (c *CLIProgressHandler) OnDomainDiscoveryComplete(total, original, new int) {
	fmt.Printf("Domain discovery completed\n")
	fmt.Printf("Total: %d domains (%d original + %d newly discovered)\n", total, original, new)
}

// OnNucleiScanStart implements ProgressCallback
func (c *CLIProgressHandler) OnNucleiScanStart(targets int) {
	fmt.Printf("Starting vulnerability scan on %d targets\n", targets)
	fmt.Printf("Loading templates...\n")
}

// OnNucleiScanProgress implements ProgressCallback
func (c *CLIProgressHandler) OnNucleiScanProgress(host string, testsCompleted int) {
	if c.verbose {
		// Verbose mode - show every 50 tests
		if testsCompleted%50 == 0 {
			fmt.Printf("Scanning %s (%d tests)\n", host, testsCompleted)
		}
	} else {
		// Normal mode - show every 100 tests
		if testsCompleted%100 == 0 {
			fmt.Printf("Scanning %s (%d tests)\n", host, testsCompleted)
		}
	}
}

// OnNucleiScanComplete implements ProgressCallback
func (c *CLIProgressHandler) OnNucleiScanComplete(testsPerformed, findings int) {
	fmt.Printf("Scan completed - %d tests, %d findings\n", testsPerformed, findings)
}

// OnReportGenerated implements ProgressCallback
func (c *CLIProgressHandler) OnReportGenerated(filepath string) {
	fmt.Printf("Report generated: %s\n", filepath)
}

// Verify CLIProgressHandler implements ProgressCallback
var _ webexposure.ProgressCallback = (*CLIProgressHandler)(nil)
