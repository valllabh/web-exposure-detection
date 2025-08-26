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
}

// Progress interface implementation

func (c *CLIProgressHandler) Stop() {
	fmt.Println("⏹️ Progress stopped.")
}

func (c *CLIProgressHandler) Init(hostCount int64, rulesCount int, requestCount int64) {
	c.hostCount = hostCount
	c.rulesCount = rulesCount
	c.totalRequests = requestCount
	fmt.Printf("🔧 Scan initialized: %d hosts, %d rules, %d requests\n", hostCount, rulesCount, requestCount)
}

func (c *CLIProgressHandler) AddToTotal(delta int64) {
	c.totalRequests += delta
	fmt.Printf("➕ Added %d to total requests. New total: %d\n", delta, c.totalRequests)
}

func (c *CLIProgressHandler) IncrementRequests() {
	c.requestsCount++
	fmt.Printf("➡️ Requests incremented: %d\n", c.requestsCount)
}

func (c *CLIProgressHandler) SetRequests(count uint64) {
	c.requestsCount += count
	fmt.Printf("🔢 Requests set/incremented by %d. Total: %d\n", count, c.requestsCount)
}

func (c *CLIProgressHandler) IncrementMatched() {
	c.matchedCount++
	fmt.Printf("✅ Matched incremented: %d\n", c.matchedCount)
}

func (c *CLIProgressHandler) IncrementErrorsBy(count int64) {
	c.errorCount += count
	fmt.Printf("⚠️ Errors incremented by %d. Total: %d\n", count, c.errorCount)
}

func (c *CLIProgressHandler) IncrementFailedRequestsBy(count int64) {
	c.failedRequests += count
	c.errorCount += count
	fmt.Printf("❌ Failed requests incremented by %d. Total failed: %d, errors: %d\n", count, c.failedRequests, c.errorCount)
}

// NewCLIProgressHandler creates a new CLI progress handler
func NewCLIProgressHandler() *CLIProgressHandler {
	return &CLIProgressHandler{
		realProgressCount: 0,
	}
}

// OnDomainDiscoveryStart implements ProgressCallback
func (c *CLIProgressHandler) OnDomainDiscoveryStart(domains []string, keywords []string) {
	fmt.Printf("🔍 Starting domain discovery for: %v\n", domains)
	if len(keywords) > 0 {
		fmt.Printf("📋 Using keywords: %v\n", keywords)
	}
	fmt.Printf("📡 Running passive subdomain enumeration...\n")

	// Reset progress count for new discovery
	c.realProgressCount = 0
}

// OnDomainDiscoveryProgress implements ProgressCallback
func (c *CLIProgressHandler) OnDomainDiscoveryProgress(found int) {
	// Show actual progress updates
	if found > c.realProgressCount {
		fmt.Printf("   Found %d live domains so far...\n", found)
		c.realProgressCount = found
	}
}

// OnDomainDiscoveryComplete implements ProgressCallback
func (c *CLIProgressHandler) OnDomainDiscoveryComplete(total, original, new int) {
	fmt.Printf("✅ Domain discovery completed\n")
	fmt.Printf("📊 Total: %d domains (%d original + %d newly discovered)\n", total, original, new)
}

// OnNucleiScanStart implements ProgressCallback
func (c *CLIProgressHandler) OnNucleiScanStart(targets int) {
	fmt.Printf("🚀 Starting web exposure scan on %d targets\n", targets)
	fmt.Printf("📝 Loading templates (tech detection, excluding SSL)\n")
	fmt.Printf("🔄 Templates loading and clustering...\n")
	fmt.Printf("✅ Templates loaded successfully\n")
	fmt.Printf("🔍 Beginning exposure detection tests...\n")
}

// OnNucleiScanProgress implements ProgressCallback
func (c *CLIProgressHandler) OnNucleiScanProgress(host string, testsCompleted int) {
	fmt.Printf("🔍 Scanning %s (%d tests completed)\n", host, testsCompleted)
}

// OnNucleiScanComplete implements ProgressCallback
func (c *CLIProgressHandler) OnNucleiScanComplete(testsPerformed, findings int) {
	fmt.Printf("✅ Web exposure scan completed\n")
	fmt.Printf("📊 Tests performed: %d | Findings: %d\n", testsPerformed, findings)
}

// OnReportGenerated implements ProgressCallback
func (c *CLIProgressHandler) OnReportGenerated(filepath string) {
	fmt.Printf("✅ Report generated: %s\n", filepath)
}

// Verify CLIProgressHandler implements ProgressCallback
var _ webexposure.ProgressCallback = (*CLIProgressHandler)(nil)
