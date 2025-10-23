package cli

import (
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
	if c.requestsCount%10 == 0 {
		webexposure.GetLogger().Debug().Msgf("Requests: %d", c.requestsCount)
	}
}

func (c *CLIProgressHandler) SetRequests(count uint64) {
	c.requestsCount += count
	// Silent - no output during set
}

func (c *CLIProgressHandler) IncrementMatched() {
	c.matchedCount++
	webexposure.GetLogger().Debug().Msgf("Matches: %d", c.matchedCount)
}

func (c *CLIProgressHandler) IncrementErrorsBy(count int64) {
	c.errorCount += count
	if count > 0 {
		webexposure.GetLogger().Warning().Msgf("Errors: %d (total: %d)", count, c.errorCount)
	}
}

func (c *CLIProgressHandler) IncrementFailedRequestsBy(count int64) {
	c.failedRequests += count
	c.errorCount += count
	if count > 0 {
		webexposure.GetLogger().Warning().Msgf("Failed requests: %d (total: %d)", count, c.failedRequests)
	}
}

// NewCLIProgressHandler creates a new CLI progress handler
func NewCLIProgressHandler() *CLIProgressHandler {
	return &CLIProgressHandler{
		realProgressCount: 0,
	}
}

// OnDomainDiscoveryStart implements ProgressCallback
func (c *CLIProgressHandler) OnDomainDiscoveryStart(domains []string, keywords []string) {
	logger := webexposure.GetLogger()
	logger.Info().Msgf("Starting domain discovery for: %v", domains)
	if len(keywords) > 0 {
		logger.Info().Msgf("Using keywords: %v", keywords)
	}
	logger.Info().Msg("Running subdomain enumeration...")

	// Reset progress count for new discovery
	c.realProgressCount = 0
}

// OnDomainDiscoveryProgress implements ProgressCallback
func (c *CLIProgressHandler) OnDomainDiscoveryProgress(found int) {
	// Show actual progress updates
	if found > c.realProgressCount {
		webexposure.GetLogger().Info().Msgf("Found %d live domains", found)
		c.realProgressCount = found
	}
}

// OnDomainDiscoveryComplete implements ProgressCallback
func (c *CLIProgressHandler) OnDomainDiscoveryComplete(total, original, new int) {
	logger := webexposure.GetLogger()
	logger.Info().Msg("Domain discovery completed")
	logger.Info().Msgf("Total: %d domains (%d original + %d newly discovered)", total, original, new)
}

// OnNucleiScanStart implements ProgressCallback
func (c *CLIProgressHandler) OnNucleiScanStart(targets int) {
	logger := webexposure.GetLogger()
	logger.Info().Msgf("Starting vulnerability scan on %d targets", targets)
	logger.Info().Msg("Loading templates...")
}

// OnNucleiScanProgress implements ProgressCallback
func (c *CLIProgressHandler) OnNucleiScanProgress(host string, testsCompleted int) {
	// Show every 100 tests
	if testsCompleted%100 == 0 {
		webexposure.GetLogger().Info().Msgf("Scanning %s (%d tests)", host, testsCompleted)
	}
}

// OnNucleiScanComplete implements ProgressCallback
func (c *CLIProgressHandler) OnNucleiScanComplete(testsPerformed, findings int) {
	webexposure.GetLogger().Info().Msgf("Scan completed - %d tests, %d findings", testsPerformed, findings)
}

// OnReportGenerated implements ProgressCallback
func (c *CLIProgressHandler) OnReportGenerated(filepath string) {
	webexposure.GetLogger().Info().Msgf("Report generated: %s", filepath)
}

// Verify CLIProgressHandler implements ProgressCallback
var _ webexposure.ProgressCallback = (*CLIProgressHandler)(nil)
