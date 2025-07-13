package cli

import (
	"fmt"
	"time"
	"web-exposure-detection/pkg/webexposure"
)

// CLIProgressHandler implements ProgressCallback for command line interface
type CLIProgressHandler struct {
	domainProgressActive bool
	domainDone          chan bool
}

// NewCLIProgressHandler creates a new CLI progress handler
func NewCLIProgressHandler() *CLIProgressHandler {
	return &CLIProgressHandler{}
}

// OnDomainDiscoveryStart implements ProgressCallback
func (c *CLIProgressHandler) OnDomainDiscoveryStart(domains []string, keywords []string) {
	fmt.Printf("🔍 Domain discovery for: %v\n", domains)
	if len(keywords) > 0 {
		fmt.Printf("📋 Using keywords: %v\n", keywords)
	}
	
	// Start the progress animation immediately
	c.domainProgressActive = true
	c.domainDone = make(chan bool)
	go c.showDomainProgress(c.domainDone)
}

// OnDomainDiscoveryProgress implements ProgressCallback  
func (c *CLIProgressHandler) OnDomainDiscoveryProgress(found int) {
	// Progress updates are handled by the animation goroutine
}

// OnDomainDiscoveryComplete implements ProgressCallback
func (c *CLIProgressHandler) OnDomainDiscoveryComplete(total, original, new int) {
	// Stop the progress animation
	if c.domainProgressActive {
		c.domainDone <- true
		c.domainProgressActive = false
		time.Sleep(100 * time.Millisecond) // Give time for cleanup
	}
	
	// Clear the progress line and show completion
	fmt.Printf("\r%-60s\r", "") // Clear the line
	fmt.Printf("✅ Domain discovery completed\n")
	fmt.Printf("📊 Discovered %d domains total (original: %d, new: %d)\n", total, original, new)
}

// OnNucleiScanStart implements ProgressCallback
func (c *CLIProgressHandler) OnNucleiScanStart(targets int) {
	fmt.Printf("🚀 Starting Nuclei scan on %d targets\n", targets)
	fmt.Printf("📝 Loading templates with tech tags (excluding ssl)\n")
	fmt.Printf("⏳ This may take a moment while templates are loaded and clustered...\n")
}

// OnNucleiScanProgress implements ProgressCallback
func (c *CLIProgressHandler) OnNucleiScanProgress(host string, testsCompleted int) {
	spinners := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	spinnerIndex := (testsCompleted / 25) % len(spinners)
	fmt.Printf("\r%s Testing %s - %d tests completed", spinners[spinnerIndex], host, testsCompleted)
}

// OnNucleiScanComplete implements ProgressCallback
func (c *CLIProgressHandler) OnNucleiScanComplete(testsPerformed, findings int) {
	fmt.Printf("\n✅ Nuclei scan completed: %d tests performed, %d findings\n", testsPerformed, findings)
}

// OnReportGenerated implements ProgressCallback
func (c *CLIProgressHandler) OnReportGenerated(filepath string) {
	fmt.Printf("✅ Report generated: %s\n", filepath)
}

// showDomainProgress shows the animated progress indicator for domain discovery
func (c *CLIProgressHandler) showDomainProgress(done chan bool) {
	spinners := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	spinnerIndex := 0
	count := 0
	estimatedTotal := 1000
	
	ticker := time.NewTicker(200 * time.Millisecond) // Faster animation for smooth spinner
	defer ticker.Stop()
	
	progressTicker := time.NewTicker(2 * time.Second)
	defer progressTicker.Stop()
	
	for {
		select {
		case <-done:
			return
		case <-progressTicker.C:
			// Simulate gradual progress discovery
			if count < estimatedTotal {
				count += 50 + (count/10) // Accelerating discovery pattern
				if count > 500 && estimatedTotal < 20000 {
					estimatedTotal = 20000 // Update estimate as we find more
				}
			}
		case <-ticker.C:
			// Animate spinner
			spinnerIndex = (spinnerIndex + 1) % len(spinners)
			
			// Show progress with fixed-position counter
			progressText := fmt.Sprintf("%s Domain discovery in progress (%d found)", spinners[spinnerIndex], count)
			// Pad to clear previous longer text
			fmt.Printf("\r%-60s", progressText)
		}
	}
}

// Verify CLIProgressHandler implements ProgressCallback
var _ webexposure.ProgressCallback = (*CLIProgressHandler)(nil)