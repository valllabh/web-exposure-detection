package webexposure

import (
	"context"
	"fmt"
	"time"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// RunNucleiScan performs vulnerability scanning using Nuclei v3 SDK
func (s *scanner) RunNucleiScan(targets []string, opts *NucleiOptions) ([]*output.ResultEvent, error) {
	if len(targets) == 0 {
		return []*output.ResultEvent{}, nil
	}
	
	// Notify progress callback if set
	if s.progress != nil {
		s.progress.OnNucleiScanStart(len(targets))
	}
	
	// Create context for Nuclei engine
	ctx := context.Background()
	
	// Create minimal Nuclei engine configuration using modern API
	ne, err := nuclei.NewNucleiEngineCtx(ctx,
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{
			Tags:        opts.IncludeTags,
			ExcludeTags: opts.ExcludeTags,
		}),
		nuclei.WithGlobalRateLimit(30, time.Second), // Fixed rate limit
		nuclei.WithConcurrency(nuclei.Concurrency{
			TemplateConcurrency:           1,  // Minimal concurrency
			HostConcurrency:              1,  // Must be at least 1
			HeadlessHostConcurrency:      1,  // Must be at least 1 for headless
			HeadlessTemplateConcurrency:  1,  // Must be at least 1 for headless templates
			JavascriptTemplateConcurrency: 1, // Must be at least 1 for JS templates
			TemplatePayloadConcurrency:   1,  // Minimal for stability
			ProbeConcurrency:             1,  // Minimal for stability
		}),
		nuclei.EnableStatsWithOpts(nuclei.StatsOptions{
			MetricServerPort: 0, // Disable metrics server
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create nuclei engine: %w", err)
	}
	defer ne.Close()
	
	// Load targets
	ne.LoadTargets(targets, false)
	
	// Template loading happens silently - progress callbacks for UI if needed
	
	// Execute scan with progress tracking
	var results []*output.ResultEvent
	var testCount int
	var currentHost string
	var lastProgressUpdate int
	
	err = ne.ExecuteWithCallback(func(event *output.ResultEvent) {
		if event == nil {
			return
		}
		
		testCount++
		
		// Update current host only when it changes
		if event.Host != currentHost {
			currentHost = event.Host
		}
		
		// Notify progress callback every 25 tests to avoid slowing down processing
		if s.progress != nil && testCount-lastProgressUpdate >= 25 {
			s.progress.OnNucleiScanProgress(currentHost, testCount)
			lastProgressUpdate = testCount
		}
		
		// Only process actual findings (not just test executions)
		if event.TemplateID == "" {
			return
		}
		
		// Store native Nuclei result directly - no conversion needed
		results = append(results, event)
		// Don't print individual findings - keep it clean
	})
	
	if err != nil {
		return nil, fmt.Errorf("nuclei execution failed: %w", err)
	}
	
	// Notify progress callback of completion
	if s.progress != nil {
		s.progress.OnNucleiScanComplete(testCount, len(results))
	}
	
	return results, nil
}

// ExecuteNucleiWithTargets is a helper function to run Nuclei on specific targets
func (s *scanner) ExecuteNucleiWithTargets(targets []string) ([]*output.ResultEvent, error) {
	opts := &NucleiOptions{
		TemplatesPath:       "./scan-templates",
		IncludeTags:         []string{"tech"},
		ExcludeTags:         []string{"ssl"},
		RateLimit:           30,
		BulkSize:            10,
		Concurrency:         5,
		Headless:            false, // Disable headless to reduce resource usage
		OmitTemplate:        true,
		FollowHostRedirects: true,
		ShowMatchLine:       true,
	}
	
	return s.RunNucleiScan(targets, opts)
}