package webexposure

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
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

	// Create Nuclei engine configuration with template filtering
	var templateFilters nuclei.TemplateFilters

	// If specific templates are provided, use them instead of tag-based filtering
	if len(opts.SpecificTemplates) > 0 {
		templateFilters = nuclei.TemplateFilters{
			IDs: opts.SpecificTemplates,
		}
	} else {
		// Use default tag-based filtering
		templateFilters = nuclei.TemplateFilters{
			Tags:        opts.IncludeTags,
			ExcludeTags: opts.ExcludeTags,
		}
	}

	ne, err := nuclei.NewNucleiEngineCtx(ctx,
		nuclei.WithTemplateFilters(templateFilters),
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
			Templates: []string{opts.TemplatesPath},
		}),
		nuclei.EnableHeadlessWithOpts(&nuclei.HeadlessOpts{
			PageTimeout: 90, // 90 second timeout for page operations
			ShowBrowser: false,
		}),
		nuclei.WithVerbosity(nuclei.VerbosityOptions{Verbose: false}),
		nuclei.WithGlobalRateLimit(opts.RateLimit, time.Second),
		nuclei.WithConcurrency(nuclei.Concurrency{
			TemplateConcurrency:           opts.Concurrency,
			HostConcurrency:               opts.Concurrency,
			HeadlessHostConcurrency:       1,
			HeadlessTemplateConcurrency:   1,
			JavascriptTemplateConcurrency: 1,
			TemplatePayloadConcurrency:    25,
			ProbeConcurrency:              50,
		}),
		nuclei.WithNetworkConfig(nuclei.NetworkConfig{
			Timeout:           opts.Timeout, // Timeout in seconds
			Retries:           2,
			LeaveDefaultPorts: false,
			DisableMaxHostErr: true, // Disable host error skip optimization to ensure all templates run
		}),
		nuclei.UseStatsWriter(s.progress), // Use CLI progress handler for Nuclei
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create nuclei engine: %w", err)
	}
	defer ne.Close()

	// Normalize targets to ensure proper URLs for headless templates
	normalizedTargets := make([]string, 0, len(targets))
	for _, target := range targets {
		// Clean up target (remove commas, spaces, etc.)
		target = strings.TrimSpace(strings.Trim(target, ","))
		if target == "" {
			continue
		}

		// Add protocol if missing
		if !strings.Contains(target, "://") {
			target = "https://" + target
		}

		normalizedTargets = append(normalizedTargets, target)
	}

	// Load normalized targets
	ne.LoadTargets(normalizedTargets, false)

	// Template loading happens silently - progress callbacks for UI if needed

	// Open progressive results writer if configured
	var progressiveWriter *os.File
	var jsonlWriter *bufio.Writer
	var jsonlMutex sync.Mutex // Protect concurrent writes to jsonlWriter
	var jsonlWriteCount int   // Track writes for periodic flushing
	if opts.ResultsWriter != "" {
		var err error
		progressiveWriter, err = os.Create(opts.ResultsWriter)
		if err != nil {
			return nil, fmt.Errorf("failed to create progressive results file: %w", err)
		}
		defer progressiveWriter.Close()
		// Use larger buffer (1MB) to reduce syscalls for large results
		jsonlWriter = bufio.NewWriterSize(progressiveWriter, 1024*1024)
		defer jsonlWriter.Flush()
	}

	// Execute scan with progress tracking
	var results []*output.ResultEvent
	var resultsMutex sync.Mutex // Protect concurrent appends to results slice
	var testCount int
	var currentHost string
	var lastProgressUpdate int
	var hostStartTimes = make(map[string]time.Time)

	err = ne.ExecuteWithCallback(func(event *output.ResultEvent) {
		if event == nil {
			return
		}

		testCount++

		// Update current host only when it changes and notify progress
		if event.Host != currentHost {
			// Mark completion of previous host if there was one
			if currentHost != "" && s.progress != nil {
				if startTime, exists := hostStartTimes[currentHost]; exists {
					duration := time.Since(startTime)
					fmt.Printf("Completed %s (%v)\n", currentHost, duration.Round(100*time.Millisecond))
				}
			}

			currentHost = event.Host
			hostStartTimes[currentHost] = time.Now()

			if s.progress != nil {
				fmt.Printf("Testing %s\n", currentHost)
			}
		}

		// Notify progress callback every 50 tests to show steady progress
		if s.progress != nil && testCount-lastProgressUpdate >= 50 {
			s.progress.OnNucleiScanProgress(currentHost, testCount)
			lastProgressUpdate = testCount
		}

		// Only process actual findings (not just test executions)
		if event.TemplateID == "" {
			return
		}

		// Store native Nuclei result directly - no conversion needed
		// Protect concurrent appends from multiple goroutines
		resultsMutex.Lock()
		results = append(results, event)
		resultsMutex.Unlock()

		// Write result progressively if writer configured
		if jsonlWriter != nil {
			// Lock mutex to protect concurrent writes from multiple goroutines
			jsonlMutex.Lock()
			defer jsonlMutex.Unlock()

			// Omit template encoding if requested
			if opts.OmitTemplate {
				event.TemplateEncoded = ""
			}

			// Omit response body if requested (can be very large)
			if opts.OmitResponse {
				event.Response = ""
				event.Request = ""
			}

			jsonData, err := json.Marshal(event)
			if err != nil {
				fmt.Printf("⚠️  Warning: Failed to marshal result for %s: %v\n", event.Host, err)
				return // Skip this result
			}

			// Write JSON data
			n, err := jsonlWriter.Write(jsonData)
			if err != nil {
				fmt.Printf("⚠️  Warning: Failed to write result for %s: %v\n", event.Host, err)
				return // Skip this result
			}
			if n != len(jsonData) {
				fmt.Printf("⚠️  Warning: Partial write for %s (%d/%d bytes)\n", event.Host, n, len(jsonData))
				return // Skip this result
			}

			// Write newline
			if _, err := jsonlWriter.WriteString("\n"); err != nil {
				fmt.Printf("⚠️  Warning: Failed to write newline for %s: %v\n", event.Host, err)
				return // Skip this result
			}

			// Flush every 10 writes to balance real-time visibility with performance
			// This reduces disk I/O while maintaining reasonable update frequency
			jsonlWriteCount++
			if jsonlWriteCount%10 == 0 {
				if err := jsonlWriter.Flush(); err != nil {
					fmt.Printf("⚠️  Warning: Failed to flush for %s: %v\n", event.Host, err)
				}
			}
		}

		// Show findings as they're discovered
		if s.progress != nil {
			fmt.Printf("Found: %s on %s\n", event.Info.Name, event.Host)
		}
	})

	if err != nil {
		return nil, fmt.Errorf("nuclei execution failed: %w", err)
	}

	// Mark completion of final host
	if currentHost != "" && s.progress != nil {
		if startTime, exists := hostStartTimes[currentHost]; exists {
			duration := time.Since(startTime)
			fmt.Printf("Completed %s (%v)\n", currentHost, duration.Round(100*time.Millisecond))
		}
	}

	// Notify progress callback of completion
	if s.progress != nil {
		s.progress.OnNucleiScanComplete(testCount, len(results))
	}

	return results, nil
}
