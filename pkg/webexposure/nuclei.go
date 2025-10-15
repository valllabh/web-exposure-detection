package webexposure

import (
	"context"
	"fmt"
	"strings"
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
		nuclei.WithVerbosity(nuclei.VerbosityOptions{Verbose: opts.Verbose}),
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

	// Execute scan with callback handling (result processing delegated to nuclei_results.go)
	return ExecuteNucleiScanWithCallback(ne, opts, s.progress)
}
