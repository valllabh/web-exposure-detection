package webexposure

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/domain-scan/domain-scan/pkg/domainscan"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"gopkg.in/yaml.v3"
)



// Native Nuclei output.ResultEvent is used directly - no custom struct needed

//go:embed scan-template-meanings.json
var templateMeanings embed.FS



// New creates a new Scanner instance
func New() (Scanner, error) {
	s := &scanner{
		meanings: make(map[string]TemplateMeaning),
	}
	
	// Load meanings from scan-template-meanings.json
	err := s.loadMeanings()
	if err != nil {
		return nil, fmt.Errorf("failed to load template meanings: %w", err)
	}
	
	if len(s.meanings) == 0 {
		return nil, fmt.Errorf("no template meanings loaded from scan-template-meanings.json")
	}
	
	return s, nil
}

// SetProgressCallback sets an optional progress callback for UI updates
func (s *scanner) SetProgressCallback(callback ProgressCallback) {
	s.progress = callback
}

// loadMeanings loads the embedded scan-template-meanings.json file
func (s *scanner) loadMeanings() error {
	data, err := templateMeanings.ReadFile("scan-template-meanings.json")
	if err != nil {
		// File doesn't exist in embed, continue without meanings
		return nil
	}
	
	return json.Unmarshal(data, &s.meanings)
}

// Scan performs the complete scan pipeline
func (s *scanner) Scan(domains []string, keywords []string) error {
	if len(domains) == 0 {
		return fmt.Errorf("no domains provided")
	}
	
	targetDomain := domains[0] // Use first domain as primary target
	
	// Step 1: Domain Discovery
	discoveredDomains, err := s.DiscoverDomains(domains, keywords)
	if err != nil {
		return fmt.Errorf("domain discovery failed: %w", err)
	}
	
	// Step 1.5: Nuclei Options
	nucleiOptions := &NucleiOptions{
		TemplatesPath:       "./scan-templates",
		IncludeTags:         []string{"tech"},
		ExcludeTags:         []string{"ssl"},
		RateLimit:           30,
		BulkSize:            10,
		Concurrency:         5,
		Headless:            true,
		OmitTemplate:        true,
		FollowHostRedirects: true,
		ShowMatchLine:       true,
	}
	
	// Step 1.6: Validate template meanings before starting scan
	if err := s.ValidateTemplateMeanings(nucleiOptions.TemplatesPath); err != nil {
		return fmt.Errorf("template validation failed: %w", err)
	}
	
	// Step 2: Nuclei Scanning
	
	nucleiResults, err := s.RunNucleiScan(discoveredDomains, nucleiOptions)
	if err != nil {
		return fmt.Errorf("nuclei scanning failed: %w", err)
	}
	
	// Step 3: Aggregate Results
	groupedResults, err := s.AggregateResults(nucleiResults)
	if err != nil {
		return fmt.Errorf("result aggregation failed: %w", err)
	}
	
	// Step 4: Generate Report
	report, err := s.GenerateReport(groupedResults, targetDomain)
	if err != nil {
		return fmt.Errorf("report generation failed: %w", err)
	}
	
	// Step 5: Write JSON to reports directory with proper structure
	return s.writeJSONReport(report, targetDomain)
}

// writeJSONReport writes the report to a JSON file with proper organization
func (s *scanner) writeJSONReport(report *ExposureReport, targetDomain string) error {
	// Clean domain name for filesystem use
	cleanDomain := strings.ReplaceAll(targetDomain, ".", "-")
	
	// Create directory structure: ./reports/{first-domain-name}/
	reportsDir := filepath.Join("reports", cleanDomain)
	err := os.MkdirAll(reportsDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create reports directory: %w", err)
	}
	
	// Create filename: {first-domain-name}-web-exposure-report.json
	filename := fmt.Sprintf("%s-web-exposure-report.json", cleanDomain)
	fullPath := filepath.Join(reportsDir, filename)
	
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}
	
	err = os.WriteFile(fullPath, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write report file: %w", err)
	}
	
	// Notify progress callback if set
	if s.progress != nil {
		s.progress.OnReportGenerated(fullPath)
	}
	return nil
}

// DiscoverDomains discovers subdomains using domain-scan
func (s *scanner) DiscoverDomains(domains []string, keywords []string) ([]string, error) {
	// Notify progress callback if set
	if s.progress != nil {
		s.progress.OnDomainDiscoveryStart(domains, keywords)
	}
	
	var allDiscovered []string
	
	// Always include original domains
	allDiscovered = append(allDiscovered, domains...)
	
	// Use domain-scan with controlled comprehensive discovery
	config := domainscan.DefaultConfig()
	// Configure for controlled comprehensive mode with timeout safety
	config.Discovery.MaxSubdomains = 500   // Set reasonable limit to prevent runaway
	config.Discovery.Timeout = 5 * time.Minute  // Reasonable timeout with safety
	config.Discovery.PassiveEnabled = true
	config.Discovery.CertificateEnabled = true  // Keep for security coverage
	config.Discovery.HTTPEnabled = true         // Keep for security coverage
	config.Ports.Default = []int{80, 443, 8080, 8443, 3000, 8000, 8888, 9000}
	domainScanner := domainscan.New(config)
	
	// Create context with timeout for safety
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	
	// Start progress tracking for UI (if callback set)
	done := make(chan bool)
	if s.progress != nil {
		go s.trackDomainScanProgress(done)
	}
	
	// Create controlled comprehensive scan request
	scanReq := &domainscan.ScanRequest{
		Domains:        domains,
		Keywords:       keywords,
		Ports:          []int{80, 443, 8080, 8443, 3000, 8000, 8888, 9000},
		MaxSubdomains:  500,                         // Controlled limit to prevent runaway
		Timeout:        5 * time.Minute,             // Safety timeout
		EnablePassive:  true,
		EnableCertScan: true,                        // Keep for security coverage
		EnableHTTPScan: true,                        // Keep for security coverage
	}
	
	// Run comprehensive domain discovery
	result, err := domainScanner.ScanWithOptions(ctx, scanReq)
	
	// Stop progress tracking
	if s.progress != nil {
		done <- true
		time.Sleep(100 * time.Millisecond) // Give time for cleanup
	}
	
	if err != nil {
		// Return original domains if scan fails
		if s.progress != nil {
			s.progress.OnDomainDiscoveryComplete(len(domains), len(domains), 0)
		}
		return domains, nil
	}
	
	// Extract all discovered subdomains from the result
	allDiscovered = append(allDiscovered, result.Subdomains...)
	
	// Also extract active service URLs and extract domains from them
	for _, service := range result.ActiveServices {
		if service.URL != "" {
			// Extract domain from URL
			// Simple extraction: remove protocol and path
			url := service.URL
			if strings.HasPrefix(url, "http://") {
				url = strings.TrimPrefix(url, "http://")
			} else if strings.HasPrefix(url, "https://") {
				url = strings.TrimPrefix(url, "https://")
			}
			// Remove path and port
			if idx := strings.Index(url, "/"); idx > 0 {
				url = url[:idx]
			}
			if idx := strings.Index(url, ":"); idx > 0 {
				url = url[:idx]
			}
			
			if url != "" && !contains(allDiscovered, url) {
				allDiscovered = append(allDiscovered, url)
			}
		}
	}
	
	// Remove duplicates
	allDiscovered = removeDuplicates(allDiscovered)
	
	// Notify progress callback of completion
	if s.progress != nil {
		s.progress.OnDomainDiscoveryComplete(len(allDiscovered), len(domains), len(allDiscovered)-len(domains))
	}
	
	return allDiscovered, nil
}

// trackDomainScanProgress provides periodic progress updates through callback
func (s *scanner) trackDomainScanProgress(done chan bool) {
	count := 0
	estimatedTotal := 500  // More realistic estimate with new limits
	
	ticker := time.NewTicker(3 * time.Second)  // Less frequent updates
	defer ticker.Stop()
	
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			// Simulate gradual progress discovery for UI feedback
			if count < estimatedTotal {
				count += 25 + (count/20) // Slower, more realistic discovery pattern
				if count > 300 && estimatedTotal < 1000 {
					estimatedTotal = 1000 // Update estimate as we find more (max 1000)
				}
				s.progress.OnDomainDiscoveryProgress(count)
			}
		}
	}
}

// Helper functions for domain processing
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	var result []string
	
	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}
	return result
}

// AggregateResults replicates the jq logic from run-result-aggr.sh
func (s *scanner) AggregateResults(results []*output.ResultEvent) (*GroupedResults, error) {
	grouped := make(map[string]map[string]*output.ResultEvent)
	
	for _, result := range results {
		if grouped[result.Host] == nil {
			grouped[result.Host] = make(map[string]*output.ResultEvent)
		}
		grouped[result.Host][result.TemplateID] = result
	}
	
	return &GroupedResults{Domains: grouped}, nil
}

// Testing helper methods - expose internal methods for testing

func (s *scanner) CountIssues(grouped *GroupedResults, keys []string) int {
	return s.countIssues(grouped, keys)
}

func (s *scanner) NormalizeAndClean(input string) []string {
	return s.normalizeAndClean(input)
}

func (s *scanner) ClassifyAsAPI(templates map[string]*output.ResultEvent) (string, string) {
	return s.classifyAsAPI(templates)
}

func (s *scanner) ClassifyAsWebApp(templates map[string]*output.ResultEvent) (string, string, []string) {
	return s.classifyAsWebApp(templates)
}

func (s *scanner) WriteJSONReport(report *ExposureReport, filename string) error {
	return s.writeJSONReport(report, filename)
}

// ValidateTemplateMeanings checks that all scan templates have corresponding meanings
func (s *scanner) ValidateTemplateMeanings(templatesPath string) error {
	// 1. Discover all template files in scan-templates directory
	templateFiles, err := s.discoverTemplateFiles(templatesPath)
	if err != nil {
		return fmt.Errorf("failed to discover template files in %s: %w", templatesPath, err)
	}
	
	if len(templateFiles) == 0 {
		return fmt.Errorf("no template files found in %s", templatesPath)
	}
	
	// 2. Extract template IDs from each template file
	templateIDs, err := s.extractTemplateIDs(templateFiles)
	if err != nil {
		return fmt.Errorf("failed to extract template IDs: %w", err)
	}
	
	// 3. Check that each template ID has a meaning
	var missingMeanings []string
	for _, templateID := range templateIDs {
		if _, exists := s.meanings[templateID]; !exists {
			missingMeanings = append(missingMeanings, templateID)
		}
	}
	
	// 4. Return error if any meanings are missing
	if len(missingMeanings) > 0 {
		return fmt.Errorf(`
Template validation failed: %d templates missing meanings in scan-template-meanings.json

Missing meanings for:
- %s

Please add meanings for these templates before running scan.
Total templates found: %d
Templates with meanings: %d`,
			len(missingMeanings),
			strings.Join(missingMeanings, "\n- "),
			len(templateIDs),
			len(templateIDs)-len(missingMeanings))
	}
	
	return nil
}

// discoverTemplateFiles finds all template files in the given directory
func (s *scanner) discoverTemplateFiles(templatesPath string) ([]string, error) {
	var templateFiles []string
	
	err := filepath.Walk(templatesPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		// Look for .yaml and .yml files
		if strings.HasSuffix(strings.ToLower(path), ".yaml") || 
		   strings.HasSuffix(strings.ToLower(path), ".yml") {
			templateFiles = append(templateFiles, path)
		}
		
		return nil
	})
	
	return templateFiles, err
}

// extractTemplateIDs extracts template IDs from YAML files
func (s *scanner) extractTemplateIDs(templateFiles []string) ([]string, error) {
	var templateIDs []string
	
	for _, filePath := range templateFiles {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read template file %s: %w", filePath, err)
		}
		
		// Parse YAML to extract template ID
		var template struct {
			ID string `yaml:"id"`
		}
		
		if err := yaml.Unmarshal(data, &template); err != nil {
			// Skip files that aren't valid Nuclei templates
			continue
		}
		
		if template.ID != "" {
			templateIDs = append(templateIDs, template.ID)
		}
	}
	
	return templateIDs, nil
}