package webexposure

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/valllabh/domain-scan/pkg/domainscan"
	"gopkg.in/yaml.v3"
)

// cleanDomainName cleans and normalizes domain names
func cleanDomainName(domain string) string {
	// Remove all invalid characters and normalize
	cleaned := strings.ToLower(strings.TrimSpace(domain))

	// Remove common invalid characters that might be included
	cleaned = strings.ReplaceAll(cleaned, ",", "")
	cleaned = strings.ReplaceAll(cleaned, ";", "")
	cleaned = strings.ReplaceAll(cleaned, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "\t", "")
	cleaned = strings.ReplaceAll(cleaned, "\n", "")
	cleaned = strings.ReplaceAll(cleaned, "\r", "")

	// Remove quotes if present
	cleaned = strings.Trim(cleaned, `"'`)

	// Remove protocol if present
	if strings.HasPrefix(cleaned, "http://") {
		cleaned = strings.TrimPrefix(cleaned, "http://")
	} else if strings.HasPrefix(cleaned, "https://") {
		cleaned = strings.TrimPrefix(cleaned, "https://")
	}

	// Remove trailing slashes and paths
	if idx := strings.Index(cleaned, "/"); idx > 0 {
		cleaned = cleaned[:idx]
	}

	return cleaned
}

// Native Nuclei output.ResultEvent is used directly - no custom struct needed

// domainScanProgressAdapter adapts domain-scan SDK progress callbacks to web-exposure-detection progress interface
type domainScanProgressAdapter struct {
	webExposureProgress ProgressCallback
}

// OnStart implements domain-scan ProgressCallback interface
func (a *domainScanProgressAdapter) OnStart(domains []string, keywords []string) {
	a.webExposureProgress.OnDomainDiscoveryStart(domains, keywords)
}

// OnProgress implements domain-scan ProgressCallback interface
func (a *domainScanProgressAdapter) OnProgress(totalDomains, liveDomains int) {
	// Report the actual number of live domains found so far
	a.webExposureProgress.OnDomainDiscoveryProgress(liveDomains)
}

// OnEnd implements domain-scan ProgressCallback interface
func (a *domainScanProgressAdapter) OnEnd(result *domainscan.AssetDiscoveryResult) {
	// Final progress update will be handled in DiscoverDomains function
	// when we process the final results
}

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

// Scan performs the complete scan pipeline with default options (no force)
func (s *scanner) Scan(domains []string, keywords []string) error {
	return s.ScanWithOptions(domains, keywords, []string{}, false)
}

// ScanWithOptions performs the complete scan pipeline with caching support
func (s *scanner) ScanWithOptions(domains []string, keywords []string, templates []string, force bool) error {
	if len(domains) == 0 {
		return fmt.Errorf("no domains provided")
	}

	// Step 0: Clean and normalize all input domains
	var normalizedDomains []string
	for _, domain := range domains {
		cleaned := cleanDomainName(domain)
		if cleaned != "" {
			normalizedDomains = append(normalizedDomains, cleaned)
		}
	}

	if len(normalizedDomains) == 0 {
		return fmt.Errorf("no valid domains provided after cleaning")
	}

	// Step 1: Validate specific templates early to fail fast
	if len(templates) > 0 {
		if err := s.validateSpecificTemplates(templates, "./scan-templates"); err != nil {
			return fmt.Errorf("template validation failed: %w", err)
		}
	}

	targetDomain := normalizedDomains[0] // Use first domain as primary target

	// Create results directory structure
	resultsDir := filepath.Join("results", targetDomain)
	err := os.MkdirAll(resultsDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create results directory: %w", err)
	}

	// Step 2: Domain Discovery with caching (using original method for now)
	discoveredURLs, err := s.discoverDomainsWithCache(normalizedDomains, keywords, resultsDir, force)
	if err != nil {
		return fmt.Errorf("domain discovery failed: %w", err)
	}

	// Step 1.5: Nuclei Options
	nucleiOptions := &NucleiOptions{
		TemplatesPath:       "./scan-templates",
		SpecificTemplates:   templates,
		IncludeTags:         []string{},
		ExcludeTags:         []string{"ssl"},
		RateLimit:           15, // Reduced rate limit for slower requests
		BulkSize:            5,  // Reduced bulk size
		Concurrency:         3,  // Reduced concurrency for more stability
		Headless:            true,
		OmitTemplate:        true,
		FollowHostRedirects: true,
		ShowMatchLine:       true,
		Timeout:             60, // 60 second timeout per request (increased for headless)
		Delay:               2,  // 2 second delay between requests
	}

	// Step 1.6: Validate template meanings before starting scan
	if err := s.ValidateTemplateMeanings(nucleiOptions.TemplatesPath); err != nil {
		return fmt.Errorf("template validation failed: %w", err)
	}

	// Step 2: Nuclei Scanning with result storage
	nucleiResults, err := s.runNucleiScanWithStorage(discoveredURLs, nucleiOptions, resultsDir)
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

	// Step 5: Write JSON to results directory
	return s.writeJSONToResults(report, resultsDir)
}

// GenerateReportFromExistingResults regenerates report from existing Nuclei results
func (s *scanner) GenerateReportFromExistingResults(domains []string) error {
	if len(domains) == 0 {
		return fmt.Errorf("no domains provided")
	}

	// Step 0: Clean and normalize all input domains (same as ScanWithOptions)
	var normalizedDomains []string
	for _, domain := range domains {
		cleaned := cleanDomainName(domain)
		if cleaned != "" {
			normalizedDomains = append(normalizedDomains, cleaned)
		}
	}

	if len(normalizedDomains) == 0 {
		return fmt.Errorf("no valid domains provided after cleaning")
	}

	targetDomain := normalizedDomains[0] // Use first domain as primary target

	// Create results directory structure (same as ScanWithOptions)
	resultsDir := filepath.Join("results", targetDomain)
	err := os.MkdirAll(resultsDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create results directory: %w", err)
	}

	// Step 1.5: Validate template meanings
	nucleiOptions := &NucleiOptions{
		TemplatesPath: "./scan-templates",
	}
	if err := s.ValidateTemplateMeanings(nucleiOptions.TemplatesPath); err != nil {
		return fmt.Errorf("template validation failed: %w", err)
	}

	// Step 2: Load existing Nuclei results
	nucleiResults, err := s.loadExistingNucleiResults(resultsDir)
	if err != nil {
		return fmt.Errorf("failed to load existing nuclei results: %w", err)
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

	// Step 5: Write JSON to results directory
	err = s.writeJSONToResults(report, resultsDir)
	if err != nil {
		return err
	}

	// Step 6: Generate HTML report
	err = s.generateHTMLReport(report, resultsDir)
	if err != nil {
		// Log warning but don't fail the entire report generation
		fmt.Printf("⚠️  Warning: Failed to generate HTML report: %v\n", err)
	} else {
		// Step 7: Generate PDF from HTML
		htmlPath := filepath.Join(resultsDir, "report", "index.html")
		pdfPath := filepath.Join(resultsDir, report.ReportMetadata.TargetDomain+"-web-exposure-report.pdf")

		err = s.generatePDF(htmlPath, pdfPath)
		if err != nil {
			// Log warning but don't fail the entire report generation
			fmt.Printf("⚠️  Warning: Failed to generate PDF report: %v\n", err)
		}
	}

	return nil
}

// writeJSONReport writes the report to a JSON file with proper organization
func (s *scanner) writeJSONReport(report *ExposureReport, targetDomain string) error {
	// Create directory structure: ./reports/{first-domain-name}/
	reportsDir := filepath.Join("reports", targetDomain)
	err := os.MkdirAll(reportsDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create reports directory: %w", err)
	}

	// Create filename: {first-domain-name}-web-exposure-report.json
	filename := fmt.Sprintf("%s-web-exposure-report.json", targetDomain)
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

// DiscoverDomains discovers subdomains using domain-scan SDK
func (s *scanner) DiscoverDomains(domains []string, keywords []string) ([]string, error) {
	// Notify progress callback if set
	if s.progress != nil {
		s.progress.OnDomainDiscoveryStart(domains, keywords)
	}

	var allDiscovered []string

	// Convert original domains to HTTPS URLs (default assumption)
	for _, domain := range domains {
		// Try HTTPS first for original domains
		httpsURL := "https://" + domain
		allDiscovered = append(allDiscovered, httpsURL)
	}

	// Use domain-scan SDK with controlled comprehensive discovery
	config := domainscan.DefaultConfig()
	// Configure for controlled comprehensive mode with timeout safety
	config.Discovery.Timeout = 5 * time.Minute
	config.Keywords = keywords

	domainScanner := domainscan.New(config)

	// Set up real progress tracking from domain-scan SDK
	if s.progress != nil {
		domainScanner.SetProgressCallback(&domainScanProgressAdapter{
			webExposureProgress: s.progress,
		})
	}

	// Create context with timeout for safety
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	// Create controlled comprehensive scan request
	scanReq := &domainscan.ScanRequest{
		Domains:  domains,
		Keywords: keywords,
		Timeout:  5 * time.Minute,
	}

	// Run comprehensive domain discovery with real progress tracking
	result, err := domainScanner.ScanWithOptions(ctx, scanReq)

	if err != nil {
		// Return original domains as HTTPS URLs if scan fails
		if s.progress != nil {
			s.progress.OnDomainDiscoveryComplete(len(allDiscovered), len(domains), 0)
		}
		return allDiscovered, nil
	}

	// Track seen clean domains to avoid duplicates
	seenDomains := make(map[string]bool)
	for _, url := range allDiscovered {
		clean := extractDomainFromURL(url)
		seenDomains[clean] = true
	}

	// Extract all discovered domains from the result with protocol information
	for domainURL, entry := range result.Domains {
		if entry.IsLive {
			// Extract clean domain for deduplication check
			cleanDomain := extractDomainFromURL(domainURL)
			if cleanDomain != "" && !seenDomains[cleanDomain] {
				// Use the full URL with protocol from domain-scan
				allDiscovered = append(allDiscovered, domainURL)
				seenDomains[cleanDomain] = true
			}
		}
	}

	// Notify progress callback of completion
	if s.progress != nil {
		s.progress.OnDomainDiscoveryComplete(len(allDiscovered), len(domains), len(allDiscovered)-len(domains))
	}

	return allDiscovered, nil
}

// DiscoverDomainsWithProtocol performs domain discovery preserving protocol information
func (s *scanner) DiscoverDomainsWithProtocol(domains []string, keywords []string) (map[string]*domainscan.DomainEntry, error) {
	// Notify progress callback if set
	if s.progress != nil {
		s.progress.OnDomainDiscoveryStart(domains, keywords)
	}

	// Use domain-scan SDK with controlled comprehensive discovery
	config := domainscan.DefaultConfig()
	config.Discovery.Timeout = 5 * time.Minute
	config.Keywords = keywords

	domainScanner := domainscan.New(config)

	// Set up real progress tracking from domain-scan SDK
	if s.progress != nil {
		domainScanner.SetProgressCallback(&domainScanProgressAdapter{
			webExposureProgress: s.progress,
		})
	}

	// Create context with timeout for safety
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	// Create controlled comprehensive scan request
	scanReq := &domainscan.ScanRequest{
		Domains:  domains,
		Keywords: keywords,
		Timeout:  5 * time.Minute,
	}

	// Run comprehensive domain discovery with real progress tracking
	result, err := domainScanner.ScanWithOptions(ctx, scanReq)

	if err != nil {
		// Return original domains with default HTTPS assumption as DomainEntry objects
		fallbackDomains := make(map[string]*domainscan.DomainEntry)
		for _, domain := range domains {
			httpsURL := "https://" + domain
			fallbackDomains[httpsURL] = &domainscan.DomainEntry{
				IsLive: true, // Assume live for fallback
			}
		}

		if s.progress != nil {
			s.progress.OnDomainDiscoveryComplete(len(fallbackDomains), len(domains), 0)
		}
		return fallbackDomains, nil
	}

	// Filter only live domains and return the DomainEntry map directly
	liveDomains := make(map[string]*domainscan.DomainEntry)
	for domainURL, entry := range result.Domains {
		if entry.IsLive {
			liveDomains[domainURL] = entry
		}
	}

	// Notify progress callback of completion
	if s.progress != nil {
		s.progress.OnDomainDiscoveryComplete(len(liveDomains), len(domains), len(liveDomains)-len(domains))
	}

	return liveDomains, nil
}

// RunNucleiScanWithProtocol runs Nuclei scan using protocol-aware targets
func (s *scanner) RunNucleiScanWithProtocol(targets map[string]*domainscan.DomainEntry, opts *NucleiOptions) ([]*output.ResultEvent, error) {
	// Extract URLs from DomainEntry map - the key is already the full URL with protocol
	var urls []string
	for domainURL, entry := range targets {
		if entry.IsLive {
			urls = append(urls, domainURL)
		}
	}

	// Use the existing RunNucleiScan method with full URLs
	return s.RunNucleiScan(urls, opts)
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

func extractDomainFromURL(url string) string {
	// Extract domain from URL-like format (protocol+domain+port)
	// e.g., "https://example.com:443" -> "example.com"
	domain := url
	if strings.HasPrefix(domain, "http://") {
		domain = strings.TrimPrefix(domain, "http://")
	} else if strings.HasPrefix(domain, "https://") {
		domain = strings.TrimPrefix(domain, "https://")
	}
	// Remove port
	if idx := strings.Index(domain, ":"); idx > 0 {
		domain = domain[:idx]
	}
	// Remove path
	if idx := strings.Index(domain, "/"); idx > 0 {
		domain = domain[:idx]
	}
	return domain
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
	uniqueDomainsMap := make(map[string]bool)
	for domain, templates := range grouped.Domains {
		for _, key := range keys {
			if _, exists := templates[key]; exists {
				uniqueDomainsMap[domain] = true
				break
			}
		}
	}
	return len(uniqueDomainsMap)
}

func (s *scanner) NormalizeAndClean(input string) []string {
	// Apply exact bash regex transformations
	normalized := strings.ToLower(input)

	// gsub("[<>\"]"; "")
	normalized = regexp.MustCompile(`[<>"]`).ReplaceAllString(normalized, "")

	// gsub(".*generator.*:"; "")
	normalized = regexp.MustCompile(`.*generator.*:`).ReplaceAllString(normalized, "")

	// gsub("[;].*"; "")
	normalized = regexp.MustCompile(`;.*`).ReplaceAllString(normalized, "")

	// gsub("[^a-zA-Z0-9\\-\\.]+"; " ")
	normalized = regexp.MustCompile(`[^a-zA-Z0-9\-\.]+`).ReplaceAllString(normalized, " ")

	// Split by spaces and filter by length
	parts := strings.Fields(normalized)
	var result []string
	for _, part := range parts {
		if len(part) > 2 {
			result = append(result, part)
		}
	}

	return result
}

func (s *scanner) ClassifyAsAPI(templates map[string]*output.ResultEvent) (string, string) {
	// Create a temporary ResultProcessor to use its classification logic
	processor := NewResultProcessor(s.meanings)

	// Process templates to get findings
	var allFindings []string

	for templateID, event := range templates {
		meaning, exists := s.meanings[templateID]
		if !exists {
			continue
		}

		findings := meaning.FindingTemplate.Process(event)
		allFindings = append(allFindings, findings...)
	}

	discovered := processor.classifyAsAPI(templates, allFindings)
	findingsText := processor.cleanFindings(allFindings)

	return discovered, findingsText
}

func (s *scanner) ClassifyAsWebApp(templates map[string]*output.ResultEvent) (string, string, []string) {
	// Create a temporary ResultProcessor to use its classification logic
	processor := NewResultProcessor(s.meanings)

	// Process templates to get detections, findings, and technologies
	var allDetections []string
	var allFindings []string
	var technologies []string

	for templateID, event := range templates {
		meaning, exists := s.meanings[templateID]
		if !exists {
			continue
		}

		detections := meaning.DetectionTemplate.Process(event)
		allDetections = append(allDetections, detections...)

		findings := meaning.FindingTemplate.Process(event)
		allFindings = append(allFindings, findings...)

		// Extract technologies from specific templates
		if processor.isTechnologyTemplate(templateID) && event.ExtractedResults != nil {
			for _, tech := range event.ExtractedResults {
				if tech != "" {
					technologies = append(technologies, tech)
				}
			}
		}
	}

	discovered := processor.classifyAsWebApp(templates)
	findingsText := processor.cleanFindings(allFindings)

	return discovered, findingsText, technologies
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

// validateSpecificTemplates validates that the specified templates exist in the templates directory
func (s *scanner) validateSpecificTemplates(templates []string, templatesPath string) error {
	// Get all available template IDs
	templateFiles, err := s.discoverTemplateFiles(templatesPath)
	if err != nil {
		return fmt.Errorf("failed to discover template files: %w", err)
	}

	availableTemplates, err := s.extractTemplateIDs(templateFiles)
	if err != nil {
		return fmt.Errorf("failed to extract template IDs: %w", err)
	}

	// Create a set of available templates for fast lookup
	availableSet := make(map[string]bool)
	for _, template := range availableTemplates {
		availableSet[template] = true
	}

	// Check each specified template
	var invalidTemplates []string
	for _, template := range templates {
		if !availableSet[template] {
			invalidTemplates = append(invalidTemplates, template)
		}
	}

	// Return error if any templates are invalid
	if len(invalidTemplates) > 0 {
		return fmt.Errorf(`
Template validation failed: %d specified templates not found in %s

Invalid templates:
- %s

Available templates:
- %s

Total available templates: %d`,
			len(invalidTemplates),
			templatesPath,
			strings.Join(invalidTemplates, "\n- "),
			strings.Join(availableTemplates, "\n- "),
			len(availableTemplates))
	}

	return nil
}

// discoverDomainsWithCache handles domain discovery with caching support
func (s *scanner) discoverDomainsWithCache(domains []string, keywords []string, resultsDir string, force bool) ([]string, error) {
	cacheFile := filepath.Join(resultsDir, "domain-scan.json")

	// If force flag is set, remove cache file
	if force {
		if err := os.Remove(cacheFile); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to clear cache: %w", err)
		}
	}

	// Try to load from cache first
	if !force {
		if cachedDomains, err := s.loadDomainsFromCache(cacheFile); err == nil {
			if s.progress != nil {
				s.progress.OnDomainDiscoveryStart(domains, keywords)
				s.progress.OnDomainDiscoveryComplete(len(cachedDomains), len(domains), len(cachedDomains)-len(domains))
			}
			return cachedDomains, nil
		}
	}

	// Perform fresh domain discovery
	discoveredDomains, err := s.DiscoverDomains(domains, keywords)
	if err != nil {
		return nil, err
	}

	// Save to cache
	if err := s.saveDomainsToCache(discoveredDomains, cacheFile); err != nil {
		// Log warning but don't fail the scan
		fmt.Printf("⚠️  Warning: Failed to save domain cache: %v\n", err)
	}

	return discoveredDomains, nil
}

// loadDomainsFromCache loads domains from cache file
func (s *scanner) loadDomainsFromCache(cacheFile string) ([]string, error) {
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return nil, err
	}

	var domains []string
	if err := json.Unmarshal(data, &domains); err != nil {
		return nil, err
	}

	return domains, nil
}

// saveDomainsToCache saves domains to cache file
func (s *scanner) saveDomainsToCache(domains []string, cacheFile string) error {
	data, err := json.MarshalIndent(domains, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(cacheFile, data, 0644)
}

// runNucleiScanWithStorage runs nuclei scan and stores results
func (s *scanner) runNucleiScanWithStorage(targets []string, opts *NucleiOptions, resultsDir string) ([]*output.ResultEvent, error) {
	// Run the nuclei scan
	results, err := s.RunNucleiScan(targets, opts)
	if err != nil {
		return nil, err
	}

	// Store results in nuclei-results directory
	nucleiResultsDir := filepath.Join(resultsDir, "nuclei-results")
	if err := os.MkdirAll(nucleiResultsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create nuclei results directory: %w", err)
	}

	// Save raw nuclei results as JSON
	nucleiResultsFile := filepath.Join(nucleiResultsDir, "results.json")
	if err := s.saveNucleiResults(results, nucleiResultsFile); err != nil {
		// Log warning but don't fail the scan
		fmt.Printf("⚠️  Warning: Failed to save nuclei results: %v\n", err)
	}

	return results, nil
}

// saveNucleiResults saves nuclei results to JSON file
func (s *scanner) saveNucleiResults(results []*output.ResultEvent, filename string) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// loadExistingNucleiResults loads existing nuclei results from JSON file
func (s *scanner) loadExistingNucleiResults(resultsDir string) ([]*output.ResultEvent, error) {
	nucleiResultsFile := filepath.Join(resultsDir, "nuclei-results", "results.json")

	// Check if the results file exists
	if _, err := os.Stat(nucleiResultsFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("nuclei results file not found: %s", nucleiResultsFile)
	}

	// Read the JSON file
	data, err := os.ReadFile(nucleiResultsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read nuclei results file: %w", err)
	}

	// Unmarshal the JSON data
	var results []*output.ResultEvent
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("failed to unmarshal nuclei results: %w", err)
	}

	return results, nil
}

// writeJSONToResults writes the final report to results directory
func (s *scanner) writeJSONToResults(report *ExposureReport, resultsDir string) error {
	filename := filepath.Join(resultsDir, "web-exposure-result.json")

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write report file: %w", err)
	}

	// Notify progress callback if set
	if s.progress != nil {
		s.progress.OnReportGenerated(filename)
	}

	return nil
}
