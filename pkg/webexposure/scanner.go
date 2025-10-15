package webexposure

import (
	"bufio"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

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

// scanTemplatesFS will be set from main package

// New creates a new Scanner instance
func New() (Scanner, error) {
	InitLogger(false, false) // Default to Info level
	return &scanner{}, nil
}

// SetProgressCallback sets an optional progress callback for UI updates
func (s *scanner) SetProgressCallback(callback ProgressCallback) {
	s.progress = callback
}

// SetDebug sets debug mode and reconfigures logger
func (s *scanner) SetDebug(debug bool) {
	s.debug = debug
	InitLogger(debug, s.silent)
}

// SetSilent sets silent mode and reconfigures logger
func (s *scanner) SetSilent(silent bool) {
	s.silent = silent
	InitLogger(s.debug, silent)
}

// extractEmbeddedTemplates extracts embedded scan-templates to a temporary directory
func (s *scanner) extractEmbeddedTemplates() (string, error) {
	logger := GetLogger()

	// Create temporary directory for templates
	tempDir, err := os.MkdirTemp("", "scan-templates-*")
	if err != nil {
		logger.Error().Msgf("Failed to create temp directory: %v", err)
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Extract embedded scan-templates to temp directory
	if err := extractEmbeddedDirectory(scanTemplatesFS, "scan-templates", tempDir); err != nil {
		if rmErr := os.RemoveAll(tempDir); rmErr != nil {
			logger.Warning().Msgf("Failed to clean up temp directory: %v", rmErr)
		}
		logger.Error().Msgf("Failed to extract embedded templates: %v", err)
		return "", fmt.Errorf("failed to extract embedded templates: %w", err)
	}

	logger.Debug().Msgf("Extracted embedded templates to %s", tempDir)
	return tempDir, nil
}

// extractEmbeddedDirectory recursively extracts a directory from embedded filesystem
func extractEmbeddedDirectory(embeddedFS embed.FS, src, dst string) error {
	// Create destination directory
	if err := os.MkdirAll(dst, 0750); err != nil {
		return fmt.Errorf("failed to create destination directory %s: %w", dst, err)
	}

	// Read embedded directory entries
	entries, err := fs.ReadDir(embeddedFS, src)
	if err != nil {
		return fmt.Errorf("failed to read embedded directory %s: %w", src, err)
	}

	// Extract each entry
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			// Recursively extract subdirectories
			if err := extractEmbeddedDirectory(embeddedFS, srcPath, dstPath); err != nil {
				return err
			}
		} else {
			// Extract files from embedded filesystem
			if err := extractEmbeddedFile(embeddedFS, srcPath, dstPath); err != nil {
				return err
			}
		}
	}

	return nil
}

// extractEmbeddedFile extracts a single file from embedded filesystem to destination
func extractEmbeddedFile(embeddedFS embed.FS, src, dst string) error {
	// Read file from embedded filesystem
	data, err := embeddedFS.ReadFile(src)
	if err != nil {
		return fmt.Errorf("failed to read embedded file %s: %w", src, err)
	}

	// Write destination file
	if err := os.WriteFile(dst, data, 0600); err != nil {
		return fmt.Errorf("failed to write destination file %s: %w", dst, err)
	}

	return nil
}

// applyPresetToNucleiOptions applies preset configuration to NucleiOptions
func applyPresetToNucleiOptions(opts *NucleiOptions, preset ScanPreset) {
	switch preset {
	case PresetFast:
		// Fast preset: Aggressive scanning for speed
		opts.RateLimit = 50   // High request rate
		opts.BulkSize = 10    // Larger bulk requests
		opts.Concurrency = 10 // High concurrency
		opts.Timeout = 30     // Shorter timeout
		opts.Delay = 0        // No delay between requests
	case PresetSlow:
		// Slow preset: Conservative scanning for stability (default)
		opts.RateLimit = 15  // Moderate request rate
		opts.BulkSize = 5    // Smaller bulk requests
		opts.Concurrency = 3 // Low concurrency
		opts.Timeout = 60    // Longer timeout for slow responses
		opts.Delay = 2       // 2 second delay between requests
	default:
		// Default to slow preset
		opts.RateLimit = 15
		opts.BulkSize = 5
		opts.Concurrency = 3
		opts.Timeout = 60
		opts.Delay = 2
	}
}

// Scan performs the complete scan pipeline with default options (no force)
func (s *scanner) Scan(domains []string, keywords []string) error {
	return s.ScanWithOptions(domains, keywords, []string{}, false)
}

// ScanWithOptions performs the complete scan pipeline with caching support
func (s *scanner) ScanWithOptions(domains []string, keywords []string, templates []string, force bool) error {
	return s.ScanWithPreset(domains, keywords, templates, force, PresetSlow, false)
}

// ScanWithPreset performs the complete scan pipeline with preset configuration
func (s *scanner) ScanWithPreset(domains []string, keywords []string, templates []string, force bool, preset ScanPreset, skipDiscovery bool) error {
	logger := GetLogger()

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

	logger.Debug().Msgf("Normalized %d domains: %v", len(normalizedDomains), normalizedDomains)

	// Step 1: Extract embedded scan-templates to temporary directory
	tempTemplatesDir, err := s.extractEmbeddedTemplates()
	if err != nil {
		logger.Error().Msgf("Failed to extract templates: %v", err)
		return fmt.Errorf("failed to extract embedded templates: %w", err)
	}
	logger.Debug().Msgf("Extracted templates to %s", tempTemplatesDir)

	// Step 1.5: Validate specific templates early to fail fast
	if len(templates) > 0 {
		logger.Debug().Msgf("Validating %d specific templates", len(templates))
		if err := s.validateSpecificTemplates(templates, tempTemplatesDir); err != nil {
			return fmt.Errorf("template validation failed: %w", err)
		}
	}

	targetDomain := normalizedDomains[0] // Use first domain as primary target

	// Create results directory structure
	resultsDir := filepath.Join("results", targetDomain)
	if err := os.MkdirAll(resultsDir, 0750); err != nil {
		return fmt.Errorf("failed to create results directory: %w", err)
	}
	logger.Debug().Msgf("Created results directory: %s", resultsDir)

	// Step 2: Domain Discovery with caching or skip if flag is set
	var discoveredURLs []string
	if skipDiscovery {
		logger.Info().Msg("Skipping domain discovery (--skip-discovery enabled)")
		// Skip discovery and create domain-scan.json with provided domains only
		discoveredURLs, err = s.createDirectDomainList(normalizedDomains, resultsDir)
		if err != nil {
			return fmt.Errorf("failed to create domain list: %w", err)
		}
	} else {
		logger.Info().Msgf("Running domain discovery for %d domains", len(normalizedDomains))
		// Run domain discovery with caching
		discoveredURLs, err = s.discoverDomainsWithCache(normalizedDomains, keywords, resultsDir, force)
		if err != nil {
			return fmt.Errorf("domain discovery failed: %w", err)
		}
	}
	logger.Info().Msgf("Discovered %d URLs", len(discoveredURLs))

	// Prepare nuclei results directory
	nucleiResultsDir := filepath.Join(resultsDir, "nuclei-results")
	if err := os.MkdirAll(nucleiResultsDir, 0750); err != nil {
		return fmt.Errorf("failed to create nuclei results directory: %w", err)
	}

	// Step 2: Nuclei Options with extracted templates path
	nucleiOptions := &NucleiOptions{
		TemplatesPath:       tempTemplatesDir,
		SpecificTemplates:   templates,
		IncludeTags:         []string{},
		ExcludeTags:         []string{"ssl"},
		Headless:            true,
		OmitTemplate:        false, // Keep template info to get ExtractedResults
		OmitResponse:        false, // Keep response to get ExtractedResults
		FollowHostRedirects: true,
		ShowMatchLine:       true,
		ResultsWriter:       filepath.Join(nucleiResultsDir, "results.jsonl"), // Progressive JSONL writer
		Debug:               s.debug,
		Silent:              s.silent,
	}

	// Apply preset configuration (RateLimit, BulkSize, Concurrency, Timeout, Delay)
	applyPresetToNucleiOptions(nucleiOptions, preset)

	// Step 2: Nuclei Scanning with result storage
	nucleiResults, err := s.runNucleiScanWithStorage(discoveredURLs, nucleiOptions, resultsDir)
	if err != nil {
		return fmt.Errorf("nuclei scanning failed: %w", err)
	}
	logger.Info().Msgf("Nuclei scan complete: %d results", len(nucleiResults))

	// Step 3: Hand off to report generation with nuclei results
	logger.Info().Msg("Generating reports from Nuclei results")
	return s.generateReportsFromNucleiResults(nucleiResults, targetDomain, resultsDir)
}

// RunDiscoveryOnly performs domain discovery and stores results without running Nuclei scan
func (s *scanner) RunDiscoveryOnly(domains []string, keywords []string, force bool) error {
	logger := GetLogger()

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

	targetDomain := normalizedDomains[0] // Use first domain as primary target

	// Create results directory structure
	resultsDir := filepath.Join("results", targetDomain)
	if err := os.MkdirAll(resultsDir, 0750); err != nil {
		return fmt.Errorf("failed to create results directory: %w", err)
	}

	// Step 1: Domain Discovery with caching
	discoveredURLs, err := s.discoverDomainsWithCache(normalizedDomains, keywords, resultsDir, force)
	if err != nil {
		return fmt.Errorf("domain discovery failed: %w", err)
	}

	logger.Info().Msg("Discovery completed successfully!")
	logger.Info().Msgf("Total domains discovered: %d", len(discoveredURLs))
	logger.Info().Msgf("Results saved to: %s/domain-scan.json", resultsDir)

	return nil
}

// GenerateReportFromExistingResults regenerates report from existing Nuclei results
func (s *scanner) GenerateReportFromExistingResults(domains []string, debug bool) error {
	logger := GetLogger()
	s.debug = debug

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
	logger.Debug().Msgf("Normalized domain: %s, results directory: results/%s", targetDomain, targetDomain)

	// Create results directory structure (same as ScanWithOptions)
	resultsDir := filepath.Join("results", targetDomain)
	err := os.MkdirAll(resultsDir, 0750)
	if err != nil {
		return fmt.Errorf("failed to create results directory: %w", err)
	}

	// Step 1: Load existing Nuclei results (already grouped)
	logger.Info().Msgf("Loading existing Nuclei results from %s", resultsDir)
	groupedResults, err := s.loadExistingNucleiResults(resultsDir)
	if err != nil {
		logger.Error().Msgf("Failed to load existing results: %v", err)
		return fmt.Errorf("failed to load existing nuclei results: %w", err)
	}

	// Step 3: Generate report from grouped results
	logger.Info().Msgf("Generating report from %d grouped results", len(groupedResults.Domains))
	report, err := s.GenerateReport(groupedResults, targetDomain)
	if err != nil {
		return fmt.Errorf("report generation failed: %w", err)
	}

	// Write JSON and generate HTML/PDF
	return s.writeAndGenerateFormats(report, resultsDir)
}

// generateReportsFromNucleiResults handles complete report generation orchestration
// This is the single entry point for all report generation (JSON + HTML + PDF)
func (s *scanner) generateReportsFromNucleiResults(nucleiResults []*output.ResultEvent, targetDomain, resultsDir string) error {
	logger := GetLogger()

	// Step 1: Aggregate Results
	logger.Debug().Msgf("Aggregating %d Nuclei result events", len(nucleiResults))
	groupedResults, err := s.AggregateResults(nucleiResults)
	if err != nil {
		return fmt.Errorf("result aggregation failed: %w", err)
	}
	logger.Debug().Msgf("Aggregated into %d hosts", len(groupedResults.Domains))

	// Step 2: Generate Report Structure
	logger.Debug().Msgf("Generated report structure for %s", targetDomain)
	report, err := s.GenerateReport(groupedResults, targetDomain)
	if err != nil {
		return fmt.Errorf("report generation failed: %w", err)
	}

	// Step 3: Write JSON and generate HTML/PDF
	return s.writeAndGenerateFormats(report, resultsDir)
}

// writeAndGenerateFormats writes JSON report and generates HTML/PDF
func (s *scanner) writeAndGenerateFormats(report *ExposureReport, resultsDir string) error {
	logger := GetLogger()

	// Write JSON to results directory
	err := s.writeJSONToResults(report, resultsDir)
	if err != nil {
		return err
	}

	// Generate HTML report
	err = s.generateHTMLReport(report, resultsDir)
	if err != nil {
		// Log warning but don't fail the entire process
		logger.Warning().Msgf("Failed to generate HTML report: %v", err)
	} else {
		// Generate PDF from HTML
		htmlPath := filepath.Join(resultsDir, "report", "index.html")
		pdfPath := filepath.Join(resultsDir, report.ReportMetadata.TargetDomain+"-web-exposure-report.pdf")

		err = s.generatePDF(htmlPath, pdfPath)
		if err != nil {
			// Log warning but don't fail the entire process
			logger.Warning().Msgf("Failed to generate PDF report: %v", err)
		} else {
			// Clean up HTML report directory after successful PDF generation (skip if debug mode)
			if !s.debug {
				reportDir := filepath.Join(resultsDir, "report")
				if err := os.RemoveAll(reportDir); err != nil {
					// Log warning but don't fail - this is just cleanup
					logger.Warning().Msgf("Failed to cleanup HTML report directory: %v", err)
				}
			} else {
				logger.Debug().Msgf("HTML report preserved at %s", filepath.Join(resultsDir, "report"))
			}
		}
	}

	return nil
}

// writeJSONReport writes the report to a JSON file with proper organization
func (s *scanner) writeJSONReport(report *ExposureReport, targetDomain string) error {
	// Create directory structure: ./reports/{first-domain-name}/
	reportsDir := filepath.Join("reports", targetDomain)
	err := os.MkdirAll(reportsDir, 0750)
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

	err = os.WriteFile(fullPath, data, 0600)
	if err != nil {
		return fmt.Errorf("failed to write report file: %w", err)
	}

	// Notify progress callback if set
	if s.progress != nil {
		s.progress.OnReportGenerated(fullPath)
	}
	return nil
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

// mergeStoredResults merges two StoredResult objects from same [Host][TemplateID]
func mergeStoredResults(existing, newResult *StoredResult) *StoredResult {
	// Start with existing result
	merged := &StoredResult{
		Host:        existing.Host,
		TemplateID:  existing.TemplateID,
		MatcherName: existing.MatcherName,
	}

	// If newResult has non-empty MatcherName, use it
	if newResult.MatcherName != "" {
		merged.MatcherName = newResult.MatcherName
	}

	// Merge Findings maps
	merged.Findings = make(map[string][]string)

	// Copy existing findings
	for k, v := range existing.Findings {
		merged.Findings[k] = v
	}

	// Merge new findings (new values overwrite existing)
	for k, v := range newResult.Findings {
		merged.Findings[k] = v
	}

	return merged
}

// AggregateResults converts output.ResultEvent to StoredResult and groups by domain/template
func (s *scanner) AggregateResults(results []*output.ResultEvent) (*GroupedResults, error) {
	grouped := make(map[string]map[string]*StoredResult)

	for _, result := range results {
		if grouped[result.Host] == nil {
			grouped[result.Host] = make(map[string]*StoredResult)
		}

		// Check if we already have a result for this [Host][TemplateID]
		existingResult := grouped[result.Host][result.TemplateID]
		if existingResult != nil {
			// Merge the new result with existing result
			mergedResult := mergeStoredResults(existingResult, NewStoredResult(result))
			grouped[result.Host][result.TemplateID] = mergedResult
		} else {
			// First result for this [Host][TemplateID]
			grouped[result.Host][result.TemplateID] = NewStoredResult(result)
		}
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

func (s *scanner) WriteJSONReport(report *ExposureReport, filename string) error {
	return s.writeJSONReport(report, filename)
}

// discoverTemplateFiles finds all template files in the given directory
func (s *scanner) discoverTemplateFiles(templatesPath string) ([]string, error) {
	logger := GetLogger()
	var templateFiles []string

	err := filepath.Walk(templatesPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logger.Error().Msgf("Error walking path %s: %v", path, err)
			return err
		}

		// Look for .yaml and .yml files
		if strings.HasSuffix(strings.ToLower(path), ".yaml") ||
			strings.HasSuffix(strings.ToLower(path), ".yml") {
			templateFiles = append(templateFiles, path)
		}

		return nil
	})

	logger.Debug().Msgf("Discovered %d template files in %s", len(templateFiles), templatesPath)
	return templateFiles, err
}

// extractTemplateIDs extracts template IDs from YAML files
func (s *scanner) extractTemplateIDs(templateFiles []string) ([]string, error) {
	logger := GetLogger()
	var templateIDs []string

	for _, filePath := range templateFiles {
		data, err := os.ReadFile(filePath)
		if err != nil {
			logger.Warning().Msgf("Failed to read template file %s: %v", filePath, err)
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

	logger.Debug().Msgf("Extracted %d template IDs from %d files", len(templateIDs), len(templateFiles))
	return templateIDs, nil
}

// validateSpecificTemplates validates that the specified templates exist in the templates directory
func (s *scanner) validateSpecificTemplates(templates []string, templatesPath string) error {
	logger := GetLogger()
	logger.Debug().Msgf("Validating %d specific templates against available templates", len(templates))

	// Get all available template IDs
	templateFiles, err := s.discoverTemplateFiles(templatesPath)
	if err != nil {
		return fmt.Errorf("failed to discover template files: %w", err)
	}

	availableTemplates, err := s.extractTemplateIDs(templateFiles)
	if err != nil {
		return fmt.Errorf("failed to extract template IDs: %w", err)
	}
	logger.Debug().Msgf("Found %d available templates", len(availableTemplates))

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
		logger.Error().Msgf("Template validation failed: %d invalid templates", len(invalidTemplates))
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

// runNucleiScanWithStorage runs nuclei scan and stores results
func (s *scanner) runNucleiScanWithStorage(targets []string, opts *NucleiOptions, resultsDir string) ([]*output.ResultEvent, error) {
	logger := GetLogger()
	logger.Info().Msgf("Running Nuclei scan on %d targets", len(targets))

	// Run the nuclei scan (writes to JSONL progressively)
	results, err := s.RunNucleiScan(targets, opts)
	if err != nil {
		logger.Error().Msgf("Nuclei scan failed: %v", err)
		return nil, err
	}

	// Convert JSONL to JSON for backward compatibility
	nucleiResultsDir := filepath.Join(resultsDir, "nuclei-results")
	jsonlFile := filepath.Join(nucleiResultsDir, "results.jsonl")
	jsonFile := filepath.Join(nucleiResultsDir, "results.json")

	if err := s.convertJSONLToJSON(jsonlFile, jsonFile); err != nil {
		// Log warning but don't fail - we still have results in memory
		logger.Warning().Msgf("Failed to convert JSONL to JSON: %v", err)
	} else {
		logger.Info().Msg("JSONL results converted to JSON format")
	}

	return results, nil
}

// loadExistingNucleiResults loads existing nuclei results from JSON file and aggregates them
func (s *scanner) loadExistingNucleiResults(resultsDir string) (*GroupedResults, error) {
	logger := GetLogger()
	logger.Debug().Msgf("Loading Nuclei results from %s", resultsDir)

	nucleiResultsFile := filepath.Join(resultsDir, "nuclei-results", "results.json")

	// Check if the results file exists
	if _, err := os.Stat(nucleiResultsFile); os.IsNotExist(err) {
		logger.Error().Msgf("Nuclei results file not found: %s", nucleiResultsFile)
		return nil, fmt.Errorf("nuclei results file not found: %s", nucleiResultsFile)
	}

	// Read the JSON file
	data, err := os.ReadFile(nucleiResultsFile)
	if err != nil {
		logger.Error().Msgf("Failed to read results file: %v", err)
		return nil, fmt.Errorf("failed to read nuclei results file: %w", err)
	}

	// Unmarshal to StoredResult array
	var storedResults []*StoredResult
	if err := json.Unmarshal(data, &storedResults); err != nil {
		logger.Error().Msgf("Failed to unmarshal results: %v", err)
		return nil, fmt.Errorf("failed to unmarshal nuclei results: %w", err)
	}

	// Group by domain and template
	grouped := make(map[string]map[string]*StoredResult)
	for _, result := range storedResults {
		if grouped[result.Host] == nil {
			grouped[result.Host] = make(map[string]*StoredResult)
		}
		grouped[result.Host][result.TemplateID] = result
	}

	logger.Info().Msgf("Loaded %d hosts from existing results", len(grouped))
	return &GroupedResults{Domains: grouped}, nil
}

// consolidateResultsByHost merges all template results for the same host into a single entry
func consolidateResultsByHost(results []*StoredResult) []*StoredResult {
	// Group by host
	hostMap := make(map[string]*StoredResult)

	for _, result := range results {
		existing, exists := hostMap[result.Host]
		if !exists {
			// First result for this host - create consolidated entry with all findings
			hostMap[result.Host] = &StoredResult{
				Host:     result.Host,
				Findings: make(map[string][]string),
			}
			existing = hostMap[result.Host]
		}

		// Merge findings from this template into consolidated entry
		for key, values := range result.Findings {
			// If key already exists, append values (avoid duplicates)
			if existingValues, ok := existing.Findings[key]; ok {
				// Deduplicate values
				valueSet := make(map[string]bool)
				for _, v := range existingValues {
					valueSet[v] = true
				}
				for _, v := range values {
					if !valueSet[v] {
						existing.Findings[key] = append(existing.Findings[key], v)
						valueSet[v] = true
					}
				}
			} else {
				// New key, just copy values
				existing.Findings[key] = values
			}
		}
	}

	// Convert map back to slice
	consolidated := make([]*StoredResult, 0, len(hostMap))
	for _, result := range hostMap {
		consolidated = append(consolidated, result)
	}

	return consolidated
}

// convertJSONLToJSON converts JSONL (JSON Lines) file to JSON array file
func (s *scanner) convertJSONLToJSON(jsonlPath, jsonPath string) error {
	logger := GetLogger()

	// Check if JSONL file exists
	if _, err := os.Stat(jsonlPath); os.IsNotExist(err) {
		logger.Error().Msgf("JSONL file not found: %s", jsonlPath)
		return fmt.Errorf("JSONL file not found: %s", jsonlPath)
	}

	// Open JSONL file for reading
	jsonlFile, err := os.Open(jsonlPath)
	if err != nil {
		return fmt.Errorf("failed to open JSONL file: %w", err)
	}
	defer func() {
		if err := jsonlFile.Close(); err != nil {
			logger.Warning().Msgf("Failed to close JSONL file: %v", err)
		}
	}()

	// Read and parse each line
	var results []*StoredResult
	scanner := bufio.NewScanner(jsonlFile)

	// Increase buffer size to handle large responses (default is 64KB)
	// Set to 10MB to accommodate large HTML responses
	const maxScanTokenSize = 10 * 1024 * 1024 // 10MB
	buf := make([]byte, maxScanTokenSize)
	scanner.Buffer(buf, maxScanTokenSize)

	lineNum := 0
	var skippedLines []int

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue // Skip empty lines
		}

		// Unmarshal to output.ResultEvent (JSONL contains full Nuclei events)
		var event output.ResultEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			// Log warning but continue processing other lines
			skippedLines = append(skippedLines, lineNum)

			// Show first 100 chars to help diagnose the issue
			preview := line
			if len(preview) > 100 {
				preview = preview[:100] + "..."
			}
			logger.Warning().Msgf("Skipping malformed JSONL line %d: %v", lineNum, err)
			logger.Debug().Msgf("Preview: %s", preview)
			continue
		}

		// Convert to StoredResult (this does XML parsing of extracted-results)
		stored := NewStoredResult(&event)
		results = append(results, stored)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading JSONL file: %w", err)
	}

	// Consolidate results: merge all templates for the same host into one entry
	consolidatedResults := consolidateResultsByHost(results)

	// Write consolidated results as JSON array
	data, err := json.MarshalIndent(consolidatedResults, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}

	if err := os.WriteFile(jsonPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write JSON file: %w", err)
	}

	// Report conversion summary
	if len(skippedLines) > 0 {
		logger.Info().Msgf("Converted %d results from JSONL to JSON (%d hosts, skipped %d malformed lines: %v)",
			len(consolidatedResults), len(consolidatedResults), len(skippedLines), skippedLines)
	} else {
		logger.Info().Msgf("Converted %d results from JSONL to JSON (%d hosts)",
			len(consolidatedResults), len(consolidatedResults))
	}

	return nil
}

// writeJSONToResults writes the final report to results directory
func (s *scanner) writeJSONToResults(report *ExposureReport, resultsDir string) error {
	logger := GetLogger()
	logger.Debug().Msgf("Writing JSON report to %s", resultsDir)

	filename := filepath.Join(resultsDir, "web-exposure-result.json")

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		logger.Error().Msgf("Failed to marshal report: %v", err)
		return fmt.Errorf("failed to marshal report: %w", err)
	}

	err = os.WriteFile(filename, data, 0600)
	if err != nil {
		logger.Error().Msgf("Failed to write report file: %v", err)
		return fmt.Errorf("failed to write report file: %w", err)
	}

	logger.Info().Msgf("JSON report saved to %s", filename)

	// Notify progress callback if set
	if s.progress != nil {
		s.progress.OnReportGenerated(filename)
	}

	return nil
}
