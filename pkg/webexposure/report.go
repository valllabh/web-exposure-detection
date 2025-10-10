package webexposure

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// GenerateReport creates an exposure report from grouped Nuclei results
func (s *scanner) GenerateReport(grouped *GroupedResults, targetDomain string) (*ExposureReport, error) {
	// Use the new ResultProcessor for efficient single-pass processing
	processor := NewResultProcessor(s.meanings)

	// Process all domains in one pass and build the report
	report := processor.ProcessAllDomains(grouped)

	// Set metadata
	report.SchemaVersion = "v1"
	report.ReportMetadata = &ReportMetadata{
		Title:        fmt.Sprintf("External Application Discovery for %s", targetDomain),
		Date:         time.Now().Format("2 Jan 2006 3:04pm"),
		TargetDomain: targetDomain,
		Timestamp:    time.Now(),
	}

	return report, nil
}

// NewResultProcessor creates a new result processor
func NewResultProcessor(meanings map[string]TemplateMeaning) *ResultProcessor {
	return &ResultProcessor{
		meanings:     meanings,
		summary:      &Summary{},
		technologies: make(map[string]bool),
	}
}

// ProcessAllDomains processes all domains in a single pass
func (rp *ResultProcessor) ProcessAllDomains(grouped *GroupedResults) *ExposureReport {
	// Reset state
	rp.apis = nil
	rp.webApps = nil
	rp.technologies = make(map[string]bool)
	rp.summary = &Summary{}

	// Single pass through all domains
	for domain, templates := range grouped.Domains {
		rp.processDomain(domain, templates)
	}

	// Build final report
	return rp.buildReport()
}

// processDomain processes a single domain's results
func (rp *ResultProcessor) processDomain(domain string, templates map[string]*output.ResultEvent) {
	domainResult := &DomainResult{
		Domain:       domain,
		Findings:     make(map[string]bool),
		Detections:   make(map[string]bool),
		Technologies: make(map[string]bool),
	}

	// Process all templates for this domain in one loop
	for templateID, event := range templates {
		rp.processTemplate(domainResult, templateID, event)
	}

	// Classify and add to appropriate collection using the ResultEvent map
	rp.classifyAndAdd(domainResult, templates)

	// Update global summary
	rp.updateSummary(domainResult)
}

// processTemplate processes a single template result
func (rp *ResultProcessor) processTemplate(domainResult *DomainResult, templateID string, event *output.ResultEvent) {
	meaning, exists := rp.meanings[templateID]
	if !exists {
		return
	}

	// Process detection templates
	detections := meaning.DetectionTemplate.Process(event)
	for _, detection := range detections {
		if detection != "" {
			domainResult.Detections[detection] = true
		}
	}

	// Process finding templates
	findings := meaning.FindingTemplate.Process(event)
	for _, finding := range findings {
		if finding != "" {
			domainResult.Findings[finding] = true
		}
	}

	// Extract technologies from specific templates
	if rp.isTechnologyTemplate(templateID) && event.ExtractedResults != nil {
		for _, tech := range event.ExtractedResults {
			if tech != "" {
				normalized := rp.normalizeTechnology(tech)
				if normalized != "" { // Only add non-empty normalized technologies
					domainResult.Technologies[normalized] = true
					rp.technologies[normalized] = true
				}
			}
		}
	}
}

// classifyAndAdd classifies the domain result and adds to appropriate collection
func (rp *ResultProcessor) classifyAndAdd(domainResult *DomainResult, templates map[string]*output.ResultEvent) {
	// Convert findings to slice for output (technologies are now handled by finding_template)
	findings := rp.setToSlice(domainResult.Findings)

	// Classify based on template IDs directly from the templates map
	apiClassification := rp.classifyAsAPI(templates, findings)
	webAppClassification := rp.classifyAsWebApp(templates)

	// Determine final classification and add to appropriate collection
	if apiClassification != "" {
		// For APIs, filter out "Web Server" from findings
		apiFindings := rp.filterWebServerFromAPI(findings)
		rp.apis = append(rp.apis, &Discovery{
			Domain:     domainResult.Domain,
			Discovered: apiClassification,
			Findings:   rp.cleanFindingsArray(apiFindings),
		})
		domainResult.Discovered = "API"
	} else if webAppClassification != "" {
		rp.webApps = append(rp.webApps, &Discovery{
			Domain:     domainResult.Domain,
			Discovered: webAppClassification,
			Findings:   rp.cleanFindingsArray(findings),
		})
		domainResult.Discovered = "WebApp"
	}
}

// updateSummary updates global summary counters
func (rp *ResultProcessor) updateSummary(domainResult *DomainResult) {
	rp.summary.TotalDomains++

	// Count detections
	rp.summary.TotalDetections += len(domainResult.Detections)

	// Count live domains (domains with any findings)
	if len(domainResult.Findings) > 0 {
		rp.summary.LiveExposedDomains++
	}

	// Count by classification
	switch domainResult.Discovered {
	case "API":
		rp.summary.APIsFound++
		// Check for API specifications
		for detection := range domainResult.Detections {
			if strings.Contains(strings.ToLower(detection), "api spec") {
				rp.summary.APISpecificationsFound++
				break
			}
		}
	case "WebApp":
		rp.summary.WebAppsFound++
		// Check for API usage in web apps (frontend frameworks typically use APIs)
		usingAPI := false
		for detection := range domainResult.Detections {
			if strings.Contains(strings.ToLower(detection), "using api") {
				usingAPI = true
				break
			}
		}
		// Also check for frontend frameworks that typically use APIs
		if !usingAPI {
			for tech := range domainResult.Technologies {
				techLower := strings.ToLower(tech)
				if strings.Contains(techLower, "angular") || strings.Contains(techLower, "react") ||
					strings.Contains(techLower, "vue") || strings.Contains(techLower, "next.js") ||
					strings.Contains(techLower, "nuxt") {
					usingAPI = true
					break
				}
			}
		}
		if usingAPI {
			rp.summary.DomainsUsingAPI++
		}
	}
}

// buildReport constructs the final report
func (rp *ResultProcessor) buildReport() *ExposureReport {
	// Sort results
	sort.Slice(rp.apis, func(i, j int) bool {
		return rp.apis[i].Domain < rp.apis[j].Domain
	})
	sort.Slice(rp.webApps, func(i, j int) bool {
		return rp.webApps[i].Domain < rp.webApps[j].Domain
	})

	// Build technologies list
	techList := rp.setToSlice(rp.technologies)
	sort.Strings(techList)

	// Calculate total applications
	rp.summary.TotalApps = rp.summary.APIsFound + rp.summary.WebAppsFound

	return &ExposureReport{
		Summary: rp.summary,
		Technologies: &TechnologiesDetected{
			Count:        len(techList),
			Technologies: techList,
		},
		APIsFound:    rp.apis,
		WebAppsFound: rp.webApps,
	}
}

// ResultProcessor helper methods

func (rp *ResultProcessor) classifyAsAPI(templates map[string]*output.ResultEvent, findings []string) string {
	hasAPISpec := false
	hasAPIServer := false
	hasAPIKeyword := false
	hasWebApp := false

	// Check for API specification templates
	if templates["openapi"] != nil || templates["swagger-api"] != nil ||
		templates["wadl-api"] != nil || templates["wsdl-api"] != nil {
		hasAPISpec = true
	}

	// Check for API server detection
	if templates["api-server-detection"] != nil {
		hasAPIServer = true
	}

	// Check for API keyword/routing server patterns
	if templates["api-host-keyword-detection"] != nil || templates["blank-root-server-detection"] != nil {
		hasAPIKeyword = true
	}

	// Check for web app indicators (must match classifyAsWebApp function)
	// Note: website-host-detection should not override API classification for domains with API keywords
	if templates["backend-framework-detection"] != nil ||
		templates["frontend-tech-detection"] != nil || templates["xhr-detection-headless"] != nil ||
		templates["js-libraries-detect"] != nil || templates["sap-spartacus"] != nil ||
		templates["gunicorn-detect"] != nil || templates["fingerprinthub-web-fingerprints"] != nil ||
		templates["tech-detect"] != nil {
		hasWebApp = true
	}

	// Only consider website-host-detection as WebApp if no API keywords are present
	if templates["website-host-detection"] != nil && !hasAPIKeyword {
		hasWebApp = true
	}

	// Backend/Frontend tech presence excludes API classification
	hasBackendFrontend := templates["backend-framework-detection"] != nil || templates["frontend-tech-detection"] != nil
	if hasBackendFrontend {
		return "" // Backend/Frontend tech means it's a WebApp, not API
	}

	// API server detection only wins if no backend/frontend tech
	if hasAPIServer {
		return "Confirmed API Endpoint"
	}

	// Other WebApp indicators exclude remaining API classifications
	if hasWebApp {
		return "" // WebApp takes precedence for specs and keywords
	}

	// For non-WebApp domains without API server, classify other API types
	if hasAPISpec {
		return "Potential API Endpoint"
	} else if hasAPIKeyword {
		// Check if it's only blank-root-server (with no other API indicators) - don't classify as API
		hasBlankRoot := templates["blank-root-server-detection"] != nil
		hasAPIHostKeyword := templates["api-host-keyword-detection"] != nil

		if hasBlankRoot && !hasAPIHostKeyword {
			// Only blank-root detected, no other API indicators
			return ""
		}

		// Check if it's only "Routing Server" - if so, don't classify as API
		if len(findings) == 1 && strings.ToLower(findings[0]) == "routing server" {
			fmt.Printf("[DEBUG] Skipping API classification for domain with only 'Routing Server': %v\n", findings)
			return ""
		}
		return "Potential API Endpoint"
	}

	return ""
}

func (rp *ResultProcessor) classifyAsWebApp(templates map[string]*output.ResultEvent) string {
	hasWebApp := false
	hasAPIServer := false
	hasAPIKeyword := false

	// Check for API keyword/routing server patterns
	if templates["api-host-keyword-detection"] != nil || templates["blank-root-server-detection"] != nil {
		hasAPIKeyword = true
	}

	// Check for web app indicators (excluding website-host-detection when API keywords present)
	if templates["backend-framework-detection"] != nil ||
		templates["frontend-tech-detection"] != nil || templates["xhr-detection-headless"] != nil ||
		templates["js-libraries-detect"] != nil || templates["sap-spartacus"] != nil ||
		templates["gunicorn-detect"] != nil || templates["fingerprinthub-web-fingerprints"] != nil ||
		templates["tech-detect"] != nil {
		hasWebApp = true
	}

	// Only consider website-host-detection as WebApp if no API keywords are present
	if templates["website-host-detection"] != nil && !hasAPIKeyword {
		hasWebApp = true
	}

	// Check for API server detection (JSON/XML serving)
	if templates["api-server-detection"] != nil {
		hasAPIServer = true
	}

	// Backend/Frontend tech always makes it a WebApp (even with JSON/XML)
	hasBackendFrontend := templates["backend-framework-detection"] != nil || templates["frontend-tech-detection"] != nil
	if hasBackendFrontend {
		return "Web App"
	}

	// Other web indicators only if not serving JSON/XML
	if hasWebApp && !hasAPIServer {
		return "Web App"
	}

	return ""
}

func (rp *ResultProcessor) isTechnologyTemplate(templateID string) bool {
	techTemplates := map[string]bool{
		"website-host-detection":          true, // Web servers, CDNs, technologies
		"api-server-detection":            true, // API technologies
		"backend-framework-detection":     true, // Backend frameworks
		"frontend-tech-detection":         true, // Frontend technologies
		"api-gateway-proxy-lb-detection":  true, // Infrastructure technologies
		"js-libraries-detect":             true, // JavaScript libraries
		"sap-spartacus":                   true, // SAP technologies
		"gunicorn-detect":                 true, // Python web servers
		"fingerprinthub-web-fingerprints": true, // General web fingerprints
		"tech-detect":                     true, // General technology detection
		"auth-detection":                  true, // Authentication mechanisms
	}
	return techTemplates[templateID]
}

func (rp *ResultProcessor) normalizeTechnology(tech string) string {
	// Normalize technology names (convert to lowercase, remove versions for common cases)
	normalized := strings.ToLower(strings.TrimSpace(tech))

	// Skip empty strings
	if normalized == "" {
		return ""
	}

	// Clean up JSON array artifacts and URLs that shouldn't be technologies
	if strings.HasPrefix(normalized, "[\"") && strings.HasSuffix(normalized, "\"]") {
		// Remove JSON array formatting
		normalized = strings.TrimPrefix(normalized, "[\"")
		normalized = strings.TrimSuffix(normalized, "\"]")
	}

	// Skip URLs that are not technology indicators
	if strings.HasPrefix(normalized, "http://") || strings.HasPrefix(normalized, "https://") {
		return ""
	}

	// Skip file paths that are not technology indicators
	if strings.HasPrefix(normalized, "/") && (strings.Contains(normalized, ".do") || strings.Contains(normalized, ".jsp") || strings.Contains(normalized, ".php")) {
		return ""
	}

	// Improve form detection specificity
	if normalized == "has forms" {
		return "authentication-forms"
	}

	// Handle web servers
	if strings.Contains(normalized, "nginx") {
		return "nginx"
	}
	if strings.Contains(normalized, "apache") {
		return "apache"
	}
	if strings.Contains(normalized, "iis") {
		return "microsoft-iis"
	}

	// Handle CDNs and infrastructure
	if strings.Contains(normalized, "akamai") {
		return "akamai"
	}
	if strings.Contains(normalized, "cloudflare") {
		return "cloudflare"
	}
	if strings.Contains(normalized, "amazon") || strings.Contains(normalized, "aws") {
		return "aws"
	}

	// Handle JavaScript frameworks
	if strings.Contains(normalized, "next.js") || strings.Contains(normalized, "nextjs") {
		return "next.js"
	}
	if strings.Contains(normalized, "react") {
		return "react"
	}
	if strings.Contains(normalized, "angular") {
		return "angular"
	}
	if strings.Contains(normalized, "vue") {
		return "vue.js"
	}

	// Handle backend technologies
	if strings.Contains(normalized, "wordpress") {
		return "wordpress"
	}
	if strings.Contains(normalized, "drupal") {
		return "drupal"
	}
	if strings.Contains(normalized, "joomla") {
		return "joomla"
	}
	if strings.Contains(normalized, "django") {
		return "django"
	}
	if strings.Contains(normalized, "spring") {
		return "spring"
	}

	// Handle authentication & SSO
	if strings.Contains(normalized, "oauth") {
		return "oauth"
	}
	if strings.Contains(normalized, "saml") {
		return "saml"
	}
	if strings.Contains(normalized, "openid") {
		return "openid"
	}
	if strings.Contains(normalized, "sso") {
		return "sso"
	}

	// Remove version numbers and common prefixes
	// Remove version patterns like "v1.2.3", "1.2.3", "(1.2.3)"
	versionPattern := regexp.MustCompile(`\s*v?\d+\.\d+(\.\d+)?(\s*\([^)]+\))?`)
	normalized = versionPattern.ReplaceAllString(normalized, "")

	// Clean up extra spaces
	normalized = strings.TrimSpace(normalized)

	return normalized
}

func (rp *ResultProcessor) setToSlice(set map[string]bool) []string {
	slice := make([]string, 0, len(set))
	for key := range set {
		slice = append(slice, key)
	}
	sort.Strings(slice)
	return slice
}

func (rp *ResultProcessor) cleanFindingsArray(findings []string) []string {
	if len(findings) == 0 {
		return []string{}
	}

	// Filter out "Live Domain" if there are other findings
	var cleanedFindings []string
	hasOtherFindings := false
	for _, f := range findings {
		if f != "Live Domain" {
			hasOtherFindings = true
			cleanedFindings = append(cleanedFindings, f)
		}
	}

	// Only include "Live Domain" if it's the only finding
	if !hasOtherFindings {
		return []string{"Live Domain"}
	}

	return cleanedFindings
}

func (rp *ResultProcessor) cleanFindings(findings []string) string {
	cleanedArray := rp.cleanFindingsArray(findings)
	if len(cleanedArray) == 0 {
		return ""
	}
	return strings.Join(cleanedArray, ", ")
}

func (rp *ResultProcessor) filterWebServerFromAPI(findings []string) []string {
	var filtered []string
	for _, finding := range findings {
		if finding != "Web Server" {
			filtered = append(filtered, finding)
		}
	}
	return filtered
}
