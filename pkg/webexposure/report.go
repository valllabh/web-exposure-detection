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
	// Report generation happens silently

	// Add meanings to grouped results (port of update_meaning function)
	s.addMeaningsToResults(grouped)

	// Calculate summary statistics (port of bash script counting logic)
	summary := s.calculateSummary(grouped)

	// Extract technologies (port of extract_normalized function)
	technologies := s.extractTechnologies(grouped)

	// Classify and extract APIs (port of APIs Found section)
	apisFound := s.extractAPIs(grouped)

	// Classify and extract Web Apps (port of Web Applications Found section)
	webAppsFound := s.extractWebApps(grouped)

	// Create report
	report := &ExposureReport{
		SchemaVersion: "v1",
		ReportMetadata: &ReportMetadata{
			Title:        fmt.Sprintf("External Application Discovery for %s", targetDomain),
			Date:         time.Now().Format("2006-01-02"),
			TargetDomain: targetDomain,
			Timestamp:    time.Now(),
		},
		Summary:      summary,
		Technologies: technologies,
		APIsFound:    apisFound,
		WebAppsFound: webAppsFound,
	}

	// Update summary with actual counts
	report.Summary.APIsFound = len(apisFound)
	report.Summary.WebAppsFound = len(webAppsFound)
	report.Summary.TotalDetections = len(apisFound) + len(webAppsFound)

	return report, nil
}

// addMeaningsToResults adds meanings from scan-template-meanings.json (port of update_meaning function)
func (s *scanner) addMeaningsToResults(grouped *GroupedResults) {
	// Native Nuclei output.ResultEvent doesn't have a Meaning field
	// Meanings will be looked up during report generation when needed
	// This function is kept for compatibility but no longer modifies results
}

// calculateSummary computes summary statistics (port of bash script counting logic)
func (s *scanner) calculateSummary(grouped *GroupedResults) *Summary {
	// Count issues by template keys (port of count_issues function)
	liveDomains := s.countIssues(grouped, []string{"live-domain"})
	apiSpecs := s.countIssues(grouped, []string{"swagger-api", "openapi", "wadl-api", "wsdl-api"})
	usingAPI := s.countIssues(grouped, []string{"frontend-tech-detection"})

	return &Summary{
		TotalDomains:           len(grouped.Domains), // This would be subdomain count in real implementation
		LiveExposedDomains:     liveDomains,
		TotalDetections:        0, // Will be updated with actual API + WebApp counts
		APIsFound:              0, // Will be updated with actual count
		APISpecificationsFound: apiSpecs,
		WebAppsFound:           0, // Will be updated with actual count
		DomainsUsingAPI:        usingAPI,
	}
}

// countIssues replicates the bash count_issues function
func (s *scanner) countIssues(grouped *GroupedResults, keys []string) int {
	uniqueDomains := make(map[string]bool)
	for domain, templates := range grouped.Domains {
		for _, key := range keys {
			if _, exists := templates[key]; exists {
				uniqueDomains[domain] = true
				break
			}
		}
	}
	return len(uniqueDomains)
}

// extractTechnologies extracts and normalizes technologies (port of extract_normalized function)
func (s *scanner) extractTechnologies(grouped *GroupedResults) *TechnologiesDetected {
	detectionKeys := []string{"frontend-tech-detection", "backend-framework-detection", "api-gateway-proxy-lb-detection"}

	techMap := make(map[string]bool)
	for _, templates := range grouped.Domains {
		for _, key := range detectionKeys {
			if event, exists := templates[key]; exists {
				if event.ExtractedResults != nil {
					for _, result := range event.ExtractedResults {
						normalized := s.normalizeAndClean(result)
						for _, tech := range normalized {
							if len(tech) > 2 {
								techMap[tech] = true
							}
						}
					}
				}
			}
		}
	}

	// Convert map to sorted slice
	technologies := make([]string, 0, len(techMap))
	for tech := range techMap {
		technologies = append(technologies, tech)
	}
	sort.Strings(technologies)

	return &TechnologiesDetected{
		Count:        len(technologies),
		Technologies: technologies,
	}
}

// normalizeAndClean applies the bash regex transformations
func (s *scanner) normalizeAndClean(input string) []string {
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

// extractAPIs extracts API findings (port of APIs Found section in bash script)
func (s *scanner) extractAPIs(grouped *GroupedResults) []*APIFinding {
	var apis []*APIFinding

	for domain, templates := range grouped.Domains {
		discovered, findings := s.classifyAsAPI(templates)
		if discovered != "" {
			apis = append(apis, &APIFinding{
				Domain:     domain,
				Discovered: discovered,
				Findings:   findings,
			})
		}
	}

	// Sort by domain
	sort.Slice(apis, func(i, j int) bool {
		return apis[i].Domain < apis[j].Domain
	})

	return apis
}

// classifyAsAPI implements template-driven API classification
func (s *scanner) classifyAsAPI(templates map[string]*output.ResultEvent) (string, string) {
	var allDetections []string
	var allFindings []string

	// Process all templates and collect detections and findings
	for templateID, event := range templates {
		meaning, exists := s.meanings[templateID]
		if !exists {
			// This should never happen due to pre-validation, but be defensive
			continue
		}

		// Process detection templates
		detections := meaning.DetectionTemplate.Process(event)
		allDetections = append(allDetections, detections...)

		// Process finding templates
		findings := meaning.FindingTemplate.Process(event)
		allFindings = append(allFindings, findings...)
	}

	// Classify based on processed detection strings
	discovered := s.determineAPIClassification(allDetections)
	findingsText := strings.Join(allFindings, ", ")

	return discovered, findingsText
}

// determineAPIClassification analyzes detection strings to classify API endpoints
func (s *scanner) determineAPIClassification(detections []string) string {
	hasAPISpec := false
	hasAPIServer := false
	hasAPIKeyword := false
	hasWebApp := false

	for _, detection := range detections {
		lower := strings.ToLower(detection)
		if strings.Contains(lower, "api spec") {
			hasAPISpec = true
		}
		if strings.Contains(lower, "serving json/xml") {
			hasAPIServer = true
		}
		if strings.Contains(lower, "domain has api keyword") || strings.Contains(lower, "routing server") {
			hasAPIKeyword = true
		}
		if strings.Contains(lower, "web app") || strings.Contains(lower, "web server") {
			hasWebApp = true
		}
	}

	// Classification logic matching original bash script logic
	if hasAPISpec {
		return "Potential API Endpoint"
	} else if hasAPIServer && !hasWebApp {
		return "Confirmed API Endpoint"
	} else if hasAPIKeyword && !hasWebApp {
		return "Potential API Endpoint"
	}

	return ""
}

// extractWebApps extracts web application findings (port of Web Applications Found section)
func (s *scanner) extractWebApps(grouped *GroupedResults) []*WebAppFinding {
	var webApps []*WebAppFinding

	for domain, templates := range grouped.Domains {
		discovered, findings, technologies := s.classifyAsWebApp(templates)
		if discovered != "" {
			webApps = append(webApps, &WebAppFinding{
				Domain:       domain,
				Discovered:   discovered,
				Findings:     findings,
				Technologies: technologies,
			})
		}
	}

	// Sort by domain
	sort.Slice(webApps, func(i, j int) bool {
		return webApps[i].Domain < webApps[j].Domain
	})

	return webApps
}

// classifyAsWebApp implements template-driven Web App classification
func (s *scanner) classifyAsWebApp(templates map[string]*output.ResultEvent) (string, string, []string) {
	var allDetections []string
	var allFindings []string
	var technologies []string

	// Process all templates and collect detections and findings
	for templateID, event := range templates {
		meaning, exists := s.meanings[templateID]
		if !exists {
			continue
		}

		// Process detection templates
		detections := meaning.DetectionTemplate.Process(event)
		allDetections = append(allDetections, detections...)

		// Process finding templates
		findings := meaning.FindingTemplate.Process(event)
		allFindings = append(allFindings, findings...)

		// Extract technologies from specific templates
		if templateID == "frontend-tech-detection" || templateID == "backend-framework-detection" ||
			templateID == "js-libraries-detect" || templateID == "sap-spartacus" {
			if event.ExtractedResults != nil {
				for _, result := range event.ExtractedResults {
					if len(result) > 0 {
						technologies = append(technologies, result)
					}
				}
			}
		}
	}

	// Classify based on processed detection strings
	discovered := s.determineWebAppClassification(allDetections)
	findingsText := strings.Join(allFindings, ", ")

	return discovered, findingsText, technologies
}

// determineWebAppClassification analyzes detection strings to classify web applications
func (s *scanner) determineWebAppClassification(detections []string) string {
	hasWebApp := false
	hasAPI := false

	for _, detection := range detections {
		lower := strings.ToLower(detection)
		if strings.Contains(lower, "web app") || strings.Contains(lower, "web server") ||
			strings.Contains(lower, "frontend") || strings.Contains(lower, "backend") ||
			strings.Contains(lower, "using api") {
			hasWebApp = true
		}
		if strings.Contains(lower, "domain has api keyword") || strings.Contains(lower, "routing server") {
			hasAPI = true
		}
	}

	// Web App classification: must have web indicators but not be purely API
	if hasWebApp && !hasAPI {
		return "Web App"
	}

	return ""
}
