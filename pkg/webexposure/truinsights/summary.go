package truinsights

import (
	"fmt"
	"strings"
)

// WebExposureSummary represents a compact summary of web exposure data
type WebExposureSummary struct {
	TotalDomains          int                 `json:"total_domains"`
	LiveExposedDomains    int                 `json:"live_exposed_domains"`
	TotalDetections       int                 `json:"total_detections"`
	APIsFound             int                 `json:"apis_found"`
	APISpecsFound         int                 `json:"api_specifications_found"`
	AIAssetsFound         int                 `json:"ai_assets_found"`
	WebAppsFound          int                 `json:"web_apps_found"`
	Technologies          map[string]int      `json:"technologies"`           // tech_name -> count
	AuthenticationMethods map[string]int      `json:"authentication_methods"` // auth_type -> count
	SecurityIssues        []string            `json:"security_issues"`
	DomainFindings        map[string][]string `json:"domain_findings"` // domain -> finding_slugs
}

// extractWebExposureSummary extracts a compact summary from web-exposure-result.json
func extractWebExposureSummary(webExposureData interface{}) (*WebExposureSummary, error) {
	data, ok := webExposureData.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid web exposure data format")
	}

	summary := &WebExposureSummary{
		Technologies:          make(map[string]int),
		AuthenticationMethods: make(map[string]int),
		SecurityIssues:        []string{},
		DomainFindings:        make(map[string][]string),
	}

	// Extract summary counts
	if summaryData, ok := data["summary"].(map[string]interface{}); ok {
		summary.TotalDomains = getIntValue(summaryData, "total_domains")
		summary.LiveExposedDomains = getIntValue(summaryData, "live_exposed_domains")
		summary.TotalDetections = getIntValue(summaryData, "total_detections")
		summary.APIsFound = getIntValue(summaryData, "apis_found")
		summary.APISpecsFound = getIntValue(summaryData, "api_specifications_found")
		summary.AIAssetsFound = getIntValue(summaryData, "ai_assets_found")
		summary.WebAppsFound = getIntValue(summaryData, "web_apps_found")
	}

	// Extract technologies
	if techData, ok := data["technology_exposure"].(map[string]interface{}); ok {
		if allTechs, ok := techData["all_technologies"].(map[string]interface{}); ok {
			for tech, countData := range allTechs {
				if countMap, ok := countData.(map[string]interface{}); ok {
					summary.Technologies[tech] = getIntValue(countMap, "count")
				}
			}
		}
	}

	// Extract findings from all domain categories
	extractDomainFindings(data, "apis_found", summary)
	extractDomainFindings(data, "api_specs_found", summary)
	extractDomainFindings(data, "ai_assets_found", summary)
	extractDomainFindings(data, "web_applications_found", summary)
	extractDomainFindings(data, "other_domains_found", summary)

	return summary, nil
}

// extractDomainFindings extracts findings from a domain category
func extractDomainFindings(data map[string]interface{}, category string, summary *WebExposureSummary) {
	if domains, ok := data[category].([]interface{}); ok {
		for _, domainData := range domains {
			if domain, ok := domainData.(map[string]interface{}); ok {
				domainName := getStringValue(domain, "domain")
				if domainName == "" {
					domainName = getStringValue(domain, "url")
				}

				// Extract finding slugs
				var findingSlugs []string
				if findings, ok := domain["findings"].([]interface{}); ok {
					for _, finding := range findings {
						if f, ok := finding.(map[string]interface{}); ok {
							slug := getStringValue(f, "slug")
							if slug != "" {
								findingSlugs = append(findingSlugs, slug)

								// Track authentication methods
								if strings.Contains(slug, "auth.") || strings.Contains(slug, "oauth") || strings.Contains(slug, "saml") {
									parts := strings.Split(slug, ".")
									if len(parts) > 1 {
										authType := parts[len(parts)-1]
										summary.AuthenticationMethods[authType]++
									}
								}

								// Track security issues
								if strings.Contains(slug, "security.") || strings.Contains(slug, "cve") || strings.Contains(slug, "vulnerability") {
									summary.SecurityIssues = append(summary.SecurityIssues, slug)
								}
							}
						}
					}
				}

				if len(findingSlugs) > 0 {
					summary.DomainFindings[domainName] = findingSlugs
				}
			}
		}
	}
}

// getIntValue safely extracts an int value from a map
func getIntValue(m map[string]interface{}, key string) int {
	if val, ok := m[key]; ok {
		switch v := val.(type) {
		case float64:
			return int(v)
		case int:
			return v
		}
	}
	return 0
}

// getStringValue safely extracts a string value from a map
func getStringValue(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// formatAsMarkdown converts the summary to a compact markdown format
func (s *WebExposureSummary) formatAsMarkdown() string {
	var md strings.Builder

	// Only high-level counts - all details are in optimized findings section
	md.WriteString(fmt.Sprintf("- **Total domains**: %d\n", s.TotalDomains))
	md.WriteString(fmt.Sprintf("- **Live exposed**: %d\n", s.LiveExposedDomains))
	md.WriteString(fmt.Sprintf("- **Total detections**: %d\n", s.TotalDetections))
	md.WriteString(fmt.Sprintf("- **APIs**: %d\n", s.APIsFound))
	md.WriteString(fmt.Sprintf("- **Web applications**: %d\n", s.WebAppsFound))

	return md.String()
}
