package truinsights

import (
	"fmt"
	"sort"
	"strings"
)

// FindingMetadata represents metadata about a unique finding
type FindingMetadata struct {
	Slug             string   `json:"slug"`
	DisplayName      string   `json:"display_name"`
	Description      string   `json:"description"`
	Labels           []string `json:"labels"`
	CVEApplicable    bool     `json:"cve_applicable"`
	CWEApplicable    bool     `json:"cwe_applicable"`
	RatingWeight     int      `json:"rating_weight"`
	Severity         string   `json:"severity"` // Derived from rating_weight
	DomainCount      int      `json:"domain_count"`
}

// DomainInfo represents a domain with its criticality and risk
type DomainInfo struct {
	Domain            string
	CriticalityScore  int
	CriticalityLevel  string
	SecurityGrade     string
	TrueRiskMin       int
	TrueRiskMax       int
}

// OptimizedFindings represents an optimized structure for findings
type OptimizedFindings struct {
	TotalUniqueFindings int                         `json:"total_unique_findings"`
	FindingsByCategory  map[string][]*FindingMetadata `json:"findings_by_category"`
	CriticalityStats    map[string]int              `json:"criticality_stats"` // HIGH, MEDIUM, LOW counts
	SecurityRatingStats map[string]int              `json:"security_rating_stats"` // A, B, C, D, F counts
	Domains             []*DomainInfo               `json:"domains"` // All domains with criticality
	FindingsMatrix      map[string]map[string]bool  `json:"findings_matrix"` // finding_slug -> domain -> present
}

// extractOptimizedFindings extracts findings in an optimized format
func extractOptimizedFindings(webExposureData interface{}) (*OptimizedFindings, error) {
	data, ok := webExposureData.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid web exposure data format")
	}

	optimized := &OptimizedFindings{
		FindingsByCategory:  make(map[string][]*FindingMetadata),
		CriticalityStats:    make(map[string]int),
		SecurityRatingStats: make(map[string]int),
		Domains:             []*DomainInfo{},
		FindingsMatrix:      make(map[string]map[string]bool),
	}

	// Map to track unique findings
	findingsMap := make(map[string]*FindingMetadata)
	// Map to track domains
	domainsMap := make(map[string]*DomainInfo)

	// Process all domain categories
	categories := []string{"apis_found", "api_specs_found", "ai_assets_found", "web_applications_found", "other_domains_found"}

	for _, category := range categories {
		if domains, ok := data[category].([]interface{}); ok {
			for _, domainData := range domains {
				if domain, ok := domainData.(map[string]interface{}); ok {
					domainName := getStringValue(domain, "domain")
					if domainName == "" {
						domainName = getStringValue(domain, "url")
					}

					// Track domain info with criticality
					if _, exists := domainsMap[domainName]; !exists {
						domInfo := &DomainInfo{
							Domain: domainName,
						}

						// Extract criticality
						if criticality, ok := domain["criticality"].(map[string]interface{}); ok {
							domInfo.CriticalityScore = getIntValue(criticality, "score")
							domInfo.CriticalityLevel = getStringValue(criticality, "category")
						}

						// Extract security grade
						if secRating, ok := domain["security_rating"].(map[string]interface{}); ok {
							domInfo.SecurityGrade = getStringValue(secRating, "grade")
						}

						// Extract True Risk Range
						if trueRisk, ok := domain["true_risk_range"].(map[string]interface{}); ok {
							domInfo.TrueRiskMin = getIntValue(trueRisk, "min")
							domInfo.TrueRiskMax = getIntValue(trueRisk, "max")
						}

						domainsMap[domainName] = domInfo
					}

					// Track criticality stats
					if criticality, ok := domain["criticality"].(map[string]interface{}); ok {
						category := getStringValue(criticality, "category")
						if category != "" {
							optimized.CriticalityStats[category]++
						}
					}

					// Track security rating stats
					if secRating, ok := domain["security_rating"].(map[string]interface{}); ok {
						grade := getStringValue(secRating, "grade")
						if grade != "" {
							optimized.SecurityRatingStats[grade]++
						}
					}

					// Extract findings
					if findings, ok := domain["findings"].([]interface{}); ok {
						for _, finding := range findings {
							if f, ok := finding.(map[string]interface{}); ok {
								slug := getStringValue(f, "slug")
								if slug == "" {
									continue
								}

								// Get or create finding metadata
								meta, exists := findingsMap[slug]
								if !exists {
									meta = &FindingMetadata{
										Slug:          slug,
										DisplayName:   getStringValue(f, "display_name"),
										Description:   getStringValue(f, "description"),
										Labels:        extractLabels(f),
										RatingWeight:  extractRatingWeight(f),
									}

									// Extract security info
									if security, ok := f["security"].(map[string]interface{}); ok {
										meta.CVEApplicable = getBoolValue(security, "cve_applicable")
										meta.CWEApplicable = getBoolValue(security, "cwe_applicable")
									}

									// Derive severity from rating_weight
									meta.Severity = deriveSeverity(meta.RatingWeight, meta.CVEApplicable)

									findingsMap[slug] = meta
								}

								// Track domain count only
								meta.DomainCount++

								// Update findings matrix
								if optimized.FindingsMatrix[slug] == nil {
									optimized.FindingsMatrix[slug] = make(map[string]bool)
								}
								optimized.FindingsMatrix[slug][domainName] = true
							}
						}
					}
				}
			}
		}
	}

	// Convert domains map to sorted list (by criticality score descending)
	for _, domInfo := range domainsMap {
		optimized.Domains = append(optimized.Domains, domInfo)
	}
	sort.Slice(optimized.Domains, func(i, j int) bool {
		return optimized.Domains[i].CriticalityScore > optimized.Domains[j].CriticalityScore
	})

	// Group findings by category (security, auth, api, webapp, etc.)
	for _, meta := range findingsMap {
		category := extractCategory(meta.Slug)
		optimized.FindingsByCategory[category] = append(optimized.FindingsByCategory[category], meta)
	}

	// Sort findings within each category by severity and domain count
	for category := range optimized.FindingsByCategory {
		sort.Slice(optimized.FindingsByCategory[category], func(i, j int) bool {
			// Sort by severity first, then by domain count
			if optimized.FindingsByCategory[category][i].Severity != optimized.FindingsByCategory[category][j].Severity {
				return severityOrder(optimized.FindingsByCategory[category][i].Severity) < severityOrder(optimized.FindingsByCategory[category][j].Severity)
			}
			return optimized.FindingsByCategory[category][i].DomainCount > optimized.FindingsByCategory[category][j].DomainCount
		})
	}

	optimized.TotalUniqueFindings = len(findingsMap)

	return optimized, nil
}

// extractCategory extracts category from slug (e.g., "security.https_status" -> "security")
func extractCategory(slug string) string {
	parts := strings.Split(slug, ".")
	if len(parts) > 0 {
		return parts[0]
	}
	return "other"
}

// extractLabels extracts labels from finding
func extractLabels(finding map[string]interface{}) []string {
	if labels, ok := finding["labels"].([]interface{}); ok {
		result := make([]string, 0, len(labels))
		for _, label := range labels {
			if str, ok := label.(string); ok {
				result = append(result, str)
			}
		}
		return result
	}
	return []string{}
}

// extractRatingWeight extracts rating weight from finding
func extractRatingWeight(finding map[string]interface{}) int {
	if weight, ok := finding["rating_weight"].(float64); ok {
		return int(weight)
	}
	return 0
}

// getBoolValue safely extracts a bool value from a map
func getBoolValue(m map[string]interface{}, key string) bool {
	if val, ok := m[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return false
}

// deriveSeverity derives severity level from rating weight and CVE status
func deriveSeverity(ratingWeight int, cveApplicable bool) string {
	if cveApplicable {
		return "CRITICAL"
	}

	// Negative weights indicate security issues
	absWeight := ratingWeight
	if absWeight < 0 {
		absWeight = -absWeight
	}

	if ratingWeight < 0 {
		// Negative = security issue
		if absWeight >= 25 {
			return "CRITICAL"
		} else if absWeight >= 15 {
			return "HIGH"
		} else if absWeight >= 5 {
			return "MEDIUM"
		}
		return "LOW"
	} else if ratingWeight > 0 {
		// Positive = security feature
		return "INFO"
	}

	return "INFO"
}

// severityOrder returns numeric order for severity sorting
func severityOrder(severity string) int {
	switch severity {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	case "INFO":
		return 4
	default:
		return 5
	}
}

// formatOptimizedFindingsAsMarkdown formats optimized findings as markdown
func (o *OptimizedFindings) formatAsMarkdown() string {
	var md strings.Builder

	md.WriteString("## Findings Analysis\n\n")

	// Use array-based format with Finding IDs (most compact)
	md.WriteString(o.formatFindingsMatrix())

	return md.String()
}
