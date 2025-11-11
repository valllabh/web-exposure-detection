package findings

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// HeadersGradeFactor represents a single scoring factor for headers grade
type HeadersGradeFactor struct {
	Factor     string  `json:"factor"`       // Human-readable description
	FactorSlug string  `json:"factor_slug"`  // Machine-readable slug
	ScoreDelta float64 `json:"score_delta"`  // Score change (+/-)
	Value      string  `json:"value"`        // Actual value detected
}

// HeadersGrade represents the HTTP security headers grade assessment of a domain
type HeadersGrade struct {
	Grade       string                `json:"grade"`        // Letter grade: A+, A, B, C, D, F
	Score       int                   `json:"score"`        // 0-100 percentage score
	Factors     []*HeadersGradeFactor `json:"factors"`      // Scoring breakdown
	Description string                `json:"description"`  // Brief description of the grade
}

// NewHeadersGradeFactor creates a new headers grade factor
func NewHeadersGradeFactor(factor, slug, value string, delta float64) *HeadersGradeFactor {
	return &HeadersGradeFactor{
		Factor:     factor,
		FactorSlug: slug,
		Value:      value,
		ScoreDelta: delta,
	}
}

// CalculateHeadersGrade calculates the HTTP security headers grade for a domain based on security findings
func CalculateHeadersGrade(findingItems []*FindingItem, findingsDB map[string]*FindingItem) *HeadersGrade {
	// Start with base score of 100 (perfect security)
	// Security checks will reduce or maintain the score
	baseScore := 50.0 // Start from middle ground
	totalScore := baseScore
	factors := []*HeadersGradeFactor{}

	// Process each security finding
	for _, item := range findingItems {
		if !strings.HasPrefix(item.Slug, "security.") {
			continue
		}

		// Get finding definition from DB
		definition, exists := findingsDB[item.Slug]
		if !exists {
			continue
		}

		// Extract value from the finding
		value := ""
		if len(item.Values) > 0 {
			value = item.Values[0]
		}

		// Calculate score delta based on rating rules
		scoreDelta := calculateScoreDelta(item.Slug, value, definition)

		if scoreDelta != 0 {
			factor := NewHeadersGradeFactor(
				definition.DisplayName,
				item.Slug,
				value,
				scoreDelta,
			)
			factors = append(factors, factor)
			totalScore += scoreDelta
		}
	}

	// Clamp score to 0-100 range
	if totalScore < 0 {
		totalScore = 0
	}
	if totalScore > 100 {
		totalScore = 100
	}

	score := int(totalScore)
	grade := scoreToGrade(score)
	description := gradeToDescription(grade)

	return &HeadersGrade{
		Grade:       grade,
		Score:       score,
		Factors:     factors,
		Description: description,
	}
}

// calculateScoreDelta determines the score delta based on finding value and rules
func calculateScoreDelta(slug, value string, definition *FindingItem) float64 {
	switch slug {
	case "security.sri_coverage":
		return calculateSRICoverageDelta(value)
	case "security.mixed_content":
		return calculateMixedContentDelta(value)
	case "security.https_status":
		return calculateHTTPSStatusDelta(value)
	case "security.form_security":
		return calculateFormSecurityDelta(value)
	case "security.meta_policies":
		return calculateMetaPoliciesDelta(value)
	case "security.hsts":
		return calculateHeaderPresenceDelta(value, 20)
	case "security.csp_header":
		return calculateHeaderPresenceDelta(value, 20)
	case "security.xfo":
		return calculateHeaderPresenceDelta(value, 10)
	case "security.xcto":
		return calculateHeaderPresenceDelta(value, 10)
	case "security.referrer_header":
		return calculateHeaderPresenceDelta(value, 5)
	case "security.permissions_policy":
		return calculateHeaderPresenceDelta(value, 10)
	case "security.coop":
		return calculateOptionalHeaderDelta(value, 5)
	case "security.coep":
		return calculateOptionalHeaderDelta(value, 5)
	case "security.corp":
		return calculateOptionalHeaderDelta(value, 5)
	case "security.server_disclosure":
		return calculateDisclosurePenalty(value, -5)
	case "security.powered_by_disclosure":
		return calculateDisclosurePenalty(value, -5)
	}
	return 0
}

// calculateSRICoverageDelta calculates score for SRI coverage percentage
func calculateSRICoverageDelta(value string) float64 {
	if value == "no-external-resources" {
		return 0 // Neutral - no resources to protect
	}

	// Parse percentage
	percentStr := strings.TrimSuffix(value, "%")
	percent, err := strconv.Atoi(percentStr)
	if err != nil {
		return -20 // Default to worst case on parse error
	}

	// Apply rating rules
	if percent == 100 {
		return 20
	} else if percent >= 80 {
		return 10
	} else if percent >= 50 {
		return 0
	} else if percent >= 1 {
		return -10
	}
	return -20
}

// calculateMixedContentDelta calculates score for mixed content detection
func calculateMixedContentDelta(value string) float64 {
	if strings.HasPrefix(value, "has-mixed-content") {
		return -25
	} else if value == "not-https" {
		return -25
	} else if value == "secure" {
		return 25
	}
	return 0
}

// calculateHTTPSStatusDelta calculates score for HTTPS/secure context status
func calculateHTTPSStatusDelta(value string) float64 {
	// Parse JSON response
	var status struct {
		Protocol        string `json:"protocol"`
		IsSecureContext bool   `json:"isSecureContext"`
		Hostname        string `json:"hostname"`
	}

	err := json.Unmarshal([]byte(value), &status)
	if err != nil {
		// Try simple string matching as fallback
		if strings.Contains(value, `"isSecureContext":true`) {
			return 30
		}
		return -30
	}

	if status.IsSecureContext {
		return 30
	}
	return -30
}

// calculateFormSecurityDelta calculates score for form security
func calculateFormSecurityDelta(value string) float64 {
	if strings.HasPrefix(value, "insecure") {
		return -15
	} else if strings.HasPrefix(value, "secure") {
		return 15
	} else if value == "no-forms" {
		return 0 // Neutral - no forms to secure
	}
	return 0
}

// calculateMetaPoliciesDelta calculates score for security meta policies
func calculateMetaPoliciesDelta(value string) float64 {
	if value == "none" {
		return -10
	}

	// Count policies
	policies := strings.Split(value, ",")
	policyCount := len(policies)

	switch policyCount {
	case 1:
		return 0
	case 2:
		return 5
	case 3:
		return 10
	default:
		if policyCount > 3 {
			return 10
		}
		return -10
	}
}

// scoreToGrade converts a 0-100 score to a letter grade
func scoreToGrade(score int) string {
	if score >= 90 {
		return "A+"
	} else if score >= 80 {
		return "A"
	} else if score >= 65 {
		return "B"
	} else if score >= 50 {
		return "C"
	} else if score >= 35 {
		return "D"
	}
	return "F"
}

// gradeToDescription provides a description for each grade
func gradeToDescription(grade string) string {
	descriptions := map[string]string{
		"A+": "Excellent security implementation",
		"A":  "Strong security practices",
		"B":  "Good security with room for improvement",
		"C":  "Moderate security concerns",
		"D":  "Significant security gaps",
		"F":  "Critical security issues",
	}

	if desc, ok := descriptions[grade]; ok {
		return desc
	}
	return "Unknown security status"
}

// GetGradeColor returns CSS color class for a grade
func (hg *HeadersGrade) GetGradeColor() string {
	switch hg.Grade {
	case "A+", "A":
		return "text-green-600"
	case "B":
		return "text-lime-600"
	case "C":
		return "text-yellow-600"
	case "D":
		return "text-orange-600"
	case "F":
		return "text-red-600"
	default:
		return "text-gray-600"
	}
}

// GetGradeBadgeColor returns CSS badge color class for a grade
func (hg *HeadersGrade) GetGradeBadgeColor() string {
	switch hg.Grade {
	case "A+", "A":
		return "bg-green-100 text-green-800 border-green-300"
	case "B":
		return "bg-lime-100 text-lime-800 border-lime-300"
	case "C":
		return "bg-yellow-100 text-yellow-800 border-yellow-300"
	case "D":
		return "bg-orange-100 text-orange-800 border-orange-300"
	case "F":
		return "bg-red-100 text-red-800 border-red-300"
	default:
		return "bg-gray-100 text-gray-800 border-gray-300"
	}
}

// FormatFactorsHTML returns HTML formatted string of all factors
func (hg *HeadersGrade) FormatFactorsHTML() string {
	if len(hg.Factors) == 0 {
		return "<p class=\"text-gray-500\">No security checks performed</p>"
	}

	var html strings.Builder
	html.WriteString("<ul class=\"space-y-2\">")

	for _, factor := range hg.Factors {
		deltaSymbol := "+"
		deltaClass := "text-green-600"
		if factor.ScoreDelta < 0 {
			deltaSymbol = ""
			deltaClass = "text-red-600"
		}

		html.WriteString(fmt.Sprintf(
			"<li><span class=\"font-medium\">%s:</span> %s <span class=\"%s\">(%s%.0f)</span></li>",
			factor.Factor,
			factor.Value,
			deltaClass,
			deltaSymbol,
			factor.ScoreDelta,
		))
	}

	html.WriteString("</ul>")
	return html.String()
}

// calculateHeaderPresenceDelta calculates score for required security headers
func calculateHeaderPresenceDelta(value string, weight float64) float64 {
	if value == "missing" {
		return -weight
	}
	return weight
}

// calculateOptionalHeaderDelta calculates score for optional security headers
func calculateOptionalHeaderDelta(value string, weight float64) float64 {
	// Optional headers only add points if present, no penalty if missing
	if value != "" && value != "missing" {
		return weight
	}
	return 0
}

// calculateDisclosurePenalty applies penalty for information disclosure headers
func calculateDisclosurePenalty(value string, penalty float64) float64 {
	// Penalty applied only if header is present
	if value != "" {
		return penalty
	}
	return 0
}
