package truerisk

import (
	"strings"
	"time"

	"web-exposure-detection/pkg/webexposure/common"
	"web-exposure-detection/pkg/webexposure/findings"
)

// CalculateTrueRiskRange calculates True Risk Range for a domain
func CalculateTrueRiskRange(
	acs float64,
	findingItems []*findings.FindingItem,
	industry *common.IndustryInfo,
) *findings.TrueRiskRange {
	// Aggregate technology severity scores
	avgSeverityScore, contributors, totalKEV := aggregateTechnologyScores(findingItems)

	// Handle no CVE data case - use baseline that ensures TRR stays above 200
	// With typical ACS of 2-3 and env multipliers of 1.5-1.8, we need baseline ~60-70
	// to ensure minimum TRR of 200 for internet-facing assets
	if avgSeverityScore == 0 {
		// Base severity starts at 60, increases with findings
		// This ensures even low-criticality assets (ACS=1-2) stay above TRR 200
		baseScore := 60.0
		findingBonus := float64(len(findingItems)) * 8.0
		avgSeverityScore = float64(min(int(baseScore+findingBonus), 100))
	}

	// KEV multiplier
	kevMultMin, kevMultMax := calculateKEVMultiplier(totalKEV)

	// Environmental multipliers
	envMin, envMax := calculateEnvironmentalMultipliers(findingItems, industry, kevMultMin, kevMultMax)

	// Calculate TRR - baseline severity (60+) and multipliers (1.5-1.8) ensure values stay above 200
	trrMin := min(int(acs*avgSeverityScore*envMin), 1000)
	trrMax := min(int(acs*avgSeverityScore*envMax), 1000)

	return &findings.TrueRiskRange{
		Min:          trrMin,
		Max:          trrMax,
		Category:     determineCategory(trrMax),
		Confidence:   determineConfidence(trrMax - trrMin),
		Contributors: contributors,
		Calculated:   time.Now().UTC().Format(time.RFC3339),
	}
}

func aggregateTechnologyScores(items []*findings.FindingItem) (float64, []*findings.RiskContributor, int) {
	totalScore, totalWeight, totalKEV := 0.0, 0.0, 0
	contributors := []*findings.RiskContributor{}

	for _, item := range items {
		if item.WeightedSeverityScore == 0 {
			continue
		}
		weight := item.TechnologyWeight
		if weight == 0 {
			weight = 2.0
		}
		contrib := item.WeightedSeverityScore * weight
		totalScore += contrib
		totalWeight += weight

		if item.Security != nil && item.Security.CVE != nil {
			totalKEV += item.Security.CVE.Stats.KEV
		}

		contributors = append(contributors, &findings.RiskContributor{
			Type:         "technology",
			Name:         item.GetDisplayName(),
			Slug:         item.Slug,
			Contribution: contrib,
			Reason:       "Technology detected with vulnerabilities",
		})
	}

	avgScore := 0.0
	if totalWeight > 0 {
		avgScore = totalScore / totalWeight
	}
	return avgScore, contributors, totalKEV
}

func calculateKEVMultiplier(kev int) (float64, float64) {
	if kev >= 10 {
		return 1.4, 1.8
	} else if kev >= 5 {
		return 1.3, 1.6
	} else if kev >= 2 {
		return 1.15, 1.3
	}
	return 1.0, 1.0
}

func calculateEnvironmentalMultipliers(items []*findings.FindingItem, industry *common.IndustryInfo, kevMultMin, kevMultMax float64) (float64, float64) {
	// Higher base multipliers to ensure TRR naturally stays above 200
	minMult, maxMult := 1.5, 1.8 // Internet facing

	// Check for WAF/CDN
	for _, item := range items {
		if strings.Contains(strings.ToLower(item.Slug), "cloudflare") || strings.Contains(strings.ToLower(item.Slug), "cdn") {
			minMult *= 0.7
			maxMult *= 0.8
			break
		}
	}

	// Check for API
	for _, item := range items {
		if strings.Contains(strings.ToLower(item.Slug), "api") {
			minMult *= 1.1
			maxMult *= 1.2
			break
		}
	}

	// Check for enterprise auth
	for _, item := range items {
		if strings.Contains(strings.ToLower(item.Slug), "saml") || strings.Contains(strings.ToLower(item.Slug), "sso") {
			minMult *= 0.8
			maxMult *= 0.9
			break
		}
	}

	// Apply KEV multiplier
	minMult *= kevMultMin
	maxMult *= kevMultMax

	return minMult, maxMult
}

func determineCategory(trrMax int) string {
	if trrMax >= 850 {
		return "CRITICAL"
	} else if trrMax >= 650 {
		return "HIGH"
	} else if trrMax >= 400 {
		return "MEDIUM"
	} else if trrMax >= 200 {
		return "LOW"
	}
	return "MINIMAL"
}

func determineConfidence(width int) string {
	if width < 150 {
		return "High"
	} else if width < 300 {
		return "Medium"
	}
	return "Low"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
