package criticality

import (
	"web-exposure-detection/pkg/webexposure/findings"
)

// Qualys-aligned Asset Criticality Scoring
// Based on: Asset Function + Environment + Service
// Scale: 1-5 (1=Minimal, 2=Low, 3=Medium, 4=High, 5=Critical)

// Score boundaries (1-5 scale, Qualys standard)
const (
	BaseScore = 3.0 // Production baseline (Medium)
	MinScore  = 1.0 // Minimal criticality
	MaxScore  = 5.0 // Critical assets
)

// NOTE: All criticality scoring now data-driven via findings.json
// Each finding can have a criticality_delta field that contributes to the score
// Examples: auth.enterprise.saml_sso (+0.4), gateway.cloudflare (+0.3), auth.mfa (+0.3)

// CalculateCriticality calculates asset criticality using Qualys methodology
// Formula: BaseScore(3.0) + Sum(criticality_delta from all findings)
// All assets are internet-exposed (external discovery), baseline is production (3.0)
// Criticality contributions are defined via criticality_delta field in findings.json
func CalculateCriticality(domain, title string, findingsSlugs []string) *findings.Criticality {
	logger := GetLogger()
	logger.Debug().Msgf("Calculating criticality for domain: %s", domain)

	score := BaseScore // Start at Medium (production baseline)
	factors := []*findings.CriticalityFactor{}

	// Process all findings - any finding with criticality_delta contributes to score
	// This includes auth methods, infrastructure, API patterns, domain patterns, etc.
	criticalityScore, criticalityFactors := processCriticalityFindings(findingsSlugs)
	score += criticalityScore
	factors = append(factors, criticalityFactors...)
	logger.Debug().Msgf("Total criticality delta from findings: %.2f", criticalityScore)

	// Clamp to 1-5 scale and round to integer
	score = clampScore(score)
	roundedScore := roundToInteger(score)
	category := determineCategory(roundedScore)

	logger.Debug().Msgf("Final criticality for %s: %d (%s)", domain, roundedScore, category)

	return &findings.Criticality{
		Score:    roundedScore,
		Category: category,
		Factors:  factors,
	}
}

// processCriticalityFindings extracts criticality scoring from ALL findings
// Any finding with a criticality_delta in findings.json contributes to the score
func processCriticalityFindings(findingsSlugs []string) (float64, []*findings.CriticalityFactor) {
	logger := GetLogger()
	score := 0.0
	factors := []*findings.CriticalityFactor{}

	// Process each finding
	for _, finding := range findingsSlugs {
		// Look up in findings metadata using NewFindingItem (handles lazy loading)
		item := NewFindingItem(finding)

		// Check if this finding has a criticality delta
		if item.CriticalityDelta != 0 {
			score += item.CriticalityDelta

			factors = append(factors, NewCriticalityFactor(
				item.GetDisplayName(),
				finding,
				item.CriticalityDelta,
			))

			logger.Debug().Msgf("Applied criticality factor: %s (delta: %.2f)", item.GetDisplayName(), item.CriticalityDelta)
		}
	}

	return score, factors
}


// clampScore ensures score is within 1-5 boundaries
func clampScore(score float64) float64 {
	if score < MinScore {
		return MinScore
	}
	if score > MaxScore {
		return MaxScore
	}
	return score
}

// determineCategory maps score to category (Qualys-style)
func determineCategory(score int) string {
	switch score {
	case 5:
		return "CRITICAL"
	case 4:
		return "HIGH"
	case 3:
		return "MEDIUM"
	case 2:
		return "LOW"
	default:
		return "MINIMAL"
	}
}

// roundToInteger rounds a float to nearest integer
func roundToInteger(f float64) int {
	if f < 0 {
		return int(f - 0.5)
	}
	return int(f + 0.5)
}
