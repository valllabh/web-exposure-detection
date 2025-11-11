package truinsights

import (
	"fmt"
	"sort"
	"strings"
)

// formatFindingsMatrix creates a compact list format with finding IDs
func (o *OptimizedFindings) formatFindingsMatrix() string {
	if len(o.FindingsMatrix) == 0 || len(o.Domains) == 0 {
		return ""
	}

	var md strings.Builder

	// Create finding ID mapping (F1001, F1002, etc.)
	findingIDMap := make(map[string]string)
	var allFindingSlugs []string
	for slug := range o.FindingsMatrix {
		allFindingSlugs = append(allFindingSlugs, slug)
	}

	// Sort findings: critical security issues first
	sort.Slice(allFindingSlugs, func(i, j int) bool {
		slugI := allFindingSlugs[i]
		slugJ := allFindingSlugs[j]

		// Security findings first
		secI := strings.HasPrefix(slugI, "security.")
		secJ := strings.HasPrefix(slugJ, "security.")
		if secI != secJ {
			return secI
		}

		// Then by slug name
		return slugI < slugJ
	})

	// Assign IDs (F1001, F1002, ...)
	for i, slug := range allFindingSlugs {
		findingIDMap[slug] = fmt.Sprintf("F%04d", 1001+i)
	}

	// Show ALL domains with their findings as arrays (sorted by criticality)
	md.WriteString("### Domains with Findings\n\n")

	// Explain ASC and TRR
	md.WriteString("**ASC** (Asset Criticality Score, 1-5): Business importance based on data sensitivity and access level.\n")
	md.WriteString("- 1 = Minimal business impact, 5 = Critical business asset\n\n")

	md.WriteString("**TRR** (True Risk Range, 0-1000): Calculated risk combining asset criticality with security findings severity.\n")
	md.WriteString("- Formula: Asset Criticality × Security Findings × Environmental Factors\n")
	md.WriteString("- Range categories: 0-199 MINIMAL, 200-399 LOW, 400-649 MEDIUM, 650-849 HIGH, 850-1000 CRITICAL\n\n")

	md.WriteString("*Format: domain (ASC:X, TRR:min-max): [Finding IDs]*\n\n")

	for _, dom := range o.Domains {
		// Get finding IDs for this domain
		var findingIDs []string
		for slug := range o.FindingsMatrix {
			if o.FindingsMatrix[slug][dom.Domain] {
				findingIDs = append(findingIDs, findingIDMap[slug])
			}
		}

		// Sort IDs for consistent output
		sort.Strings(findingIDs)

		// Format: domain.com (ASC:5, TRR:200-599): [F1001, F1003, F1005]
		trrStr := "N/A"
		if dom.TrueRiskMin > 0 || dom.TrueRiskMax > 0 {
			trrStr = fmt.Sprintf("%d-%d", dom.TrueRiskMin, dom.TrueRiskMax)
		}

		md.WriteString(fmt.Sprintf("- **%s** (ASC:%d, TRR:%s): [%s]\n",
			dom.Domain,
			dom.CriticalityScore,
			trrStr,
			strings.Join(findingIDs, ", ")))
	}

	md.WriteString("\n---\n\n")
	md.WriteString("### Finding ID Reference\n\n")
	md.WriteString("*All findings detected across the organization*\n\n")

	// Show finding details with IDs
	for _, slug := range allFindingSlugs {
		findingID := findingIDMap[slug]

		// Get metadata from FindingsByCategory
		var meta *FindingMetadata
		for _, findings := range o.FindingsByCategory {
			for _, f := range findings {
				if f.Slug == slug {
					meta = f
					break
				}
			}
			if meta != nil {
				break
			}
		}

		if meta != nil {
			// Compact format: F1001 [CRITICAL, CVE, 120]: security.https_status - Description (Tags: X, Y)
			secTags := []string{meta.Severity}
			if meta.CVEApplicable {
				secTags = append(secTags, "CVE")
			}
			if meta.CWEApplicable {
				secTags = append(secTags, "CWE")
			}

			// First line: ID, severity, count, slug
			md.WriteString(fmt.Sprintf("**%s** [%s, %d]: `%s`",
				findingID,
				strings.Join(secTags, ", "),
				meta.DomainCount,
				slug))

			// Add display name if different from slug
			if meta.DisplayName != "" && meta.DisplayName != slug {
				md.WriteString(fmt.Sprintf(" - %s", meta.DisplayName))
			}
			md.WriteString("\n")

			// Description (compact, single line)
			if meta.Description != "" {
				// Trim description to first sentence or 150 chars
				desc := meta.Description
				if len(desc) > 150 {
					// Find first period
					if idx := strings.Index(desc, ". "); idx > 0 && idx < 150 {
						desc = desc[:idx+1]
					} else {
						desc = desc[:147] + "..."
					}
				}
				md.WriteString(fmt.Sprintf("  %s\n", desc))
			}

			// Labels (inline)
			if len(meta.Labels) > 0 {
				md.WriteString(fmt.Sprintf("  Tags: %s\n", strings.Join(meta.Labels, ", ")))
			}

			md.WriteString("\n")
		}
	}

	md.WriteString(fmt.Sprintf("*Total: %d unique findings across %d domains*\n",
		len(allFindingSlugs), len(o.Domains)))

	return md.String()
}
