package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/valllabh/domain-scan/pkg/domainscan"

	"web-exposure-detection/pkg/webexposure/common"
	"web-exposure-detection/pkg/webexposure/criticality"
	"web-exposure-detection/pkg/webexposure/findings"
	"web-exposure-detection/pkg/webexposure/logger"
	"web-exposure-detection/pkg/webexposure/nuclei"
	"web-exposure-detection/pkg/webexposure/truerisk"
)

// ResultProcessor centralizes all report generation logic
type ResultProcessor struct {
	summary        *common.Summary
	apis           []*findings.Discovery
	apiSpecs       []*findings.Discovery
	aiAssets       []*findings.Discovery
	webApps        []*findings.Discovery
	otherDomains   []*findings.Discovery
	technologies   map[string]bool                // set for deduplication
	techCounts     map[string]int                 // count of domains using each technology
	grouped        *nuclei.GroupedResults         // stored for populating technology values
	industryInfo   *common.IndustryInfo           // industry classification for risk calculations
	falsePositives map[string]bool                // set of slugs marked as false positives
}

// GenerateReport creates an exposure report from grouped Nuclei results
func GenerateReport(grouped *nuclei.GroupedResults, targetDomain string, industryClassification *common.IndustryInfo, discoveryResult *domainscan.AssetDiscoveryResult) (*common.ExposureReport, error) {
	logger := logger.GetLogger()
	logger.Debug().Msgf("Processing %d domains for report generation", len(grouped.Domains))

	// Use the new ResultProcessor for efficient single-pass processing
	processor := NewResultProcessor()
	processor.industryInfo = industryClassification // Set industry info for TRR calculations
	processor.falsePositives = LoadFalsePositives(targetDomain) // Load false positives for filtering

	// Process all domains in one pass and build the report
	report := processor.ProcessAllDomains(grouped)

	// Set metadata
	report.SchemaVersion = "v1"
	report.ReportMetadata = &common.ReportMetadata{
		Title:        fmt.Sprintf("External Application Discovery for %s", targetDomain),
		Date:         time.Now().UTC().Format("2 Jan 2006 3:04pm MST"),
		TargetDomain: targetDomain,
		Timestamp:    time.Now(),
	}

	// Add industry classification if available
	if industryClassification != nil {
		report.ReportMetadata.Industry = industryClassification
	}

	// Calculate domain metrics from discovery result if available
	if discoveryResult != nil {
		report.Summary.DomainMetrics = CalculateDomainMetrics(discoveryResult)

		// Override InternetExposed to reflect domains actually scanned (not just discovered)
		// TotalDomains = domains that nuclei successfully scanned
		// Some discovered domains may fail nuclei scan due to network errors
		report.Summary.DomainMetrics.InternetExposed = report.Summary.TotalDomains

		logger.Debug().Msgf("Domain metrics calculated: %d discovered, %d exposed, %d not reachable",
			report.Summary.DomainMetrics.TotalDiscovered,
			report.Summary.DomainMetrics.InternetExposed,
			report.Summary.DomainMetrics.NotReachable)
	}

	logger.Info().Msgf("Report generated successfully for %s: %d apps, %d APIs, %d API specs, %d AI assets",
		targetDomain, report.Summary.TotalApps, report.Summary.APIServers,
		report.Summary.APISpecificationsFound, report.Summary.AIAssetsFound)

	return report, nil
}

// NewResultProcessor creates a new result processor
func NewResultProcessor() *ResultProcessor {
	return &ResultProcessor{
		summary:      &common.Summary{},
		technologies: make(map[string]bool),
		techCounts:   make(map[string]int),
	}
}

// ProcessAllDomains processes all domains in a single pass
func (rp *ResultProcessor) ProcessAllDomains(grouped *nuclei.GroupedResults) *common.ExposureReport {
	logger := logger.GetLogger()
	logger.Debug().Msgf("Processing %d domains in single pass", len(grouped.Domains))

	// Reset state
	rp.apis = nil
	rp.apiSpecs = nil
	rp.aiAssets = nil
	rp.webApps = nil
	rp.otherDomains = nil
	rp.technologies = make(map[string]bool)
	rp.techCounts = make(map[string]int)
	rp.summary = &common.Summary{}
	rp.grouped = grouped // Store for later use in building technologies

	// Single pass through all domains
	for domain, templates := range grouped.Domains {
		rp.processDomain(domain, templates)
	}

	logger.Debug().Msgf("Completed processing: %d technologies detected, %d domains processed",
		len(rp.technologies), len(grouped.Domains))

	// Build final report
	return rp.buildReport()
}

// processDomain processes a single domain's results
func (rp *ResultProcessor) processDomain(domain string, templates map[string]*nuclei.StoredResult) {
	logger := logger.GetLogger()
	logger.Debug().Msgf("Processing domain: %s with %d templates", domain, len(templates))

	domainResult := &common.DomainResult{
		Domain:       domain,
		Findings:     make(map[string]bool),
		Technologies: make(map[string]bool),
	}

	// Step 1: Merge all findings from all templates
	allFindings := make(map[string][]string) // slug -> values

	for templateID, event := range templates {
		// Extract metadata (title, description)
		if event.Findings != nil && rp.isTechnologyTemplate(templateID) {
			if values, ok := event.Findings["page.title"]; ok && len(values) > 0 {
				title := values[0]
				if title != "" && !rp.isGenericTitle(title) {
					domainResult.Title = title
				}
			}
			if values, ok := event.Findings["page.description"]; ok && len(values) > 0 {
				description := values[0]
				if description != "" {
					domainResult.Description = description
				}
			}
		}

		// Merge all findings
		if event.Findings != nil {
			for slug, values := range event.Findings {
				// Skip metadata keys
				if slug == "page.title" || slug == "page.description" || slug == "server.blank_root_status" {
					continue
				}
				// Merge values (deduplicate)
				if existing, ok := allFindings[slug]; ok {
					// Deduplicate
					valueSet := make(map[string]bool)
					for _, v := range existing {
						valueSet[v] = true
					}
					for _, v := range values {
						if !valueSet[v] {
							allFindings[slug] = append(allFindings[slug], v)
						}
					}
				} else {
					allFindings[slug] = values
				}
			}
		}
	}

	// Step 2: Collect technologies from allFindings and add all to Findings
	for slug := range allFindings {
		domainResult.Technologies[slug] = true
		rp.technologies[slug] = true

		// Count this technology usage (increment count for this domain)
		rp.techCounts[slug]++

		// Add all findings with their display names
		item := findings.NewFindingItem(slug)
		displayName := item.GetDisplayName()
		domainResult.Findings[displayName+"|"+slug] = true
	}

	// Step 3: Classify and add to collections
	rp.classifyAndAdd(domainResult, templates)

	logger.Debug().Msgf("Domain %s classified as: %s with %d findings",
		domain, domainResult.Discovered, len(domainResult.Findings))

	// Update global summary
	rp.updateSummary(domainResult)
}

// classifyAndAdd classifies the domain result and adds to appropriate collections
// Domains can appear in multiple categories based on their findings
func (rp *ResultProcessor) classifyAndAdd(domainResult *common.DomainResult, templates map[string]*nuclei.StoredResult) {
	// Extract display names and build FindingItems from the combined "displayName|slug" format
	findingsMap := rp.extractFindingsWithSlugs(domainResult.Findings)
	findingsList := findingsMap.displayNames

	// Check all possible classifications (no priority)
	webAppClassification := rp.classifyAsWebApp(templates)
	apiClassification := rp.classifyAsAPI(templates, findingsList)
	apiSpecClassification := rp.classifyAsAPISpec(templates)
	aiClassification := rp.classifyAsAI(templates)

	// Helper function to build findings from technologies filtered by classification
	buildTechFindings := func(classification string) (*findingsWithSlugs, []string) {
		techFindingsMap := &findingsWithSlugs{
			displayNames:      make([]string, 0, len(domainResult.Technologies)),
			displayNameToSlug: make(map[string]string),
		}
		for techSlug := range domainResult.Technologies {
			item := findings.NewFindingItem(techSlug)
			// Only include technologies that match the classification and should be shown
			// Use hasClassificationForDisplay to include both regular and "~" prefixed classifications
			if item.ShowInTech && rp.hasClassificationForDisplay(item, classification) {
				displayName := item.GetDisplayName()
				techFindingsMap.displayNames = append(techFindingsMap.displayNames, displayName)
				techFindingsMap.displayNameToSlug[displayName] = techSlug
			}
		}
		sort.Strings(techFindingsMap.displayNames)
		return techFindingsMap, techFindingsMap.displayNames
	}

	// Add to WebApp collection if it has webapp classification
	if webAppClassification != "" {
		logger := logger.GetLogger()
		webappFindings := rp.filterFindingsByClassification(findingsList, findingsMap, "webapp")
		cleanedFindings := rp.cleanFindingsArray(webappFindings)

		var finalMap *findingsWithSlugs
		var finalFindings []string
		if len(cleanedFindings) == 0 {
			finalMap, finalFindings = buildTechFindings("webapp")
		} else {
			finalMap = rp.buildFilteredFindingsMap(cleanedFindings, findingsMap)
			finalFindings = cleanedFindings
		}

		logger.Debug().Msgf("Adding %s to WebApp collection: %s", domainResult.Domain, webAppClassification)

		// Calculate criticality for this asset (pass slugs, not display names)
		slugs := rp.extractSlugs(finalFindings, finalMap)
		assetCriticality := criticality.CalculateCriticality(domainResult.Domain, domainResult.Title, slugs)
		logger.Debug().Msgf("WebApp %s criticality: %.2f (%s)", domainResult.Domain, assetCriticality.Score, assetCriticality.Category)

		// Build finding items
		findingItems := rp.buildFindingItems(finalFindings, finalMap, templates)

		// Calculate headers grade
		findingsDB := findings.GetGlobalFindingsMap()
		headersGrade := findings.CalculateHeadersGrade(findingItems, findingsDB)
		logger.Debug().Msgf("WebApp %s headers grade: %s (%d/100)", domainResult.Domain, headersGrade.Grade, headersGrade.Score)

		// Calculate True Risk Range
		trueRiskRange := truerisk.CalculateTrueRiskRange(
			float64(assetCriticality.Score),
			findingItems,
			rp.industryInfo,
		)
		logger.Debug().Msgf("WebApp %s TRR: %d-%d (%s)", domainResult.Domain, trueRiskRange.Min, trueRiskRange.Max, trueRiskRange.Category)

		// Extract URL metadata from first available template result
		url, ip := rp.extractURLMetadata(templates)

		rp.webApps = append(rp.webApps, &findings.Discovery{
			Domain:        domainResult.Domain,
			Title:         domainResult.Title,
			Description:   domainResult.Description,
			Discovered:    webAppClassification,
			FindingItems:  findingItems,
			Criticality:   assetCriticality,
			TrueRiskRange: trueRiskRange,
			HeadersGrade:  headersGrade,
			URL:           url,
			IP:            ip,
		})
		domainResult.Discovered = "WebApp"
	}

	// Add to API collection if it has api classification
	if apiClassification != "" {
		logger := logger.GetLogger()
		apiFindings := rp.filterFindingsByClassification(findingsList, findingsMap, "api")
		cleanedFindings := rp.cleanFindingsArray(apiFindings)

		var finalMap *findingsWithSlugs
		var finalFindings []string

		if len(cleanedFindings) > 0 {
			finalMap = rp.buildFilteredFindingsMap(cleanedFindings, findingsMap)
			finalFindings = cleanedFindings
		} else {
			finalMap, finalFindings = buildTechFindings("api")
		}

		logger.Debug().Msgf("Adding %s to API collection: %s", domainResult.Domain, apiClassification)

		// Calculate criticality for this asset (pass slugs, not display names)
		slugs := rp.extractSlugs(finalFindings, finalMap)
		assetCriticality := criticality.CalculateCriticality(domainResult.Domain, domainResult.Title, slugs)
		logger.Debug().Msgf("API %s criticality: %.2f (%s)", domainResult.Domain, assetCriticality.Score, assetCriticality.Category)

		// Build finding items
		findingItems := rp.buildFindingItems(finalFindings, finalMap, templates)

		// Calculate headers grade
		findingsDB := findings.GetGlobalFindingsMap()
		headersGrade := findings.CalculateHeadersGrade(findingItems, findingsDB)
		logger.Debug().Msgf("API %s headers grade: %s (%d/100)", domainResult.Domain, headersGrade.Grade, headersGrade.Score)

		// Calculate True Risk Range
		trueRiskRange := truerisk.CalculateTrueRiskRange(
			float64(assetCriticality.Score),
			findingItems,
			rp.industryInfo,
		)
		logger.Debug().Msgf("API %s TRR: %d-%d (%s)", domainResult.Domain, trueRiskRange.Min, trueRiskRange.Max, trueRiskRange.Category)

		// Extract URL metadata from first available template result
		url, ip := rp.extractURLMetadata(templates)

		rp.apis = append(rp.apis, &findings.Discovery{
			Domain:        domainResult.Domain,
			Title:         domainResult.Title,
			Description:   domainResult.Description,
			Discovered:    apiClassification,
			FindingItems:  findingItems,
			Criticality:   assetCriticality,
			TrueRiskRange: trueRiskRange,
			HeadersGrade:  headersGrade,
			URL:           url,
			IP:            ip,
		})
		if domainResult.Discovered == "" {
			domainResult.Discovered = "API"
		}
	}

	// Add to API Spec collection if it has api-spec classification
	if apiSpecClassification != "" {
		logger := logger.GetLogger()
		apiSpecFindings := rp.filterFindingsByClassification(findingsList, findingsMap, "api-spec")
		cleanedFindings := rp.cleanFindingsArray(apiSpecFindings)

		var finalMap *findingsWithSlugs
		var finalFindings []string
		if len(cleanedFindings) == 0 {
			finalMap, finalFindings = buildTechFindings("api-spec")
		} else {
			finalMap = rp.buildFilteredFindingsMap(cleanedFindings, findingsMap)
			finalFindings = cleanedFindings
		}

		logger.Debug().Msgf("Adding %s to API Spec collection: %s", domainResult.Domain, apiSpecClassification)

		// Calculate criticality for this asset (pass slugs, not display names)
		slugs := rp.extractSlugs(finalFindings, finalMap)
		assetCriticality := criticality.CalculateCriticality(domainResult.Domain, domainResult.Title, slugs)
		logger.Debug().Msgf("API Spec %s criticality: %.2f (%s)", domainResult.Domain, assetCriticality.Score, assetCriticality.Category)

		// Build finding items
		findingItems := rp.buildFindingItems(finalFindings, finalMap, templates)

		// Calculate headers grade
		findingsDB := findings.GetGlobalFindingsMap()
		headersGrade := findings.CalculateHeadersGrade(findingItems, findingsDB)
		logger.Debug().Msgf("API Spec %s headers grade: %s (%d/100)", domainResult.Domain, headersGrade.Grade, headersGrade.Score)

		// Calculate True Risk Range
		trueRiskRange := truerisk.CalculateTrueRiskRange(
			float64(assetCriticality.Score),
			findingItems,
			rp.industryInfo,
		)
		logger.Debug().Msgf("API Spec %s TRR: %d-%d (%s)", domainResult.Domain, trueRiskRange.Min, trueRiskRange.Max, trueRiskRange.Category)

		// Extract URL metadata from first available template result
		url, ip := rp.extractURLMetadata(templates)

		rp.apiSpecs = append(rp.apiSpecs, &findings.Discovery{
			Domain:        domainResult.Domain,
			Title:         domainResult.Title,
			Description:   domainResult.Description,
			Discovered:    apiSpecClassification,
			FindingItems:  findingItems,
			Criticality:   assetCriticality,
			TrueRiskRange: trueRiskRange,
			HeadersGrade:  headersGrade,
			URL:           url,
			IP:            ip,
		})
		if domainResult.Discovered == "" {
			domainResult.Discovered = "APISpec"
		}
	}

	// Add to AI collection if it has ai classification
	if aiClassification != "" {
		logger := logger.GetLogger()
		aiFindings := rp.filterFindingsByClassification(findingsList, findingsMap, "ai")
		cleanedFindings := rp.cleanFindingsArray(aiFindings)

		var finalMap *findingsWithSlugs
		var finalFindings []string
		if len(cleanedFindings) == 0 {
			finalMap, finalFindings = buildTechFindings("ai")
		} else {
			finalMap = rp.buildFilteredFindingsMap(cleanedFindings, findingsMap)
			finalFindings = cleanedFindings
		}

		logger.Debug().Msgf("Adding %s to AI collection: %s", domainResult.Domain, aiClassification)

		// Calculate criticality for this asset (pass slugs, not display names)
		slugs := rp.extractSlugs(finalFindings, finalMap)
		assetCriticality := criticality.CalculateCriticality(domainResult.Domain, domainResult.Title, slugs)
		logger.Debug().Msgf("AI Asset %s criticality: %.2f (%s)", domainResult.Domain, assetCriticality.Score, assetCriticality.Category)

		// Build finding items
		findingItems := rp.buildFindingItems(finalFindings, finalMap, templates)

		// Calculate headers grade
		findingsDB := findings.GetGlobalFindingsMap()
		headersGrade := findings.CalculateHeadersGrade(findingItems, findingsDB)
		logger.Debug().Msgf("AI Asset %s headers grade: %s (%d/100)", domainResult.Domain, headersGrade.Grade, headersGrade.Score)

		// Calculate True Risk Range
		trueRiskRange := truerisk.CalculateTrueRiskRange(
			float64(assetCriticality.Score),
			findingItems,
			rp.industryInfo,
		)
		logger.Debug().Msgf("AI Asset %s TRR: %d-%d (%s)", domainResult.Domain, trueRiskRange.Min, trueRiskRange.Max, trueRiskRange.Category)

		// Extract URL metadata from first available template result
		url, ip := rp.extractURLMetadata(templates)

		rp.aiAssets = append(rp.aiAssets, &findings.Discovery{
			Domain:        domainResult.Domain,
			Title:         domainResult.Title,
			Description:   domainResult.Description,
			Discovered:    aiClassification,
			FindingItems:  findingItems,
			Criticality:   assetCriticality,
			TrueRiskRange: trueRiskRange,
			HeadersGrade:  headersGrade,
			URL:           url,
			IP:            ip,
		})
		if domainResult.Discovered == "" {
			domainResult.Discovered = "AI"
		}
	}

	// Track unclassified domains - domains that were scanned but didn't match any classification
	if domainResult.Discovered == "" {
		rp.summary.UnclassifiedFound++

		// Collect all available findings for unclassified domains
		findingsMap := rp.extractFindingsWithSlugs(domainResult.Findings)
		allFindings := findingsMap.displayNames

		// Clean findings and build final map
		cleanedFindings := rp.cleanFindingsArray(allFindings)
		var finalMap *findingsWithSlugs
		var finalFindings []string

		if len(cleanedFindings) > 0 {
			finalMap = rp.buildFilteredFindingsMap(cleanedFindings, findingsMap)
			finalFindings = cleanedFindings
		} else {
			finalMap = findingsMap
			finalFindings = allFindings
		}

		// Calculate criticality for unclassified domain
		slugs := rp.extractSlugs(finalFindings, finalMap)
		assetCriticality := criticality.CalculateCriticality(domainResult.Domain, domainResult.Title, slugs)

		// Build finding items
		findingItems := rp.buildFindingItems(finalFindings, finalMap, templates)

		// Calculate headers grade
		findingsDB := findings.GetGlobalFindingsMap()
		headersGrade := findings.CalculateHeadersGrade(findingItems, findingsDB)

		// Calculate True Risk Range
		trueRiskRange := truerisk.CalculateTrueRiskRange(
			float64(assetCriticality.Score),
			findingItems,
			rp.industryInfo,
		)

		// Extract URL metadata
		url, ip := rp.extractURLMetadata(templates)

		// Add to other domains collection
		rp.otherDomains = append(rp.otherDomains, &findings.Discovery{
			Domain:        domainResult.Domain,
			Title:         domainResult.Title,
			Description:   domainResult.Description,
			Discovered:    "Other",
			FindingItems:  findingItems,
			Criticality:   assetCriticality,
			TrueRiskRange: trueRiskRange,
			HeadersGrade:  headersGrade,
			URL:           url,
			IP:            ip,
		})
	}
}

// findingsWithSlugs holds both display names and slug mapping
type findingsWithSlugs struct {
	displayNames      []string
	displayNameToSlug map[string]string
}

// extractFindingsWithSlugs separates the combined "displayName|slug" format
func (rp *ResultProcessor) extractFindingsWithSlugs(findings map[string]bool) *findingsWithSlugs {
	displayNames := make([]string, 0, len(findings))
	displayNameToSlug := make(map[string]string)

	for combined := range findings {
		parts := strings.Split(combined, "|")
		if len(parts) == 2 {
			displayName := parts[0]
			slug := parts[1]
			displayNames = append(displayNames, displayName)
			displayNameToSlug[displayName] = slug
		} else {
			// Fallback for items without slugs (shouldn't happen)
			logger := logger.GetLogger()
			logger.Warning().Msgf("Finding without slug detected: %s (using fallback)", combined)
			displayNames = append(displayNames, combined)
			displayNameToSlug[combined] = strings.ToLower(strings.ReplaceAll(combined, " ", "-"))
		}
	}

	sort.Strings(displayNames)
	return &findingsWithSlugs{
		displayNames:      displayNames,
		displayNameToSlug: displayNameToSlug,
	}
}

// buildFindingItems creates findings.FindingItem array from display names
func (rp *ResultProcessor) buildFindingItems(displayNames []string, findingsMap *findingsWithSlugs, templates map[string]*nuclei.StoredResult) []*findings.FindingItem {
	logger := logger.GetLogger()
	items := make([]*findings.FindingItem, 0, len(displayNames))

	// Get the domain from the first template result (all templates are for the same domain)
	var currentDomain string
	for _, template := range templates {
		if template.Host != "" {
			currentDomain = template.Host
			break
		}
	}

	for _, displayName := range displayNames {
		slug, exists := findingsMap.displayNameToSlug[displayName]
		if !exists {
			logger.Debug().Msgf("Slug not found for display name %s, using fallback", displayName)
			slug = strings.ToLower(strings.ReplaceAll(displayName, " ", "-"))
		}

		// Skip if marked as false positive
		if rp.falsePositives != nil && rp.falsePositives[slug] {
			logger.Debug().Msgf("Skipping false positive: %s (display: %s)", slug, displayName)
			continue
		}

		item := findings.NewFindingItem(slug)

		// If display_as is "link", populate Values from nuclei results
		// Only include URLs that belong to the current domain
		if item.DisplayAs == "link" {
			valueSet := make(map[string]bool) // Deduplicate URLs
			for _, template := range templates {
				if template.Findings != nil {
					if urls, ok := template.Findings[slug]; ok {
						for _, url := range urls {
							// Only include URLs that contain the current domain
							if currentDomain != "" && strings.Contains(url, currentDomain) {
								if !valueSet[url] {
									item.Values = append(item.Values, url)
									valueSet[url] = true
								}
							}
						}
					}
				}
			}
		}

		items = append(items, item)
	}
	return items
}

// updateSummary updates global summary counters
func (rp *ResultProcessor) updateSummary(domainResult *common.DomainResult) {
	rp.summary.TotalDomains++

	// Count total detections from findings
	rp.summary.TotalDetections += len(domainResult.Findings)

	// Count live domains (domains with any findings)
	if len(domainResult.Findings) > 0 {
		rp.summary.LiveExposedDomains++
	}

	// Check for API usage in web apps
	if domainResult.Discovered == "WebApp" {
		for finding := range domainResult.Findings {
			if finding == "Using API" {
				rp.summary.DomainsUsingAPI++
				break
			}
		}
	}
}

// securityGradeToSortValue converts security rating grade to numeric value for sorting
// Lower values = worse security (F=0, D=1, C=2, B=3, A=4, A+=5)
func securityGradeToSortValue(grade string) int {
	switch grade {
	case "F":
		return 0
	case "D":
		return 1
	case "C":
		return 2
	case "B":
		return 3
	case "A":
		return 4
	case "A+":
		return 5
	default:
		return -1 // No grade
	}
}

// buildReport constructs the final report
func (rp *ResultProcessor) buildReport() *common.ExposureReport {
	logger := logger.GetLogger()
	logger.Debug().Msgf("Building final report: %d APIs, %d API specs, %d AI assets, %d web apps",
		len(rp.apis), len(rp.apiSpecs), len(rp.aiAssets), len(rp.webApps))

	// Sort results by TruRisk score descending (highest risk first)
	sort.Slice(rp.apis, func(i, j int) bool {
		// Sort by TruRisk Max score descending (highest risk first)
		if rp.apis[i].TrueRiskRange != nil && rp.apis[j].TrueRiskRange != nil {
			if rp.apis[i].TrueRiskRange.Max != rp.apis[j].TrueRiskRange.Max {
				return rp.apis[i].TrueRiskRange.Max > rp.apis[j].TrueRiskRange.Max
			}
		}
		// Fallback to domain name for ties
		return rp.apis[i].Domain < rp.apis[j].Domain
	})
	sort.Slice(rp.apiSpecs, func(i, j int) bool {
		// Sort by TruRisk Max score descending (highest risk first)
		if rp.apiSpecs[i].TrueRiskRange != nil && rp.apiSpecs[j].TrueRiskRange != nil {
			if rp.apiSpecs[i].TrueRiskRange.Max != rp.apiSpecs[j].TrueRiskRange.Max {
				return rp.apiSpecs[i].TrueRiskRange.Max > rp.apiSpecs[j].TrueRiskRange.Max
			}
		}
		return rp.apiSpecs[i].Domain < rp.apiSpecs[j].Domain
	})
	sort.Slice(rp.aiAssets, func(i, j int) bool {
		// Sort by TruRisk Max score descending (highest risk first)
		if rp.aiAssets[i].TrueRiskRange != nil && rp.aiAssets[j].TrueRiskRange != nil {
			if rp.aiAssets[i].TrueRiskRange.Max != rp.aiAssets[j].TrueRiskRange.Max {
				return rp.aiAssets[i].TrueRiskRange.Max > rp.aiAssets[j].TrueRiskRange.Max
			}
		}
		return rp.aiAssets[i].Domain < rp.aiAssets[j].Domain
	})
	sort.Slice(rp.webApps, func(i, j int) bool {
		// Sort by TruRisk Max score descending (highest risk first)
		if rp.webApps[i].TrueRiskRange != nil && rp.webApps[j].TrueRiskRange != nil {
			if rp.webApps[i].TrueRiskRange.Max != rp.webApps[j].TrueRiskRange.Max {
				return rp.webApps[i].TrueRiskRange.Max > rp.webApps[j].TrueRiskRange.Max
			}
		}
		return rp.webApps[i].Domain < rp.webApps[j].Domain
	})
	sort.Slice(rp.otherDomains, func(i, j int) bool {
		// Sort by TruRisk Max score descending (highest risk first)
		if rp.otherDomains[i].TrueRiskRange != nil && rp.otherDomains[j].TrueRiskRange != nil {
			if rp.otherDomains[i].TrueRiskRange.Max != rp.otherDomains[j].TrueRiskRange.Max {
				return rp.otherDomains[i].TrueRiskRange.Max > rp.otherDomains[j].TrueRiskRange.Max
			}
		}
		return rp.otherDomains[i].Domain < rp.otherDomains[j].Domain
	})

	// Build technologies list from slugs, filtering by ShowInTech flag for top 5
	// and setting their usage counts
	var techItems []*findings.FindingItem
	for slug := range rp.technologies {
		// Skip if marked as false positive
		if rp.falsePositives != nil && rp.falsePositives[slug] {
			logger.Debug().Msgf("Skipping false positive technology (top 5): %s", slug)
			continue
		}

		item := findings.NewFindingItem(slug)
		if item.ShowInTech {
			// Set the count from techCounts map
			item.Count = rp.techCounts[slug]
			techItems = append(techItems, item)
		}
	}

	// Sort by count descending (most used first), then by display name for ties
	sort.Slice(techItems, func(i, j int) bool {
		if techItems[i].Count != techItems[j].Count {
			return techItems[i].Count > techItems[j].Count
		}
		return techItems[i].GetDisplayName() < techItems[j].GetDisplayName()
	})

	// Create top 5 list for first page
	top5 := techItems
	if len(techItems) > 5 {
		top5 = techItems[:5]
	}

	// Build technologies list for detailed section (only show_in_tech=true)
	var allTechItems []*findings.FindingItem
	for slug := range rp.technologies {
		// Skip if marked as false positive
		if rp.falsePositives != nil && rp.falsePositives[slug] {
			logger.Debug().Msgf("Skipping false positive technology: %s", slug)
			continue
		}

		item := findings.NewFindingItem(slug)
		// Only include technologies marked as show_in_tech=true
		if !item.ShowInTech {
			continue
		}
		// Set the count from techCounts map
		item.Count = rp.techCounts[slug]
		allTechItems = append(allTechItems, item)
	}

	// Sort all technologies by count descending
	sort.Slice(allTechItems, func(i, j int) bool {
		if allTechItems[i].Count != allTechItems[j].Count {
			return allTechItems[i].Count > allTechItems[j].Count
		}
		return allTechItems[i].GetDisplayName() < allTechItems[j].GetDisplayName()
	})

	// Calculate summary counts from actual collections
	rp.summary.APIServers = len(rp.apis)
	rp.summary.APISpecificationsFound = len(rp.apiSpecs)
	rp.summary.AIAssetsFound = len(rp.aiAssets)
	rp.summary.WebAppsFound = len(rp.webApps)

	// Calculate total apps by counting unique domains across all collections (avoid double-counting)
	uniqueDomains := make(map[string]bool)
	for _, app := range rp.apis {
		uniqueDomains[app.Domain] = true
	}
	for _, app := range rp.apiSpecs {
		uniqueDomains[app.Domain] = true
	}
	for _, app := range rp.aiAssets {
		uniqueDomains[app.Domain] = true
	}
	for _, app := range rp.webApps {
		uniqueDomains[app.Domain] = true
	}
	rp.summary.TotalApps = len(uniqueDomains)

	// Calculate criticality distributions for each asset type
	rp.summary.APICriticality = rp.calculateCriticalityDistribution(rp.apis)
	rp.summary.APISpecCriticality = rp.calculateCriticalityDistribution(rp.apiSpecs)
	rp.summary.AIAssetCriticality = rp.calculateCriticalityDistribution(rp.aiAssets)
	rp.summary.WebAppCriticality = rp.calculateCriticalityDistribution(rp.webApps)

	// Calculate security metrics from technology vulnerabilities
	rp.summary.Security = rp.calculateSecurityMetrics(allTechItems)

	logger.Debug().Msgf("Summary calculated: %d total apps, %d live domains, %d detections",
		rp.summary.TotalApps, rp.summary.LiveExposedDomains, rp.summary.TotalDetections)

	return &common.ExposureReport{
		Summary: rp.summary,
		Technologies: &common.TechnologiesDetected{
			Count:           len(techItems),
			Technologies:    top5,         // Top 5 for first page (show_in_tech=true only)
			AllTechnologies: allTechItems, // All technologies for detailed section (show_in_tech=true only)
		},
		APIServers:    rp.apis,
		APISpecsFound: rp.apiSpecs,
		AIAssetsFound: rp.aiAssets,
		WebAppsFound:  rp.webApps,
		OtherDomains:  rp.otherDomains,
	}
}

// ResultProcessor helper methods

func (rp *ResultProcessor) classifyAsAPI(templates map[string]*nuclei.StoredResult, findings []string) string {
	hasServerDetection := false
	hasDomainPattern := false

	// Check for specific API detection types
	for _, template := range templates {
		if template.Findings != nil {
			for slug := range template.Findings {
				// Confirmed API: serving JSON or XML
				if slug == "api.server.json" || slug == "api.server.xml" {
					hasServerDetection = true
				}
				// Potential API: domain pattern only
				if slug == "api.domain_pattern" {
					hasDomainPattern = true
				}
			}
		}
	}

	// Server detection takes precedence (confirmed)
	if hasServerDetection {
		return "Confirmed API Endpoint"
	}
	// Domain pattern only (potential)
	if hasDomainPattern {
		return "Potential API Endpoint"
	}
	return ""
}

func (rp *ResultProcessor) classifyAsWebApp(templates map[string]*nuclei.StoredResult) string {
	hasWebApp := false

	// Check for web app indicators using classification metadata from findings.json
	// Look in both "frontend-tech-detection" and "" (empty template ID from aggregated results)
	for templateID, template := range templates {
		if (templateID == "frontend-tech-detection" || templateID == "") && template.Findings != nil {
			for slug := range template.Findings {
				// Look up the finding item and check its classification
				item := findings.NewFindingItem(slug)
				if rp.hasClassification(item, "webapp") {
					hasWebApp = true
					break
				}
			}
			if hasWebApp {
				break
			}
		}
	}

	// Backend/Frontend tech always makes it a WebApp
	if hasWebApp {
		return "Web App"
	}

	return ""
}

// hasClassification checks if a findings.FindingItem has a specific classification tag
// Classifications with "~" prefix are ignored for classification purposes (only shown in findings)
func (rp *ResultProcessor) hasClassification(item *findings.FindingItem, classification string) bool {
	for _, c := range item.Classification {
		// Skip classifications with "~" prefix (they're only for display, not classification)
		if strings.HasPrefix(c, "~") {
			continue
		}
		if c == classification {
			return true
		}
	}
	return false
}

// hasClassificationForDisplay checks if a findings.FindingItem has a specific classification tag for display
// Includes both regular classifications and "~" prefixed ones
func (rp *ResultProcessor) hasClassificationForDisplay(item *findings.FindingItem, classification string) bool {
	for _, c := range item.Classification {
		// Match both "webapp" and "~webapp"
		if c == classification || c == "~"+classification {
			return true
		}
	}
	return false
}

func (rp *ResultProcessor) classifyAsAPISpec(templates map[string]*nuclei.StoredResult) string {
	// Check all templates for API-Spec classification using metadata
	for _, template := range templates {
		if template.Findings != nil {
			for slug := range template.Findings {
				item := findings.NewFindingItem(slug)
				if rp.hasClassification(item, "api-spec") {
					return "API Specification"
				}
			}
		}
	}
	return ""
}

func (rp *ResultProcessor) classifyAsAI(templates map[string]*nuclei.StoredResult) string {
	// Check all templates for AI classification using metadata
	for _, template := range templates {
		if template.Findings != nil {
			for slug := range template.Findings {
				item := findings.NewFindingItem(slug)
				if rp.hasClassification(item, "ai") {
					return "AI Service"
				}
			}
		}
	}
	return ""
}

func (rp *ResultProcessor) isTechnologyTemplate(templateID string) bool {
	techTemplates := map[string]bool{
		"":                        true, // Empty template ID = aggregated results from all templates
		"frontend-tech-detection": true, // All technologies: frontend, backend, API, infrastructure, auth
		"ai-detection":            true, // AI technologies: OpenAI, Anthropic, Ollama, MCP, Vector DBs
		"openapi":                 true, // API spec: OpenAPI
		"swagger-api":             true, // API spec: Swagger
		"postman-collection":      true, // API spec: Postman
		"wadl-api":                true, // API spec: WADL
		"wsdl-api":                true, // API spec: WSDL
	}
	return techTemplates[templateID]
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

// filterFindingsByClassification filters findings to only include those with the specified classification
// Uses hasClassificationForDisplay to include both regular and "~" prefixed classifications
func (rp *ResultProcessor) filterFindingsByClassification(findingsList []string, findingsMap *findingsWithSlugs, classification string) []string {
	var filtered []string
	for _, displayName := range findingsList {
		slug, exists := findingsMap.displayNameToSlug[displayName]
		if !exists {
			continue
		}
		item := findings.NewFindingItem(slug)
		if rp.hasClassificationForDisplay(item, classification) {
			filtered = append(filtered, displayName)
		}
	}
	return filtered
}

// buildFilteredFindingsMap rebuilds a findingsWithSlugs map from filtered display names
func (rp *ResultProcessor) buildFilteredFindingsMap(filteredNames []string, originalMap *findingsWithSlugs) *findingsWithSlugs {
	newMap := &findingsWithSlugs{
		displayNames:      filteredNames,
		displayNameToSlug: make(map[string]string),
	}
	for _, name := range filteredNames {
		if slug, exists := originalMap.displayNameToSlug[name]; exists {
			newMap.displayNameToSlug[name] = slug
		}
	}
	return newMap
}

// extractSlugs converts display names to slugs using the findingsMap
func (rp *ResultProcessor) extractSlugs(displayNames []string, findingsMap *findingsWithSlugs) []string {
	slugs := make([]string, 0, len(displayNames))
	for _, displayName := range displayNames {
		if slug, exists := findingsMap.displayNameToSlug[displayName]; exists {
			slugs = append(slugs, slug)
		}
	}
	return slugs
}

// isGenericTitle checks if a title is too generic to be useful
func (rp *ResultProcessor) isGenericTitle(title string) bool {
	// List of generic title keywords to ignore
	genericTitles := []string{
		"home",
		"homepage",
		"home page",
		"login",
		"log in",
		"signin",
		"sign in",
		"sign-in",
		"welcome",
		"index",
		"default",
		"untitled",
		"404",
		"error",
		"not found",
		"403",
		"forbidden",
		"unauthorized",
		"500",
		"maintenance",
	}

	titleLower := strings.ToLower(strings.TrimSpace(title))

	// Check for exact matches or if the title contains only generic words
	for _, generic := range genericTitles {
		if titleLower == generic || titleLower == generic+"." {
			return true
		}
	}

	return false
}

// calculateCriticalityDistribution counts how many assets fall into each criticality level
func (rp *ResultProcessor) calculateCriticalityDistribution(assets []*findings.Discovery) *findings.CriticalityDistribution {
	if len(assets) == 0 {
		return nil
	}

	dist := &findings.CriticalityDistribution{}
	for _, asset := range assets {
		if asset.Criticality == nil {
			continue
		}
		switch asset.Criticality.Score {
		case 5:
			dist.Critical++
		case 4:
			dist.High++
		case 3:
			dist.Medium++
		case 2:
			dist.Low++
		case 1:
			dist.Minimal++
		}
	}
	return dist
}

// calculateSecurityMetrics aggregates vulnerability and weakness data from technologies
func (rp *ResultProcessor) calculateSecurityMetrics(techItems []*findings.FindingItem) *common.SecurityMetrics {
	if len(techItems) == 0 {
		return nil
	}

	metrics := &common.SecurityMetrics{}
	weaknessMap := make(map[string]*common.WeaknessPattern) // ID -> pattern for aggregation

	// Aggregate vulnerability stats and weaknesses from all technologies
	for _, tech := range techItems {
		if tech.Security == nil {
			continue
		}

		// Aggregate CVE stats
		if tech.Security.CVE != nil {
			metrics.TotalVulnerabilities += tech.Security.CVE.Stats.Total
			metrics.CriticalCount += tech.Security.CVE.Stats.Critical
			metrics.HighCount += tech.Security.CVE.Stats.High
			metrics.MediumCount += tech.Security.CVE.Stats.Medium
			metrics.LowCount += tech.Security.CVE.Stats.Low
			metrics.KEVCount += tech.Security.CVE.Stats.KEV
		}

		// Aggregate weaknesses
		if tech.Security.Weaknesses != nil {
			for _, cwe := range tech.Security.Weaknesses.Stats.TopCategories {
				if existing, ok := weaknessMap[cwe.ID]; ok {
					// Add to existing count
					existing.Count += cwe.Count
				} else {
					// Add new weakness
					weaknessMap[cwe.ID] = &common.WeaknessPattern{
						ID:    cwe.ID,
						Name:  cwe.Name,
						Count: cwe.Count,
					}
				}
			}
		}
	}

	// Convert weakness map to sorted slice (top 10 by count)
	weaknesses := make([]*common.WeaknessPattern, 0, len(weaknessMap))
	for _, pattern := range weaknessMap {
		weaknesses = append(weaknesses, pattern)
	}

	// Sort by count descending
	sort.Slice(weaknesses, func(i, j int) bool {
		if weaknesses[i].Count != weaknesses[j].Count {
			return weaknesses[i].Count > weaknesses[j].Count
		}
		return weaknesses[i].ID < weaknesses[j].ID // Tie break by ID
	})

	// Keep top 10
	if len(weaknesses) > 10 {
		weaknesses = weaknesses[:10]
	}

	// Calculate total count for percentage calculation
	totalCount := 0
	for _, wp := range weaknesses {
		totalCount += wp.Count
	}

	// Convert to []WeaknessPattern (not pointers) and calculate percentages
	metrics.TopWeaknesses = make([]common.WeaknessPattern, len(weaknesses))
	for i, wp := range weaknesses {
		percentage := 0.0
		if totalCount > 0 {
			percentage = float64(wp.Count) / float64(totalCount) * 100.0
		}
		metrics.TopWeaknesses[i] = common.WeaknessPattern{
			ID:         wp.ID,
			Name:       wp.Name,
			Count:      wp.Count,
			Percentage: percentage,
		}
	}

	return metrics
}

// CalculateDomainMetrics calculates domain categorization metrics from AssetDiscoveryResult
func CalculateDomainMetrics(result *domainscan.AssetDiscoveryResult) *common.DomainMetrics {
	if result == nil || result.Domains == nil {
		return nil
	}

	metrics := &common.DomainMetrics{
		TotalDiscovered: len(result.Domains),
	}

	now := time.Now()
	expiringSoonThreshold := now.AddDate(0, 0, 30) // 30 days from now

	for _, entry := range result.Domains {
		// Internet Exposed: Any HTTP status means reachable
		if entry.Status != 0 || entry.Reachable {
			metrics.InternetExposed++
		} else {
			// Not Reachable: No HTTP response
			metrics.NotReachable++

			// Passive Only: Discovered via passive sources but not HTTP accessible
			hadPassiveScan := false
			for _, source := range entry.Sources {
				if source.Type == "passive" {
					hadPassiveScan = true
					break
				}
			}
			if hadPassiveScan {
				metrics.PassiveOnly++
			}
		}

		// Track redirects
		if entry.Redirect != nil && entry.Redirect.IsRedirect {
			metrics.WithRedirects++
		}

		// Track certificates
		if entry.Certificate != nil {
			metrics.WithCertificates++

			// Check if certificate is expired
			if !entry.Certificate.ExpiresOn.IsZero() && entry.Certificate.ExpiresOn.Before(now) {
				metrics.ExpiredCerts++
			}

			// Check if certificate is expiring soon (within 30 days)
			if !entry.Certificate.ExpiresOn.IsZero() &&
			   entry.Certificate.ExpiresOn.After(now) &&
			   entry.Certificate.ExpiresOn.Before(expiringSoonThreshold) {
				metrics.ExpiringSoonCerts++
			}
		}
	}

	return metrics
}

// extractURLMetadata extracts URL and IP from the first available template result
func (rp *ResultProcessor) extractURLMetadata(templates map[string]*nuclei.StoredResult) (url, ip string) {
	// Find first result with URL metadata
	for _, result := range templates {
		if result.URL != "" {
			return result.URL, result.IP
		}
	}
	return "", ""
}

// LoadTRUInsights loads threat landscape assessment JSON from results directory
func LoadTRUInsights(domain string) (*TRUInsightsData, error) {
	logger := logger.GetLogger()

	// Load threat landscape JSON
	jsonPath := fmt.Sprintf("results/%s/tru-insights-TAS.json", domain)

	data, err := os.ReadFile(jsonPath)
	if err != nil {
		// File doesn't exist - threat landscape not generated yet
		logger.Debug().Msgf("Threat landscape not found at %s", jsonPath)
		return nil, nil
	}

	// Parse threat_landscape structure
	var landscapeData struct {
		ThreatLandscape TRUInsightsData `json:"threat_landscape"`
	}

	if err := json.Unmarshal(data, &landscapeData); err != nil {
		logger.Warning().Msgf("Failed to parse threat landscape JSON: %v", err)
		return nil, fmt.Errorf("failed to parse threat landscape: %w", err)
	}

	logger.Info().Msgf("Loaded threat landscape with %d top insights", len(landscapeData.ThreatLandscape.ThreatAssessment.TopInsights))
	return &landscapeData.ThreatLandscape, nil
}
