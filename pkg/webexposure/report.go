package webexposure

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// GenerateReport creates an exposure report from grouped Nuclei results
func (s *scanner) GenerateReport(grouped *GroupedResults, targetDomain string) (*ExposureReport, error) {
	// Use the new ResultProcessor for efficient single-pass processing
	processor := NewResultProcessor()

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
func NewResultProcessor() *ResultProcessor {
	return &ResultProcessor{
		summary:      &Summary{},
		technologies: make(map[string]bool),
		techCounts:   make(map[string]int),
	}
}

// ProcessAllDomains processes all domains in a single pass
func (rp *ResultProcessor) ProcessAllDomains(grouped *GroupedResults) *ExposureReport {
	// Reset state
	rp.apis = nil
	rp.apiSpecs = nil
	rp.aiAssets = nil
	rp.webApps = nil
	rp.technologies = make(map[string]bool)
	rp.techCounts = make(map[string]int)
	rp.summary = &Summary{}
	rp.grouped = grouped // Store for later use in building technologies

	// Single pass through all domains
	for domain, templates := range grouped.Domains {
		rp.processDomain(domain, templates)
	}

	// Build final report
	return rp.buildReport()
}

// processDomain processes a single domain's results
func (rp *ResultProcessor) processDomain(domain string, templates map[string]*StoredResult) {
	domainResult := &DomainResult{
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
		item := NewFindingItem(slug)
		displayName := item.GetDisplayName()
		domainResult.Findings[displayName+"|"+slug] = true
	}

	// Step 3: Classify and add to collections
	rp.classifyAndAdd(domainResult, templates)

	// Update global summary
	rp.updateSummary(domainResult)
}

// classifyAndAdd classifies the domain result and adds to appropriate collections
// Domains can appear in multiple categories based on their findings
func (rp *ResultProcessor) classifyAndAdd(domainResult *DomainResult, templates map[string]*StoredResult) {
	// Extract display names and build FindingItems from the combined "displayName|slug" format
	findingsMap := rp.extractFindingsWithSlugs(domainResult.Findings)
	findings := findingsMap.displayNames

	// Check all possible classifications (no priority)
	webAppClassification := rp.classifyAsWebApp(templates)
	apiClassification := rp.classifyAsAPI(templates, findings)
	apiSpecClassification := rp.classifyAsAPISpec(templates)
	aiClassification := rp.classifyAsAI(templates)

	// Helper function to build findings from technologies filtered by classification
	buildTechFindings := func(classification string) (*findingsWithSlugs, []string) {
		techFindingsMap := &findingsWithSlugs{
			displayNames:      make([]string, 0, len(domainResult.Technologies)),
			displayNameToSlug: make(map[string]string),
		}
		for techSlug := range domainResult.Technologies {
			item := NewFindingItem(techSlug)
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
		webappFindings := rp.filterFindingsByClassification(findings, findingsMap, "webapp")
		cleanedFindings := rp.cleanFindingsArray(webappFindings)

		var finalMap *findingsWithSlugs
		var finalFindings []string
		if len(cleanedFindings) == 0 {
			finalMap, finalFindings = buildTechFindings("webapp")
		} else {
			finalMap = rp.buildFilteredFindingsMap(cleanedFindings, findingsMap)
			finalFindings = cleanedFindings
		}

		rp.webApps = append(rp.webApps, &Discovery{
			Domain:       domainResult.Domain,
			Title:        domainResult.Title,
			Description:  domainResult.Description,
			Discovered:   webAppClassification,
			FindingItems: rp.buildFindingItems(finalFindings, finalMap, templates),
		})
		domainResult.Discovered = "WebApp"
	}

	// Add to API collection if it has api classification
	if apiClassification != "" {
		apiFindings := rp.filterFindingsByClassification(findings, findingsMap, "api")
		cleanedFindings := rp.cleanFindingsArray(apiFindings)

		var finalMap *findingsWithSlugs
		var finalFindings []string

		if len(cleanedFindings) > 0 {
			finalMap = rp.buildFilteredFindingsMap(cleanedFindings, findingsMap)
			finalFindings = cleanedFindings
		} else {
			finalMap, finalFindings = buildTechFindings("api")
		}

		rp.apis = append(rp.apis, &Discovery{
			Domain:       domainResult.Domain,
			Title:        domainResult.Title,
			Description:  domainResult.Description,
			Discovered:   apiClassification,
			FindingItems: rp.buildFindingItems(finalFindings, finalMap, templates),
		})
		if domainResult.Discovered == "" {
			domainResult.Discovered = "API"
		}
	}

	// Add to API Spec collection if it has api-spec classification
	if apiSpecClassification != "" {
		apiSpecFindings := rp.filterFindingsByClassification(findings, findingsMap, "api-spec")
		cleanedFindings := rp.cleanFindingsArray(apiSpecFindings)

		var finalMap *findingsWithSlugs
		var finalFindings []string
		if len(cleanedFindings) == 0 {
			finalMap, finalFindings = buildTechFindings("api-spec")
		} else {
			finalMap = rp.buildFilteredFindingsMap(cleanedFindings, findingsMap)
			finalFindings = cleanedFindings
		}

		rp.apiSpecs = append(rp.apiSpecs, &Discovery{
			Domain:       domainResult.Domain,
			Title:        domainResult.Title,
			Description:  domainResult.Description,
			Discovered:   apiSpecClassification,
			FindingItems: rp.buildFindingItems(finalFindings, finalMap, templates),
		})
		if domainResult.Discovered == "" {
			domainResult.Discovered = "APISpec"
		}
	}

	// Add to AI collection if it has ai classification
	if aiClassification != "" {
		aiFindings := rp.filterFindingsByClassification(findings, findingsMap, "ai")
		cleanedFindings := rp.cleanFindingsArray(aiFindings)

		var finalMap *findingsWithSlugs
		var finalFindings []string
		if len(cleanedFindings) == 0 {
			finalMap, finalFindings = buildTechFindings("ai")
		} else {
			finalMap = rp.buildFilteredFindingsMap(cleanedFindings, findingsMap)
			finalFindings = cleanedFindings
		}

		rp.aiAssets = append(rp.aiAssets, &Discovery{
			Domain:       domainResult.Domain,
			Title:        domainResult.Title,
			Description:  domainResult.Description,
			Discovered:   aiClassification,
			FindingItems: rp.buildFindingItems(finalFindings, finalMap, templates),
		})
		if domainResult.Discovered == "" {
			domainResult.Discovered = "AI"
		}
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

// buildFindingItems creates FindingItem array from display names
func (rp *ResultProcessor) buildFindingItems(displayNames []string, findingsMap *findingsWithSlugs, templates map[string]*StoredResult) []*FindingItem {
	items := make([]*FindingItem, 0, len(displayNames))
	for _, displayName := range displayNames {
		slug, exists := findingsMap.displayNameToSlug[displayName]
		if !exists {
			slug = strings.ToLower(strings.ReplaceAll(displayName, " ", "-"))
		}
		item := NewFindingItem(slug)

		// If display_as is "link", populate Values from nuclei results
		if item.DisplayAs == "link" {
			for _, template := range templates {
				if template.Findings != nil {
					if urls, ok := template.Findings[slug]; ok {
						item.Values = append(item.Values, urls...)
					}
				}
			}
		}

		items = append(items, item)
	}
	return items
}

// updateSummary updates global summary counters
func (rp *ResultProcessor) updateSummary(domainResult *DomainResult) {
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

// buildReport constructs the final report
func (rp *ResultProcessor) buildReport() *ExposureReport {
	// Sort results
	sort.Slice(rp.apis, func(i, j int) bool {
		return rp.apis[i].Domain < rp.apis[j].Domain
	})
	sort.Slice(rp.apiSpecs, func(i, j int) bool {
		return rp.apiSpecs[i].Domain < rp.apiSpecs[j].Domain
	})
	sort.Slice(rp.aiAssets, func(i, j int) bool {
		return rp.aiAssets[i].Domain < rp.aiAssets[j].Domain
	})
	sort.Slice(rp.webApps, func(i, j int) bool {
		return rp.webApps[i].Domain < rp.webApps[j].Domain
	})

	// Build technologies list from slugs, filtering by ShowInTech flag for top 5
	// and setting their usage counts
	var techItems []*FindingItem
	for slug := range rp.technologies {
		item := NewFindingItem(slug)
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

	// Build ALL technologies list (including show_in_tech=false) for detailed section
	var allTechItems []*FindingItem
	for slug := range rp.technologies {
		item := NewFindingItem(slug)
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
	rp.summary.APIsFound = len(rp.apis)
	rp.summary.APISpecificationsFound = len(rp.apiSpecs)
	rp.summary.AIAssetsFound = len(rp.aiAssets)
	rp.summary.WebAppsFound = len(rp.webApps)
	rp.summary.TotalApps = rp.summary.APIsFound + rp.summary.AIAssetsFound + rp.summary.WebAppsFound

	return &ExposureReport{
		Summary: rp.summary,
		Technologies: &TechnologiesDetected{
			Count:           len(techItems),
			Technologies:    top5,         // Top 5 for first page (show_in_tech=true only)
			AllTechnologies: allTechItems, // All technologies for detailed section (including show_in_tech=false)
		},
		APIsFound:     rp.apis,
		APISpecsFound: rp.apiSpecs,
		AIAssetsFound: rp.aiAssets,
		WebAppsFound:  rp.webApps,
	}
}

// ResultProcessor helper methods

func (rp *ResultProcessor) classifyAsAPI(templates map[string]*StoredResult, findings []string) string {
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

func (rp *ResultProcessor) classifyAsWebApp(templates map[string]*StoredResult) string {
	hasWebApp := false

	// Check for web app indicators using classification metadata from findings.json
	// Look in both "frontend-tech-detection" and "" (empty template ID from aggregated results)
	for templateID, template := range templates {
		if (templateID == "frontend-tech-detection" || templateID == "") && template.Findings != nil {
			for slug := range template.Findings {
				// Look up the finding item and check its classification
				item := NewFindingItem(slug)
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

// hasClassification checks if a FindingItem has a specific classification tag
// Classifications with "~" prefix are ignored for classification purposes (only shown in findings)
func (rp *ResultProcessor) hasClassification(item *FindingItem, classification string) bool {
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

// hasClassificationForDisplay checks if a FindingItem has a specific classification tag for display
// Includes both regular classifications and "~" prefixed ones
func (rp *ResultProcessor) hasClassificationForDisplay(item *FindingItem, classification string) bool {
	for _, c := range item.Classification {
		// Match both "webapp" and "~webapp"
		if c == classification || c == "~"+classification {
			return true
		}
	}
	return false
}

func (rp *ResultProcessor) classifyAsAPISpec(templates map[string]*StoredResult) string {
	// Check all templates for API-Spec classification using metadata
	for _, template := range templates {
		if template.Findings != nil {
			for slug := range template.Findings {
				item := NewFindingItem(slug)
				if rp.hasClassification(item, "api-spec") {
					return "API Specification"
				}
			}
		}
	}
	return ""
}

func (rp *ResultProcessor) classifyAsAI(templates map[string]*StoredResult) string {
	// Check all templates for AI classification using metadata
	for _, template := range templates {
		if template.Findings != nil {
			for slug := range template.Findings {
				item := NewFindingItem(slug)
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
func (rp *ResultProcessor) filterFindingsByClassification(findings []string, findingsMap *findingsWithSlugs, classification string) []string {
	var filtered []string
	for _, displayName := range findings {
		slug, exists := findingsMap.displayNameToSlug[displayName]
		if !exists {
			continue
		}
		item := NewFindingItem(slug)
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
