# Criticality Scoring - Integration Plan

**Date:** October 17, 2025
**Status:** Ready for Implementation
**Target:** pkg/webexposure package

## Current Flow

```
1. Discovery (discovery.go)
   ↓
2. Nuclei Scan (nuclei.go, nuclei_results.go)
   ↓
3. Results Grouping (scanner.go)
   GroupByDomain() → GroupedResults
   ↓
4. Report Generation (report.go)
   ProcessAllDomains() → ExposureReport
   ├── processDomain() - per domain processing
   ├── classifyAndAdd() - domain classification
   └── buildReport() - final report
   ↓
5. HTML/PDF Generation (report_html.go, report_pdf.go)
```

## Injection Point

**Primary Location:** `pkg/webexposure/report.go` in `processDomain()` function

**Why here:**
- Already have domain name
- Already have page title (from findings)
- Already have all findings/technologies
- Perfect place to calculate criticality before classification

## Implementation Steps

### Step 1: Add Criticality Types

**File:** `pkg/webexposure/report_types.go`

```go
// Add to Discovery struct
type Discovery struct {
	Domain       string         `json:"domain"`
	Title        string         `json:"title,omitempty"`
	Description  string         `json:"description,omitempty"`
	Discovered   string         `json:"discovered"`
	FindingItems []*FindingItem `json:"findings"`
	Criticality  *Criticality   `json:"criticality,omitempty"` // NEW
}

// Add new Criticality type
type Criticality struct {
	Score    float64  `json:"score"`    // 0.1 to 5.0
	Category string   `json:"category"` // CRITICAL, HIGH, MEDIUM, LOW
	Factors  []string `json:"factors"`  // Human-readable scoring factors
}

// Add to Summary for aggregated statistics
type Summary struct {
	TotalDomains           int `json:"total_domains"`
	LiveExposedDomains     int `json:"live_exposed_domains"`
	TotalDetections        int `json:"total_detections"`
	APIsFound              int `json:"apis_found"`
	APISpecificationsFound int `json:"api_specifications_found"`
	AIAssetsFound          int `json:"ai_assets_found"`
	WebAppsFound           int `json:"web_apps_found"`
	DomainsUsingAPI        int `json:"domains_using_api"`
	TotalApps              int `json:"total_apps"`
	TotalCriticalCVEs      int `json:"total_critical_cves"`
	TotalHighCVEs          int `json:"total_high_cves"`
	TotalKEVCVEs           int `json:"total_kev_cves"`
	// NEW: Criticality statistics
	CriticalDomains        int `json:"critical_domains,omitempty"`
	HighDomains            int `json:"high_domains,omitempty"`
	MediumDomains          int `json:"medium_domains,omitempty"`
	LowDomains             int `json:"low_domains,omitempty"`
}
```

### Step 2: Create Criticality Scoring Module

**File:** `pkg/webexposure/criticality.go` (NEW)

```go
package webexposure

import (
	"regexp"
	"strings"
)

// Domain pattern weights
var criticalDomainPatterns = map[string]float64{
	"pay.":      1.5,
	"payment.":  1.5,
	"checkout.": 1.5,
	"auth.":     1.2,
	"sso.":      1.2,
	"portal.":   0.7,
	"portal-":   0.7,
	"admin.":    0.8,
	"console.":  0.8,
	"api.":      0.5,
	"-api.":     0.5,
	"api-":      0.5,
	"www.":      0.5,
}

var devPatterns = map[string]float64{
	"dev.":     -0.7,
	"dev-":     -0.7,
	".dev.":    -0.7,
	"test.":    -0.7,
	"test-":    -0.7,
	".test.":   -0.7,
	"staging.": -0.6,
	"staging-": -0.6,
	"sandbox.": -0.7,
	"demo.":    -0.6,
	"uat.":     -0.6,
	"qa.":      -0.6,
}

// Title keyword weights
var titleKeywords = map[string]float64{
	"portal":    0.6,
	"login":     0.5,
	"admin":     0.7,
	"dashboard": 0.5,
	"console":   0.6,
	"enterprise": 0.4,
	"platform":   0.4,
	"payment":    0.8,
	"checkout":   0.8,
	"api":        0.3,
}

var titleNegative = map[string]float64{
	"404":        -0.5,
	"not found":  -0.5,
	"403":        -0.5,
	"forbidden":  -0.5,
	"error":      -0.4,
	"test":       -0.7,
	"development": -0.8,
	"staging":     -0.6,
	"demo":        -0.5,
}

// Findings weights (based on slug)
var findingsWeights = map[string]float64{
	"auth.enterprise.saml_sso":         0.6,
	"auth.mfa":                         0.5,
	"auth.traditional.basic_auth":      0.2,
	"auth.traditional.registration":    0.4,
	"auth.traditional.password_recovery": 0.3,
	"backend.cms.wordpress":            0.3,
	"backend.cms.drupal":               0.3,
	"api.domain_pattern":               0.4,
	"gateway.cloudflare":               0.2,
}

// CalculateCriticality calculates criticality score for a domain
func CalculateCriticality(domain, title string, findingSlugs []string) *Criticality {
	logger := GetLogger()

	baseScore := 1.0
	factors := []string{}

	// 1. Domain pattern scoring
	domainScore, domainFactors := scoreDomainPattern(domain)
	factors = append(factors, domainFactors...)

	// 2. Title keyword scoring
	titleScore, titleFactors := scoreTitleKeywords(title)
	factors = append(factors, titleFactors...)

	// 3. Findings scoring
	findingsScore, findingsFactors := scoreFindingsArray(findingSlugs)
	factors = append(factors, findingsFactors...)

	// Calculate final score
	totalScore := baseScore + domainScore + titleScore + findingsScore

	// Apply bounds
	finalScore := totalScore
	if finalScore < 0.1 {
		finalScore = 0.1
	}
	if finalScore > 5.0 {
		finalScore = 5.0
	}

	// Round to 1 decimal place
	finalScore = float64(int(finalScore*10+0.5)) / 10

	// Determine category
	category := ""
	if finalScore >= 3.5 {
		category = "CRITICAL"
	} else if finalScore >= 2.0 {
		category = "HIGH"
	} else if finalScore >= 1.0 {
		category = "MEDIUM"
	} else {
		category = "LOW"
	}

	logger.Debug().Msgf("Criticality for %s: score=%.1f, category=%s, factors=%v",
		domain, finalScore, category, factors)

	return &Criticality{
		Score:    finalScore,
		Category: category,
		Factors:  factors,
	}
}

func scoreDomainPattern(domain string) (float64, []string) {
	score := 0.0
	factors := []string{}
	domainLower := strings.ToLower(domain)

	// Check dev/test patterns first (override)
	for pattern, weight := range devPatterns {
		if strings.Contains(domainLower, pattern) {
			score = weight
			factors = append(factors, fmt.Sprintf("Dev/test pattern '%s': %+.1f", pattern, weight))
			return score, factors
		}
	}

	// Check critical patterns
	for pattern, weight := range criticalDomainPatterns {
		if strings.Contains(domainLower, pattern) {
			score += weight
			factors = append(factors, fmt.Sprintf("Domain '%s': %+.1f", pattern, weight))
		}
	}

	return score, factors
}

func scoreTitleKeywords(title string) (float64, []string) {
	if title == "" {
		return 0.0, []string{}
	}

	score := 0.0
	factors := []string{}
	titleLower := strings.ToLower(title)

	// Check for error page (higher priority)
	if isErrorPage(title) {
		score -= 0.8
		factors = append(factors, "Error page: -0.8")
		return score, factors
	}

	// Check negative patterns
	for keyword, weight := range titleNegative {
		if strings.Contains(titleLower, keyword) {
			score += weight
			factors = append(factors, fmt.Sprintf("Title '%s': %+.1f", keyword, weight))
		}
	}

	// Check positive keywords
	for keyword, weight := range titleKeywords {
		if strings.Contains(titleLower, keyword) {
			score += weight
			factors = append(factors, fmt.Sprintf("Title '%s': %+.1f", keyword, weight))
		}
	}

	return score, factors
}

func isErrorPage(title string) bool {
	if title == "" {
		return false
	}

	titleLower := strings.ToLower(title)
	errorPatterns := [][]string{
		{"404", "not found"},
		{"403", "forbidden"},
		{"500", "internal server error"},
		{"503", "service unavailable"},
	}

	for _, pattern := range errorPatterns {
		hasAll := true
		for _, keyword := range pattern {
			if !strings.Contains(titleLower, keyword) {
				hasAll = false
				break
			}
		}
		if hasAll {
			return true
		}
	}

	return false
}

func scoreFindingsArray(findingSlugs []string) (float64, []string) {
	if len(findingSlugs) == 0 {
		return 0.0, []string{}
	}

	score := 0.0
	factors := []string{}
	authCount := 0

	for _, slug := range findingSlugs {
		if weight, exists := findingsWeights[slug]; exists && weight > 0 {
			score += weight
			// Shorten slug for display
			parts := strings.Split(slug, ".")
			shortName := parts[len(parts)-1]
			factors = append(factors, fmt.Sprintf("Finding '%s': %+.1f", shortName, weight))

			if strings.HasPrefix(slug, "auth.") {
				authCount++
			}
		}
	}

	// Multiple auth bonus
	if authCount >= 3 {
		bonus := 0.3
		score += bonus
		factors = append(factors, fmt.Sprintf("Multiple auth (%d types): %+.1f", authCount, bonus))
	}

	return score, factors
}
```

### Step 3: Integrate into processDomain()

**File:** `pkg/webexposure/report.go`

**Location:** In `processDomain()` function, after building `domainResult` but before `classifyAndAdd()`

```go
// In processDomain() function, around line 145

func (rp *ResultProcessor) processDomain(domain string, templates map[string]*StoredResult) {
	logger := GetLogger()
	logger.Debug().Msgf("Processing domain: %s with %d templates", domain, len(templates))

	domainResult := &DomainResult{
		Domain:       domain,
		Findings:     make(map[string]bool),
		Technologies: make(map[string]bool),
	}

	// ... existing code to extract title, description, merge findings ...

	// Step 2: Collect technologies from allFindings
	for slug := range allFindings {
		domainResult.Technologies[slug] = true
		// ... existing code ...
	}

	// NEW: Calculate criticality score
	// Extract finding slugs for criticality calculation
	findingSlugs := make([]string, 0, len(allFindings))
	for slug := range allFindings {
		findingSlugs = append(findingSlugs, slug)
	}

	// Calculate criticality
	criticality := CalculateCriticality(domain, domainResult.Title, findingSlugs)
	domainResult.Criticality = criticality // Store in DomainResult

	logger.Debug().Msgf("Domain %s criticality: score=%.1f, category=%s",
		domain, criticality.Score, criticality.Category)

	// Step 3: Classify and add to collections
	rp.classifyAndAdd(domainResult, templates)

	// ... rest of existing code ...
}
```

### Step 4: Pass Criticality to Discovery Objects

**File:** `pkg/webexposure/report.go`

**Location:** In `classifyAndAdd()` function, when creating Discovery objects

```go
// Modify each Discovery creation to include criticality
// Example for WebApp:

rp.webApps = append(rp.webApps, &Discovery{
	Domain:       domainResult.Domain,
	Title:        domainResult.Title,
	Description:  domainResult.Description,
	Discovered:   webAppClassification,
	FindingItems: rp.buildFindingItems(finalFindings, finalMap, templates),
	Criticality:  domainResult.Criticality, // NEW
})

// Repeat for API, APISpec, and AIAssets collections
```

### Step 5: Update DomainResult Type

**File:** `pkg/webexposure/report_types.go`

```go
// Add Criticality field to DomainResult
type DomainResult struct {
	Domain       string
	Title        string
	Description  string
	Findings     map[string]bool
	Technologies map[string]bool
	Discovered   string
	Criticality  *Criticality // NEW
}
```

### Step 6: Update Summary Statistics

**File:** `pkg/webexposure/report.go`

**Location:** In `buildReport()` function

```go
func (rp *ResultProcessor) buildReport() *ExposureReport {
	// ... existing code ...

	// NEW: Calculate criticality statistics
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	// Count across all collections
	allDiscoveries := append([]*Discovery{}, rp.apis...)
	allDiscoveries = append(allDiscoveries, rp.apiSpecs...)
	allDiscoveries = append(allDiscoveries, rp.aiAssets...)
	allDiscoveries = append(allDiscoveries, rp.webApps...)

	for _, discovery := range allDiscoveries {
		if discovery.Criticality != nil {
			switch discovery.Criticality.Category {
			case "CRITICAL":
				criticalCount++
			case "HIGH":
				highCount++
			case "MEDIUM":
				mediumCount++
			case "LOW":
				lowCount++
			}
		}
	}

	// Set in summary
	rp.summary.CriticalDomains = criticalCount
	rp.summary.HighDomains = highCount
	rp.summary.MediumDomains = mediumCount
	rp.summary.LowDomains = lowCount

	// ... rest of existing code ...
}
```

### Step 7: Update HTML Report Template

**File:** `templates/report.html`

**Add criticality badge to domain listings:**

```html
<!-- For each domain in APIs, WebApps, etc. -->
{{range .APIsFound}}
<div class="domain-item">
    <div class="domain-header">
        <h3>{{.Domain}}</h3>
        {{if .Criticality}}
        <span class="criticality-badge criticality-{{.Criticality.Category | lower}}">
            {{.Criticality.Category}}
        </span>
        <span class="criticality-score">{{.Criticality.Score}}</span>
        {{end}}
    </div>
    <!-- ... rest of domain content ... -->
</div>
{{end}}
```

**Add CSS for badges:**

```css
.criticality-badge {
    padding: 4px 12px;
    border-radius: 4px;
    font-weight: bold;
    font-size: 0.85em;
}

.criticality-critical {
    background-color: #dc3545;
    color: white;
}

.criticality-high {
    background-color: #fd7e14;
    color: white;
}

.criticality-medium {
    background-color: #ffc107;
    color: #000;
}

.criticality-low {
    background-color: #28a745;
    color: white;
}

.criticality-score {
    margin-left: 8px;
    font-weight: bold;
    color: #666;
}
```

## Testing Plan

### Phase 1: Unit Tests

**File:** `pkg/webexposure/criticality_test.go` (NEW)

```go
func TestCalculateCriticality(t *testing.T) {
	tests := []struct{
		domain   string
		title    string
		findings []string
		want     string // category
	}{
		{"portal.example.com", "Portal", []string{"auth.enterprise.saml_sso", "auth.mfa"}, "CRITICAL"},
		{"dev.api.example.com", "Development", []string{}, "LOW"},
		{"api.example.com", "API", []string{}, "HIGH"},
		{"example.com", "404 Not Found", []string{}, "LOW"},
	}

	for _, tt := range tests {
		got := CalculateCriticality(tt.domain, tt.title, tt.findings)
		if got.Category != tt.want {
			t.Errorf("CalculateCriticality(%s) = %s, want %s", tt.domain, got.Category, tt.want)
		}
	}
}
```

### Phase 2: Integration Test

Run on existing qualys.com scan:

```bash
# Already scanned
./bin/web-exposure-detection scan qualys.com --cached

# Should now show criticality in JSON output
jq '.apis_found[0].criticality' results/qualys.com/web-exposure-result.json
```

### Phase 3: HTML Report Verification

```bash
# Generate report
./bin/web-exposure-detection scan qualys.com --cached

# Check HTML report
open results/qualys.com/report.html
# Should see criticality badges on each domain
```

## Migration Path

1. **Week 1:** Implement core criticality.go module + unit tests
2. **Week 2:** Integrate into report.go (types + processDomain)
3. **Week 3:** Update HTML templates, add CSS, test rendering
4. **Week 4:** Full testing on multiple domains, tune weights if needed

## Performance Impact

**Expected overhead per domain:**
- Domain pattern matching: <0.1ms
- Title keyword matching: <0.1ms
- Findings array iteration: <0.5ms
- **Total: <1ms per domain**

For 295 domains (qualys.com): ~300ms overhead (negligible)

## Output Examples

### JSON Output

```json
{
  "apis_found": [
    {
      "domain": "api.example.com",
      "title": "Example API",
      "discovered": "Confirmed API Endpoint",
      "findings": [...],
      "criticality": {
        "score": 2.4,
        "category": "HIGH",
        "factors": [
          "Domain 'api.': +0.5",
          "Title 'api': +0.3",
          "Finding 'domain_pattern': +0.4"
        ]
      }
    }
  ],
  "summary": {
    "total_domains": 295,
    "critical_domains": 6,
    "high_domains": 70,
    "medium_domains": 124,
    "low_domains": 95
  }
}
```

### HTML Report

Domains will show:
```
portal.example.com
[CRITICAL] 4.2 | Portal Login
```

With color-coded badges for visual identification.

## Summary

**Injection Point:** `pkg/webexposure/report.go` → `processDomain()` function

**New Files:**
- `pkg/webexposure/criticality.go` - Scoring logic
- `pkg/webexposure/criticality_test.go` - Unit tests

**Modified Files:**
- `pkg/webexposure/report_types.go` - Add Criticality type
- `pkg/webexposure/report.go` - Call CalculateCriticality()
- `templates/report.html` - Display badges

**Effort:** 2-3 weeks
**Risk:** Low (non-breaking addition)
**Value:** Enables risk prioritization and financial quantification

**Date:** October 17, 2025
