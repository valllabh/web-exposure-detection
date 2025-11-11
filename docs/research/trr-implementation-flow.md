# TRR Implementation Flow and Placement

## Current Scan & Report Generation Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. DOMAIN DISCOVERY (scanner/scanner.go)                        │
│    scanner.DiscoverDomains()                                     │
│    └─> Uses domain-scan SDK to find subdomains                  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 2. NUCLEI SCANNING (scanner/scanner.go)                         │
│    scanner.ScanWithNuclei()                                      │
│    └─> Scans each domain with Nuclei templates                  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 3. RESULTS GROUPING (nuclei/nuclei.go)                          │
│    nuclei.GroupResultsByDomain()                                 │
│    └─> Groups findings by domain                                │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 4. REPORT GENERATION (report/report.go)                         │
│    report.GenerateReport() [called from scanner.go:532,570]     │
│    └─> Creates ExposureReport from grouped results              │
│         │                                                        │
│         └─> ProcessAllDomains()                                 │
│              └─> For each domain:                               │
│                   processAPIDomain()                            │
│                   processAPISpecDomain()                        │
│                   processAIAssetDomain()                        │
│                   processWebAppDomain()                         │
│                   processOtherDomain()                          │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 5. OUTPUT GENERATION (scanner/scanner.go)                       │
│    scanner.writeAndGenerateFormats()                            │
│    └─> Writes JSON, generates HTML & PDF                        │
└─────────────────────────────────────────────────────────────────┘
```

---

## Per-Domain Processing Flow (Inside ProcessAllDomains)

**File**: `pkg/webexposure/report/report.go`

For each domain type (WebApp, API, AI Asset, etc.), the flow is:

```go
// CURRENT FLOW (example from processWebAppDomain around line 235-273)

1. Build findings list
   └─> filterFindingsByClassification()
   └─> cleanFindingsArray()

2. Calculate Asset Criticality Score (ACS)
   └─> criticality.CalculateCriticality(domain, title, slugs)  // LINE 248
   └─> Returns: *findings.Criticality{Score: 1-5, Category: "HIGH", Factors: [...]}

3. Build finding items
   └─> buildFindingItems(finalFindings, finalMap, templates)  // LINE 252
   └─> Returns: []*findings.FindingItem

4. Calculate Headers Grade
   └─> findings.CalculateHeadersGrade(findingItems, findingsDB)  // LINE 256
   └─> Returns: *findings.HeadersGrade{Grade: "A", Score: 85}

5. Extract URL metadata
   └─> extractURLMetadata(templates)  // LINE 260

6. Create Discovery object
   └─> &findings.Discovery{               // LINE 262-272
         Domain:       domain,
         Title:        title,
         FindingItems: findingItems,
         Criticality:  assetCriticality,   // ← ACS here
         HeadersGrade: headersGrade,       // ← Headers grade here
         URL:          url,
         IP:           ip,
       }
```

---

## WHERE TO ADD TRR CALCULATION

**Location**: `pkg/webexposure/report/report.go`

**In each process function** (processWebAppDomain, processAPIDomain, etc.):

```go
// PROPOSED FLOW WITH TRR

1. Build findings list
   └─> [existing code]

2. Calculate Asset Criticality Score (ACS)
   └─> assetCriticality := criticality.CalculateCriticality(...)  // LINE 248

3. Build finding items
   └─> findingItems := rp.buildFindingItems(...)  // LINE 252

4. Calculate Headers Grade
   └─> headersGrade := findings.CalculateHeadersGrade(...)  // LINE 256

5. *** ADD TRR CALCULATION HERE ***
   └─> trueRiskRange := truerisk.CalculateTrueRiskRange(
         assetCriticality.Score,      // ACS (1-5)
         findingItems,                 // []*findings.FindingItem (with technology_weight, weighted_severity_score)
         industryInfo,                 // *common.IndustryInfo (for high-value detection)
       )
   └─> Returns: *findings.TrueRiskRange{
         Min:          499,
         Max:          806,
         Category:     "HIGH",
         Confidence:   "Medium",
         Contributors: []*findings.RiskContributor{...},
       }

6. Extract URL metadata
   └─> url, ip := rp.extractURLMetadata(...)

7. Create Discovery object (with TRR)
   └─> &findings.Discovery{
         Domain:        domain,
         Title:         title,
         FindingItems:  findingItems,
         Criticality:   assetCriticality,
         TrueRiskRange: trueRiskRange,  // ← NEW FIELD
         HeadersGrade:  headersGrade,
         URL:           url,
         IP:           ip,
       }
```

---

## Exact Code Location

**File**: `pkg/webexposure/report/report.go`

**Lines to modify** (5 places, one for each domain type):

### 1. processWebAppDomain (around line 256)

```go
// Calculate headers grade
findingsDB := findings.GetGlobalFindingsMap()
headersGrade := findings.CalculateHeadersGrade(findingItems, findingsDB)
logger.Debug().Msgf("WebApp %s headers grade: %s (%d/100)", domainResult.Domain, headersGrade.Grade, headersGrade.Score)

// *** ADD HERE: Calculate True Risk Range ***
trueRiskRange := truerisk.CalculateTrueRiskRange(
    assetCriticality.Score,
    findingItems,
    rp.industryInfo,  // Need to add this to ResultProcessor
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
    TrueRiskRange: trueRiskRange,  // ← ADD THIS
    HeadersGrade:  headersGrade,
    URL:           url,
    IP:           ip,
})
```

### 2. processAPIDomain (around line 304)
### 3. processAPISpecDomain (around line 353)
### 4. processAIAssetDomain (around line 402)
### 5. processOtherDomain (around line 455)

Same pattern for all 5 domain processing functions.

---

## Implementation Order

### Step 1: Add TrueRiskRange struct to findings_types.go

```go
// pkg/webexposure/findings/findings_types.go

type TrueRiskRange struct {
    Min          int                  `json:"min"`
    Max          int                  `json:"max"`
    Category     string               `json:"category"`
    Confidence   string               `json:"confidence"`
    Contributors []*RiskContributor   `json:"contributors"`
    Calculated   string               `json:"calculated"`
}

type RiskContributor struct {
    Type         string  `json:"type"`
    Name         string  `json:"name"`
    Slug         string  `json:"slug"`
    Contribution float64 `json:"contribution"`
    Reason       string  `json:"reason"`
}

// Add to Discovery struct
type Discovery struct {
    Domain        string           `json:"domain"`
    Title         string           `json:"title,omitempty"`
    Description   string           `json:"description,omitempty"`
    Discovered    string           `json:"discovered"`
    FindingItems  []*FindingItem   `json:"findings"`
    Criticality   *Criticality     `json:"criticality,omitempty"`
    TrueRiskRange *TrueRiskRange   `json:"true_risk_range,omitempty"` // NEW
    HeadersGrade  *HeadersGrade    `json:"headers_grade,omitempty"`
    URL           string           `json:"url,omitempty"`
    IP            string           `json:"ip,omitempty"`
}
```

### Step 2: Create truerisk package

```
pkg/webexposure/truerisk/
├── truerisk.go         # Main calculation logic
├── environmental.go    # Environmental multiplier detection
├── aggregation.go      # Technology score aggregation
└── logger.go           # Logger setup
```

**Main function signature**:

```go
// pkg/webexposure/truerisk/truerisk.go

package truerisk

import "web-exposure-detection/pkg/webexposure/findings"
import "web-exposure-detection/pkg/webexposure/common"

func CalculateTrueRiskRange(
    acs float64,                           // Asset Criticality Score (1-5)
    findingItems []*findings.FindingItem,  // Detected findings
    industry *common.IndustryInfo,         // Industry classification (optional)
) *findings.TrueRiskRange {
    // 1. Aggregate technology severity scores
    avgSeverity, contributors, totalKEV := aggregateTechnologyScores(findingItems)

    // 2. Calculate environmental multipliers
    minMult, maxMult, factors := calculateEnvironmentalMultipliers(findingItems, industry, totalKEV)

    // 3. Calculate TRR
    trrMin := min(int(acs * avgSeverity * minMult), 1000)
    trrMax := min(int(acs * avgSeverity * maxMult), 1000)

    // 4. Return result
    return &findings.TrueRiskRange{
        Min:          trrMin,
        Max:          trrMax,
        Category:     determineCategory(trrMax),
        Confidence:   determineConfidence(trrMax - trrMin),
        Contributors: contributors,
        Calculated:   time.Now().Format(time.RFC3339),
    }
}
```

### Step 3: Modify report.go

**Add industry info to ResultProcessor**:

```go
// pkg/webexposure/report/report.go

type ResultProcessor struct {
    summary      *common.Summary
    apis         []*findings.Discovery
    // ... other fields ...
    industryInfo *common.IndustryInfo  // ADD THIS
}
```

**Update GenerateReport to pass industry**:

```go
func GenerateReport(grouped *nuclei.GroupedResults, targetDomain string, industryClassification *common.IndustryInfo, discoveryResult *domainscan.AssetDiscoveryResult) (*common.ExposureReport, error) {
    processor := NewResultProcessor()
    processor.industryInfo = industryClassification  // ADD THIS

    report := processor.ProcessAllDomains(grouped)
    // ... rest of function
}
```

**Add TRR calculation in 5 process functions** (as shown above).

### Step 4: Update HTML/PDF templates

Add TRR visualization to report templates (separate task).

---

## Why This Location?

### ✓ Advantages

1. **All data available**: By this point we have:
   - Asset Criticality Score (just calculated)
   - Finding items with technology_weight and weighted_severity_score
   - Industry classification (from report metadata)

2. **Consistent with existing pattern**:
   - Headers grade is calculated at same location
   - Both are per-asset metrics
   - Both go into Discovery object

3. **Single responsibility**:
   - Report generation handles all metric calculation
   - Clean separation from scanning logic

4. **Efficient**:
   - Calculated once per domain
   - No need to recalculate during HTML/PDF generation
   - Stored in JSON output

5. **Easy to test**:
   - Can test truerisk package independently
   - Can test report generation with mock data

### ✗ Alternative Locations (and why they're worse)

**❌ During scanning (scanner.go)**:
- Too early, findings not yet aggregated
- Would need to recalculate in report generation

**❌ During HTML generation (report_html.go)**:
- Too late, need TRR in JSON output
- Would require recalculation for PDF

**❌ As a separate pass after report generation**:
- Inefficient (need to reload data)
- Breaks single-pass processing pattern

---

## Summary

**Right place**: `pkg/webexposure/report/report.go` in each `process*Domain()` function

**Right sequence**:
1. Calculate criticality ← existing
2. Build finding items ← existing
3. Calculate headers grade ← existing
4. **Calculate TRR** ← NEW
5. Create Discovery object ← update to include TRR

**Integration points**:
- Import: `"web-exposure-detection/pkg/webexposure/truerisk"`
- Call: `truerisk.CalculateTrueRiskRange(acs, findingItems, industry)`
- Store: Add `TrueRiskRange` field to `findings.Discovery` struct

**Number of modifications**:
- 1 new package: `pkg/webexposure/truerisk/`
- 1 struct addition: `findings_types.go` (TrueRiskRange)
- 5 function updates: `report.go` (one per domain type)
- 0 scanner changes
- 0 nuclei changes

**Effort estimate**: 1-2 weeks (including tests, validation, documentation)
