# Complete Risk Scoring Implementation Plan

**Date:** October 17, 2025
**Status:** Design Complete
**Stages:** Criticality → Financial Risk → Reporting

## Complete Flow

```
Stage 1: Asset Discovery
   ↓
Stage 2: Vulnerability Scanning (Nuclei)
   ↓
Stage 3: Asset Criticality Scoring ← We're here
   ↓
Stage 4: Financial Risk Quantification ← MISSING STAGE
   ↓
Stage 5: Report Generation with $ Risk
```

## Stage 3: Asset Criticality Scoring

**Purpose:** Determine how critical each asset is to the organization

**Input:**
- Domain name
- Page title
- Nuclei findings

**Output:**
```go
type Criticality struct {
    Score    float64  // 0.1 to 5.0
    Category string   // CRITICAL, HIGH, MEDIUM, LOW
    Factors  []string // Scoring breakdown
}
```

**Implementation:** See `criticality-integration-plan.md`

## Stage 4: Financial Risk Quantification (MISSING)

**Purpose:** Convert technical criticality into business risk (dollars)

**Formula:**
```
Expected Annual Loss (EAL) =
    Compromise_Probability × Average_Breach_Cost × Asset_Value_Multiplier
```

### Input Data

**From Stage 3:**
- Criticality score (0.1 to 5.0)
- Findings array (for vulnerability severity)

**Configuration:**
- Industry (from CLI flag: `--industry healthcare|financial|technology|retail`)
- Default: technology

### Calculation Components

#### 1. Compromise Probability

Map criticality score + vulnerability severity to annual breach probability:

```go
func calculateCompromiseProbability(criticality float64, hasHighSeverity bool) float64 {
    // Base probability from criticality
    var baseProb float64

    if criticality >= 4.5 {
        baseProb = 0.95 // 95% annual probability
    } else if criticality >= 3.5 {
        baseProb = 0.85 // 85%
    } else if criticality >= 2.5 {
        baseProb = 0.70 // 70%
    } else if criticality >= 1.5 {
        baseProb = 0.40 // 40%
    } else if criticality >= 1.0 {
        baseProb = 0.20 // 20%
    } else {
        baseProb = criticality / 10 // Conservative for low scores
    }

    // Adjust for high severity vulnerabilities
    if hasHighSeverity {
        baseProb = baseProb * 1.2 // +20% if high severity vulns present
        if baseProb > 1.0 {
            baseProb = 1.0 // Cap at 100%
        }
    }

    return baseProb
}
```

#### 2. Average Breach Cost

Based on IBM Cost of Data Breach Report 2024:

```go
var industryBreachCosts = map[string]int{
    "healthcare":  10930000, // $10.93M
    "financial":   5900000,  // $5.90M
    "technology":  4880000,  // $4.88M (default)
    "retail":      3480000,  // $3.48M
    "manufacturing": 4560000, // $4.56M
    "energy":      5040000,  // $5.04M
    "education":   3650000,  // $3.65M
}

func getBreachCost(industry string) int {
    if cost, exists := industryBreachCosts[industry]; exists {
        return cost
    }
    return industryBreachCosts["technology"] // Default
}
```

#### 3. Asset Value Multiplier

Based on criticality score:

```go
func getAssetValueMultiplier(criticality float64) float64 {
    // Map criticality to asset value
    // Higher criticality = more valuable/critical asset

    if criticality >= 4.5 {
        return 5.0  // Payment systems, critical portals
    } else if criticality >= 3.5 {
        return 3.0  // Production portals with enterprise auth
    } else if criticality >= 2.5 {
        return 2.0  // APIs, admin consoles
    } else if criticality >= 1.5 {
        return 1.2  // Standard web assets
    } else if criticality >= 1.0 {
        return 0.8  // Internal tools
    } else {
        return 0.3  // Dev/test, error pages
    }
}
```

### Implementation

**File:** `pkg/webexposure/financial_risk.go` (NEW)

```go
package webexposure

import (
    "fmt"
    "strings"
)

// FinancialRisk represents the calculated financial risk
type FinancialRisk struct {
    ExpectedAnnualLoss   int      `json:"expected_annual_loss"`   // Dollar amount
    CompromiseProbability float64  `json:"compromise_probability"` // 0.0 to 1.0
    BreachCost           int      `json:"breach_cost"`            // Industry average
    AssetValueMultiplier float64  `json:"asset_value_multiplier"` // Criticality-based
    Industry             string   `json:"industry"`               // Industry context
    RiskLevel            string   `json:"risk_level"`             // EXTREME, HIGH, MEDIUM, LOW
    Factors              []string `json:"factors"`                // Calculation breakdown
}

// Industry breach costs (IBM 2024)
var industryBreachCosts = map[string]int{
    "healthcare":    10930000,
    "financial":     5900000,
    "technology":    4880000,
    "retail":        3480000,
    "manufacturing": 4560000,
    "energy":        5040000,
    "education":     3650000,
}

// CalculateFinancialRisk calculates expected annual loss
func CalculateFinancialRisk(criticality *Criticality, findings []string, industry string) *FinancialRisk {
    logger := GetLogger()
    factors := []string{}

    // Default to technology if not specified
    if industry == "" {
        industry = "technology"
    }

    // 1. Compromise probability
    hasHighSeverity := hasHighSeverityFindings(findings)
    probability := calculateCompromiseProbability(criticality.Score, hasHighSeverity)
    factors = append(factors, fmt.Sprintf("Compromise probability: %.0f%% (criticality %.1f)",
        probability*100, criticality.Score))

    // 2. Breach cost
    breachCost := getBreachCost(industry)
    factors = append(factors, fmt.Sprintf("Industry breach cost: $%s (%s)",
        formatCurrency(breachCost), industry))

    // 3. Asset value multiplier
    multiplier := getAssetValueMultiplier(criticality.Score)
    factors = append(factors, fmt.Sprintf("Asset value multiplier: %.1fx (criticality-based)",
        multiplier))

    // 4. Calculate EAL
    eal := int(float64(breachCost) * probability * multiplier)
    factors = append(factors, fmt.Sprintf("EAL = $%s × %.0f%% × %.1fx = $%s",
        formatCurrency(breachCost), probability*100, multiplier, formatCurrency(eal)))

    // 5. Determine risk level
    riskLevel := determineRiskLevel(eal)

    logger.Info().Msgf("Financial risk for domain: EAL=$%s, probability=%.0f%%, level=%s",
        formatCurrency(eal), probability*100, riskLevel)

    return &FinancialRisk{
        ExpectedAnnualLoss:    eal,
        CompromiseProbability: probability,
        BreachCost:            breachCost,
        AssetValueMultiplier:  multiplier,
        Industry:              industry,
        RiskLevel:             riskLevel,
        Factors:               factors,
    }
}

func calculateCompromiseProbability(criticality float64, hasHighSeverity bool) float64 {
    var baseProb float64

    if criticality >= 4.5 {
        baseProb = 0.95
    } else if criticality >= 3.5 {
        baseProb = 0.85
    } else if criticality >= 2.5 {
        baseProb = 0.70
    } else if criticality >= 1.5 {
        baseProb = 0.40
    } else if criticality >= 1.0 {
        baseProb = 0.20
    } else {
        baseProb = criticality / 10
    }

    // Adjust for high severity
    if hasHighSeverity {
        baseProb = baseProb * 1.2
        if baseProb > 1.0 {
            baseProb = 1.0
        }
    }

    return baseProb
}

func getBreachCost(industry string) int {
    if cost, exists := industryBreachCosts[strings.ToLower(industry)]; exists {
        return cost
    }
    return industryBreachCosts["technology"]
}

func getAssetValueMultiplier(criticality float64) float64 {
    if criticality >= 4.5 {
        return 5.0
    } else if criticality >= 3.5 {
        return 3.0
    } else if criticality >= 2.5 {
        return 2.0
    } else if criticality >= 1.5 {
        return 1.2
    } else if criticality >= 1.0 {
        return 0.8
    } else {
        return 0.3
    }
}

func hasHighSeverityFindings(findings []string) bool {
    // Check for high-severity auth/security findings
    highSeverityPatterns := []string{
        "auth.enterprise.saml_sso",
        "auth.mfa",
        "auth.traditional.registration",
    }

    for _, finding := range findings {
        for _, pattern := range highSeverityPatterns {
            if finding == pattern {
                return true
            }
        }
    }
    return false
}

func determineRiskLevel(eal int) string {
    if eal >= 5000000 {
        return "EXTREME"
    } else if eal >= 2000000 {
        return "HIGH"
    } else if eal >= 500000 {
        return "MEDIUM"
    } else {
        return "LOW"
    }
}

func formatCurrency(amount int) string {
    // Format with thousands separators
    s := fmt.Sprintf("%d", amount)
    n := len(s)
    if n <= 3 {
        return s
    }

    var result []byte
    for i, c := range s {
        if i > 0 && (n-i)%3 == 0 {
            result = append(result, ',')
        }
        result = append(result, byte(c))
    }
    return string(result)
}
```

### Integration Points

**1. Update Discovery Type**

```go
// In report_types.go
type Discovery struct {
    Domain       string         `json:"domain"`
    Title        string         `json:"title,omitempty"`
    Description  string         `json:"description,omitempty"`
    Discovered   string         `json:"discovered"`
    FindingItems []*FindingItem `json:"findings"`
    Criticality  *Criticality   `json:"criticality,omitempty"`
    FinancialRisk *FinancialRisk `json:"financial_risk,omitempty"` // NEW
}
```

**2. Update processDomain()**

```go
// In report.go, after calculating criticality
criticality := CalculateCriticality(domain, domainResult.Title, findingSlugs)
domainResult.Criticality = criticality

// NEW: Calculate financial risk
financialRisk := CalculateFinancialRisk(criticality, findingSlugs, rp.industry)
domainResult.FinancialRisk = financialRisk

logger.Info().Msgf("Domain %s: criticality=%.1f (%s), risk=$%s/year (%s)",
    domain, criticality.Score, criticality.Category,
    formatCurrency(financialRisk.ExpectedAnnualLoss), financialRisk.RiskLevel)
```

**3. Store Industry in ResultProcessor**

```go
// In report_types.go
type ResultProcessor struct {
    summary      *Summary
    apis         []*Discovery
    // ... existing fields ...
    industry     string // NEW: Store industry for financial risk calc
}
```

**4. Pass Industry from Scanner**

```go
// In scanner_types.go
type ScanOptions struct {
    Domain            string
    Keywords          []string
    Force             bool
    ResultsDir        string
    Industry          string // NEW: For financial risk calculation
}

// In scanner.go
func (s *scanner) GenerateReport(grouped *GroupedResults, targetDomain string, industry string) (*ExposureReport, error) {
    processor := NewResultProcessor()
    processor.industry = industry // Pass industry
    report := processor.ProcessAllDomains(grouped)
    // ...
}
```

**5. Add CLI Flag**

```go
// In cmd/scan.go
var industry string

func init() {
    scanCmd.Flags().StringVar(&industry, "industry", "technology",
        "Industry for financial risk calculation (healthcare|financial|technology|retail)")
}
```

### Summary Statistics

**Update Summary Type:**

```go
type Summary struct {
    // ... existing fields ...

    // Criticality stats
    CriticalDomains int `json:"critical_domains,omitempty"`
    HighDomains     int `json:"high_domains,omitempty"`
    MediumDomains   int `json:"medium_domains,omitempty"`
    LowDomains      int `json:"low_domains,omitempty"`

    // NEW: Financial risk stats
    TotalFinancialRisk      int     `json:"total_financial_risk,omitempty"`       // Sum of all EALs
    AverageFinancialRisk    int     `json:"average_financial_risk,omitempty"`     // Average EAL
    HighestRiskDomain       string  `json:"highest_risk_domain,omitempty"`        // Domain with highest EAL
    HighestRiskAmount       int     `json:"highest_risk_amount,omitempty"`        // Highest EAL value
    ExtremRiskDomains       int     `json:"extreme_risk_domains,omitempty"`       // Count of EXTREME risk
    PortfolioRiskLevel      string  `json:"portfolio_risk_level,omitempty"`       // Overall portfolio risk
}
```

**Calculate in buildReport():**

```go
func (rp *ResultProcessor) buildReport() *ExposureReport {
    // ... existing code ...

    // Calculate financial risk statistics
    allDiscoveries := append([]*Discovery{}, rp.apis...)
    allDiscoveries = append(allDiscoveries, rp.apiSpecs...)
    allDiscoveries = append(allDiscoveries, rp.aiAssets...)
    allDiscoveries = append(allDiscoveries, rp.webApps...)

    totalRisk := 0
    highestRisk := 0
    highestRiskDomain := ""
    extremeCount := 0

    for _, d := range allDiscoveries {
        if d.FinancialRisk != nil {
            eal := d.FinancialRisk.ExpectedAnnualLoss
            totalRisk += eal

            if eal > highestRisk {
                highestRisk = eal
                highestRiskDomain = d.Domain
            }

            if d.FinancialRisk.RiskLevel == "EXTREME" {
                extremeCount++
            }
        }
    }

    avgRisk := 0
    if len(allDiscoveries) > 0 {
        avgRisk = totalRisk / len(allDiscoveries)
    }

    portfolioLevel := "LOW"
    if totalRisk >= 50000000 {
        portfolioLevel = "EXTREME"
    } else if totalRisk >= 20000000 {
        portfolioLevel = "HIGH"
    } else if totalRisk >= 5000000 {
        portfolioLevel = "MEDIUM"
    }

    rp.summary.TotalFinancialRisk = totalRisk
    rp.summary.AverageFinancialRisk = avgRisk
    rp.summary.HighestRiskDomain = highestRiskDomain
    rp.summary.HighestRiskAmount = highestRisk
    rp.summary.ExtremRiskDomains = extremeCount
    rp.summary.PortfolioRiskLevel = portfolioLevel

    // ... rest of code ...
}
```

## Stage 5: Report Generation with $ Risk

### HTML Report Updates

**Add financial risk section to report.html:**

```html
<!-- Executive Summary -->
<div class="executive-summary">
    <h2>Financial Risk Summary</h2>
    <div class="risk-metrics">
        <div class="metric">
            <h3>Total Portfolio Risk</h3>
            <div class="risk-amount">${{.Summary.TotalFinancialRisk | formatCurrency}}</div>
            <div class="risk-level risk-{{.Summary.PortfolioRiskLevel | lower}}">
                {{.Summary.PortfolioRiskLevel}}
            </div>
        </div>
        <div class="metric">
            <h3>Highest Risk Domain</h3>
            <div class="domain-name">{{.Summary.HighestRiskDomain}}</div>
            <div class="risk-amount">${{.Summary.HighestRiskAmount | formatCurrency}}/year</div>
        </div>
        <div class="metric">
            <h3>Average Risk per Domain</h3>
            <div class="risk-amount">${{.Summary.AverageFinancialRisk | formatCurrency}}/year</div>
        </div>
    </div>
</div>

<!-- For each domain listing -->
{{range .APIsFound}}
<div class="domain-item">
    <div class="domain-header">
        <h3>{{.Domain}}</h3>
        {{if .Criticality}}
        <span class="criticality-badge criticality-{{.Criticality.Category | lower}}">
            {{.Criticality.Category}}
        </span>
        {{end}}
        {{if .FinancialRisk}}
        <span class="financial-risk">
            <span class="risk-label">Annual Risk:</span>
            <span class="risk-amount">${{.FinancialRisk.ExpectedAnnualLoss | formatCurrency}}</span>
            <span class="risk-badge risk-{{.FinancialRisk.RiskLevel | lower}}">
                {{.FinancialRisk.RiskLevel}}
            </span>
        </span>
        {{end}}
    </div>
    <!-- ... rest of domain content ... -->
</div>
{{end}}
```

### JSON Output Example

```json
{
  "summary": {
    "total_domains": 295,
    "critical_domains": 6,
    "high_domains": 70,
    "total_financial_risk": 15800000,
    "average_financial_risk": 53559,
    "highest_risk_domain": "portal-bo.gov1.qualys.us",
    "highest_risk_amount": 9540000,
    "portfolio_risk_level": "MEDIUM"
  },
  "apis_found": [
    {
      "domain": "api.example.com",
      "title": "Example API",
      "criticality": {
        "score": 2.4,
        "category": "HIGH"
      },
      "financial_risk": {
        "expected_annual_loss": 673000,
        "compromise_probability": 0.70,
        "breach_cost": 4880000,
        "asset_value_multiplier": 2.0,
        "industry": "technology",
        "risk_level": "MEDIUM",
        "factors": [
          "Compromise probability: 70% (criticality 2.4)",
          "Industry breach cost: $4,880,000 (technology)",
          "Asset value multiplier: 2.0x (criticality-based)",
          "EAL = $4,880,000 × 70% × 2.0x = $673,000"
        ]
      }
    }
  ]
}
```

## Complete Implementation Timeline

### Week 1-2: Criticality Scoring
- Create `pkg/webexposure/criticality.go`
- Unit tests
- Integrate into `report.go`

### Week 3-4: Financial Risk Quantification
- Create `pkg/webexposure/financial_risk.go`
- Add industry CLI flag
- Unit tests
- Integrate into `report.go`

### Week 5: Reporting
- Update `report_types.go` with all new types
- Update summary statistics calculation
- Update HTML templates
- Add CSS for risk displays

### Week 6: Testing & Documentation
- End-to-end testing
- Documentation
- User guide updates

## Usage Examples

### Basic Scan (Default Industry)
```bash
./bin/web-exposure-detection scan example.com
# Uses "technology" industry ($4.88M average breach cost)
```

### Healthcare Organization
```bash
./bin/web-exposure-detection scan hospital.com --industry healthcare
# Uses $10.93M average breach cost
```

### Financial Institution
```bash
./bin/web-exposure-detection scan bank.com --industry financial
# Uses $5.90M average breach cost
```

### View Results
```bash
# JSON output with financial risk
jq '.summary.total_financial_risk' results/example.com/web-exposure-result.json

# Highest risk domains
jq '.apis_found | sort_by(.financial_risk.expected_annual_loss) | reverse | .[0:5]' \
  results/example.com/web-exposure-result.json

# HTML report with risk visualizations
open results/example.com/report.html
```

## Summary

**Complete Flow:**
1. ✅ Discovery & Scanning (existing)
2. ✅ Criticality Scoring (Stage 3 - designed)
3. ✅ Financial Risk Quantification (Stage 4 - designed)
4. ✅ Risk Reporting (Stage 5 - designed)

**New Files:**
- `pkg/webexposure/criticality.go`
- `pkg/webexposure/financial_risk.go`
- `pkg/webexposure/criticality_test.go`
- `pkg/webexposure/financial_risk_test.go`

**Modified Files:**
- `pkg/webexposure/report_types.go`
- `pkg/webexposure/report.go`
- `pkg/webexposure/scanner_types.go`
- `cmd/scan.go` (add --industry flag)
- `templates/report.html`

**Value:**
- Translate technical findings into business risk
- Prioritize remediation by financial impact
- Executive-friendly reporting in dollars
- Industry-specific breach costs

**Status:** Ready for implementation
**Date:** October 17, 2025
