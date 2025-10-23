# Financial Risk Quantification Model

**Date:** October 16, 2025
**Status:** Research - Design Phase
**Purpose:** Translate technical compromise prediction scores into dollar value risk that business stakeholders can understand
**Dependencies:** Domain Compromise Prediction Model

## Executive Summary

This model converts technical compromise probability scores (0-100) into **Expected Annual Loss (EAL)** in dollars, enabling business-level risk discussions and ROI-based security investment decisions.

**Key Innovation:** Bridge the gap between technical security metrics and business language by quantifying financial exposure per domain.

**Output:** "This domain has a $450,000 expected annual loss due to compromise risk" instead of "This domain scores 55/100"

## Problem Statement

**Current State:**
- Technical teams understand "Compromise Probability: 55/100 (High Risk)"
- Business stakeholders ask "So what? How much will this cost us?"
- Security budget discussions lack concrete financial justification

**Gap:**
- No translation between technical risk scores and financial impact
- Cannot compare security investments across domains
- Cannot justify remediation costs vs breach costs

**Goal:**
- Calculate Expected Annual Loss (EAL) per domain
- Enable ROI analysis for security investments
- Provide board-level financial risk reporting
- Prioritize domains by financial exposure, not just technical score

## Financial Risk Model

### Core Formula

```
Expected_Annual_Loss (EAL) =
  Compromise_Probability × Average_Breach_Cost × Asset_Value_Multiplier

Where:
  Compromise_Probability = Domain compromise score / 100 (0.0 to 1.0)
  Average_Breach_Cost = Base cost of a breach (industry + org specific)
  Asset_Value_Multiplier = Criticality factor for this specific domain (0.1 to 5.0)
```

### Component Breakdown

#### 1. Compromise Probability (From Previous Model)

Convert 0-100 score to annual probability:

```
Annual_Probability = Score / 100

Timeline adjustments:
- Score 85-100: 95% probability in 30 days → ~100% annual
- Score 70-84:  80% probability in 90 days → ~95% annual
- Score 50-69:  60% probability in 180 days → ~85% annual
- Score 30-49:  40% probability in 1 year → ~40% annual
- Score 0-29:   10% probability in 1 year → ~10% annual

Calibrated_Annual_Probability =
  if score >= 85: 1.00
  if score >= 70: 0.95
  if score >= 50: 0.85
  if score >= 30: 0.40
  else: score / 300  // Conservative estimate for low scores
```

#### 2. Average Breach Cost

**Industry Baselines (2024 Data):**

| Industry | Average Breach Cost | Source |
|----------|-------------------|--------|
| Healthcare | $10.93M | IBM Cost of Breach 2024 |
| Financial Services | $5.90M | IBM Cost of Breach 2024 |
| Pharmaceuticals | $5.01M | IBM Cost of Breach 2024 |
| Technology | $4.88M | IBM Cost of Breach 2024 |
| Energy | $4.78M | IBM Cost of Breach 2024 |
| Industrial | $4.73M | IBM Cost of Breach 2024 |
| Consumer | $4.24M | IBM Cost of Breach 2024 |
| Media | $3.98M | IBM Cost of Breach 2024 |
| Retail | $3.48M | IBM Cost of Breach 2024 |
| Hospitality | $3.28M | IBM Cost of Breach 2024 |
| **Global Average** | **$4.88M** | IBM Cost of Breach 2024 |

**Breach Cost Components:**

```
Total_Breach_Cost =
  Detection_and_Escalation +
  Notification_Costs +
  Post_Breach_Response +
  Lost_Business_Cost +
  Regulatory_Fines +
  Legal_Costs +
  Reputation_Damage

Industry breakdown (% of total):
- Detection and Escalation: 29%
- Post-breach Response: 27%
- Lost Business: 38%
- Notification: 6%
```

**Customization Levels:**

```
Level 1 - Use Industry Average:
  Average_Breach_Cost = industry_baseline[$user_industry]

Level 2 - Organization-Specific:
  Average_Breach_Cost = $user_provided_value
  // Based on org's historical incidents or insurance assessments

Level 3 - Domain-Type Specific:
  Average_Breach_Cost = base_cost × domain_type_multiplier

  Domain type multipliers:
  - Production customer-facing: 1.5x (reputational damage)
  - Production internal: 1.0x (baseline)
  - Staging/Test with real data: 0.8x (less exposure)
  - Development/Test: 0.3x (minimal data)
  - Legacy/Deprecated: 0.5x (lower business impact)
```

#### 3. Asset Value Multiplier

Adjusts breach cost based on domain criticality and data sensitivity.

**Automatic Classification (From Nuclei Findings):**

```
Base_Multiplier = 1.0

Adjustments based on findings:

1. Data Sensitivity Indicators:
   - Has auth.traditional.registration → +0.3 (user PII)
   - Has payment processing indicators → +0.8 (PCI data)
   - Database exposed (future finding) → +0.5 (data access)

2. Business Criticality:
   - Production domain pattern (www, portal, app) → +0.2
   - API domain (api.*) → +0.3 (service dependency)
   - Admin/internal domain → +0.1
   - Staging/dev domain → -0.3

3. Technology Stack Value:
   - Enterprise SSO present → +0.2 (many users)
   - Multiple auth mechanisms → +0.2 (active usage)
   - Complex tech stack (5+ technologies) → +0.3 (critical app)

4. Exposure Level:
   - Has CDN (Cloudflare) → +0.1 (public-facing)
   - No CDN, self-hosted → -0.1 (possibly internal)

Asset_Value_Multiplier = max(0.1, min(5.0, Base_Multiplier + Σ(adjustments)))
```

**Manual Override (User Configuration):**

```json
{
  "domain_criticality": {
    "www.company.com": {
      "multiplier": 2.5,
      "reason": "Primary revenue-generating e-commerce site",
      "manual_override": true
    },
    "portal.company.com": {
      "multiplier": 1.8,
      "reason": "Customer portal with PII and payment data"
    },
    "staging.company.com": {
      "multiplier": 0.4,
      "reason": "Non-production, anonymized data"
    }
  }
}
```

## Calculation Examples

### Example 1: Low-Risk API Endpoint

```
Domain: nac-le-service.qg1.apps.qualys.ae
Compromise Score: 12/100 (Minimal Risk)

Inputs:
- Compromise_Probability: 12/100 = 0.12
- Calibrated_Annual_Probability: 0.04 (12/300, conservative for low scores)
- Industry: Technology
- Average_Breach_Cost: $4,880,000
- Asset_Value_Multiplier: 0.5
  * Base: 1.0
  * API domain: +0.3
  * Error page exposed: -0.1
  * No auth (minimal data): -0.3
  * Simple stack (1 tech): -0.4
  * Total: max(0.1, 0.5) = 0.5

Calculation:
Expected_Annual_Loss = 0.04 × $4,880,000 × 0.5
                     = $97,600

Financial Risk: $97,600 per year
Monthly Risk: $8,133
Recommended Budget: Up to $20,000 for remediation (20% of annual risk)
```

### Example 2: Enterprise Portal with Auth

```
Domain: portal.qg3.apps.qualys.com
Compromise Score: 42/100 (Moderate Risk)

Inputs:
- Compromise_Probability: 42/100 = 0.42
- Calibrated_Annual_Probability: 0.40 (score in 30-49 range)
- Industry: Technology
- Average_Breach_Cost: $4,880,000
- Asset_Value_Multiplier: 2.0
  * Base: 1.0
  * Has registration: +0.3
  * Has enterprise SSO: +0.2
  * Has MFA: +0.2
  * Production portal: +0.2
  * Complex stack (4 techs): +0.3
  * Rails with KEV: +0.3
  * Has CDN: +0.1
  * Total: min(5.0, 2.6) = 2.6 → round to 2.0

Calculation:
Expected_Annual_Loss = 0.40 × $4,880,000 × 2.0
                     = $3,904,000

Financial Risk: $3.9M per year
Monthly Risk: $325,333
90-Day Risk: $976,000

Remediation Cost Justification:
- Rails update: $15,000
- MFA hardening: $25,000
- WAF deployment: $40,000
- Total: $80,000

Post-Remediation Score: 25/100 (projected)
Post-Remediation EAL: 0.08 × $4,880,000 × 2.0 = $780,800
Annual Risk Reduction: $3,904,000 - $780,800 = $3,123,200
ROI: ($3,123,200 - $80,000) / $80,000 = 38x return
```

### Example 3: Legacy WordPress Application

```
Domain: legacy-app.qualys.internal
Compromise Score: 55/100 (High Risk)

Inputs:
- Compromise_Probability: 55/100 = 0.55
- Calibrated_Annual_Probability: 0.85 (score in 50-69 range)
- Industry: Technology
- Average_Breach_Cost: $4,880,000
- Asset_Value_Multiplier: 1.2
  * Base: 1.0
  * Has registration: +0.3
  * WordPress (legacy CMS): +0.2
  * No CDN: -0.1
  * No MFA: -0.2
  * Internal domain: 0.0
  * Total: 1.2

Calculation:
Expected_Annual_Loss = 0.85 × $4,880,000 × 1.2
                     = $4,976,000

Financial Risk: $5.0M per year
30-Day Risk: $414,667 (extremely high)

URGENT REMEDIATION REQUIRED:
- Immediate WordPress/PHP updates: $20,000
- Implement MFA: $15,000
- Add WAF: $30,000
- Migrate to modern stack (if feasible): $150,000
- Total immediate fixes: $65,000

Post-Remediation Score: 30/100 (projected)
Post-Remediation EAL: 0.13 × $4,880,000 × 1.2 = $760,320
Annual Risk Reduction: $5,000,000 - $760,320 = $4,239,680
ROI: ($4,239,680 - $65,000) / $65,000 = 64x return

Business Case: Spending $65k to avoid $5M annual risk = 1.3% of risk value
```

## Portfolio-Level Financial Risk

### Aggregation Formula

```
Total_Portfolio_Risk = Σ(Domain_EAL_i) for all domains

Risk Concentration Analysis:
- Top 10% of domains by EAL
- Risk per technology type
- Risk per business unit
```

### Example Portfolio

```
Organization: TotalAppSec Inc.
Industry: Technology
Total Domains Scanned: 50

Financial Risk Assessment:

Critical Risk Domains (5):
┌──────────────────────────┬───────┬──────────────┬──────────────┐
│ Domain                   │ Score │ Annual EAL   │ 90-Day Risk  │
├──────────────────────────┼───────┼──────────────┼──────────────┤
│ legacy-app.internal      │ 55    │ $4,976,000   │ $1,244,000   │
│ portal.company.com       │ 42    │ $3,904,000   │ $976,000     │
│ api.payments.com         │ 68    │ $7,820,000   │ $1,955,000   │
│ admin.legacy.com         │ 51    │ $4,392,000   │ $1,098,000   │
│ customer-db.internal     │ 72    │ $9,150,000   │ $2,287,500   │
└──────────────────────────┴───────┴──────────────┴──────────────┘
Subtotal: $30,242,000 annual risk

High Risk Domains (8): $18,500,000 annual risk
Moderate Risk Domains (15): $12,800,000 annual risk
Low Risk Domains (22): $3,200,000 annual risk

TOTAL PORTFOLIO RISK: $64,742,000 per year

Risk Distribution:
- Top 5 domains: 47% of total risk
- Top 10 domains: 68% of total risk
- WordPress/PHP stack: $22M (34% of risk)
- Rails stack: $15M (23% of risk)
- Modern stacks: $8M (12% of risk)
- API endpoints: $19M (29% of risk)
```

## Report Presentation

### Executive Dashboard

```
┌─────────────────────────────────────────────────────────────┐
│ FINANCIAL RISK SUMMARY                                      │
│                                                             │
│ Total Portfolio Exposure: $64.7M annually                   │
│ 90-Day Risk Window: $16.2M                                  │
│                                                             │
│ Critical Actions Required:                                  │
│ ├─ 5 domains require immediate remediation                  │
│ ├─ Projected cost: $425,000                                 │
│ ├─ Risk reduction: $20.5M annually                          │
│ └─ ROI: 48x return on investment                            │
│                                                             │
│ Top Financial Risks:                                        │
│ 1. customer-db.internal    $9.2M  [Score: 72] 🔴           │
│ 2. api.payments.com        $7.8M  [Score: 68] 🔴           │
│ 3. legacy-app.internal     $5.0M  [Score: 55] 🟠           │
│ 4. admin.legacy.com        $4.4M  [Score: 51] 🟠           │
│ 5. portal.company.com      $3.9M  [Score: 42] 🟡           │
│                                                             │
│ Risk by Technology:                                         │
│ WordPress/PHP: $22M (34%) ████████████████                  │
│ Rails:         $15M (23%) ███████████                       │
│ APIs:          $19M (29%) █████████████                     │
│ Modern Stack:  $8M  (12%) ██████                            │
└─────────────────────────────────────────────────────────────┘
```

### Per-Domain Financial Card

```
┌─────────────────────────────────────────────────────────────┐
│ FINANCIAL RISK ASSESSMENT                                   │
│                                                             │
│ Domain: portal.company.com                                  │
│ Compromise Probability: 42/100 (Moderate)                   │
│                                                             │
│ Expected Annual Loss: $3,904,000                            │
│ ├─ Monthly: $325,333                                        │
│ ├─ 90-Day Window: $976,000                                  │
│ └─ Probability: 40% within 12 months                        │
│                                                             │
│ Cost Breakdown:                                             │
│ ├─ Base Breach Cost: $4,880,000 (Technology industry avg)  │
│ ├─ Asset Multiplier: 2.0x (Customer portal, PII, payment)  │
│ └─ Annual Probability: 40%                                  │
│                                                             │
│ Remediation Investment Analysis:                            │
│ ┌───────────────────────────────────────────────────┐       │
│ │ Proposed Fixes:                        Cost       │       │
│ │ ├─ Update Rails to latest           $15,000       │       │
│ │ ├─ Implement MFA hardening          $25,000       │       │
│ │ ├─ Deploy WAF                       $40,000       │       │
│ │ └─ Security audit                   $10,000       │       │
│ │ TOTAL INVESTMENT:                   $90,000       │       │
│ │                                                    │       │
│ │ Projected Risk Reduction:                         │       │
│ │ ├─ New Score: 25/100 (Low)                        │       │
│ │ ├─ New EAL: $780,800                              │       │
│ │ ├─ Risk Reduced: $3,123,200 annually              │       │
│ │ └─ ROI: 34x ($34 saved per $1 spent)              │       │
│ └───────────────────────────────────────────────────┘       │
│                                                             │
│ Business Justification:                                     │
│ Spending $90k (2.3% of annual risk) to reduce exposure     │
│ by $3.1M per year. Payback period: 11 days                 │
└─────────────────────────────────────────────────────────────┘
```

## Configuration

### Organization-Level Settings

```json
{
  "financial_risk_config": {
    "industry": "technology",
    "custom_breach_cost": null,
    "use_industry_average": true,
    "currency": "USD",

    "asset_classification": {
      "auto_detect": true,
      "manual_overrides": {
        "www.company.com": {
          "multiplier": 3.0,
          "reason": "Primary revenue generator",
          "annual_revenue_impact": 25000000
        },
        "api.payments.com": {
          "multiplier": 2.5,
          "reason": "Payment processing, PCI compliance",
          "regulatory_fines_risk": 5000000
        }
      }
    },

    "probability_calibration": {
      "use_default": true,
      "custom_mapping": null
    },

    "reporting": {
      "show_financial_risk": true,
      "show_roi_analysis": true,
      "show_portfolio_summary": true,
      "currency_symbol": "$",
      "number_format": "en-US"
    }
  }
}
```

## Implementation Requirements

### Data Needed

**Already Available:**
- Compromise probability score (0-100) ✓
- Nuclei findings (for asset value classification) ✓
- Technology stack data ✓

**New Data:**
- Industry selection (user input)
- Custom breach cost (optional user input)
- Asset criticality overrides (optional user config)
- Currency preference

### Schema Extension

```json
{
  "domain": "portal.company.com",
  "compromise_prediction": {
    "score": 42.4,
    "category": "Moderate Risk"
  },
  "financial_risk": {
    "expected_annual_loss": 3904000,
    "currency": "USD",
    "breakdown": {
      "compromise_probability": 0.42,
      "calibrated_annual_probability": 0.40,
      "base_breach_cost": 4880000,
      "industry": "technology",
      "asset_value_multiplier": 2.0,
      "asset_classification": {
        "auto_detected": true,
        "factors": [
          {"factor": "has_registration", "adjustment": 0.3},
          {"factor": "has_enterprise_sso", "adjustment": 0.2},
          {"factor": "production_domain", "adjustment": 0.2},
          {"factor": "complex_stack", "adjustment": 0.3}
        ]
      }
    },
    "time_windows": {
      "monthly_risk": 325333,
      "quarterly_risk": 976000,
      "annual_risk": 3904000
    },
    "remediation_analysis": {
      "proposed_fixes": [
        {
          "action": "Update Rails to latest version",
          "cost": 15000,
          "risk_reduction_points": 8
        },
        {
          "action": "Implement MFA hardening",
          "cost": 25000,
          "risk_reduction_points": 5
        },
        {
          "action": "Deploy WAF",
          "cost": 40000,
          "risk_reduction_points": 4
        }
      ],
      "total_cost": 80000,
      "projected_new_score": 25,
      "projected_new_eal": 780800,
      "annual_savings": 3123200,
      "roi_multiple": 38,
      "payback_days": 9
    }
  }
}
```

## Industry Benchmarks

### Breach Cost by Company Size

| Company Size | Average Breach Cost | Per-Record Cost |
|--------------|-------------------|-----------------|
| <500 employees | $2.98M | $164 |
| 500-1,000 employees | $3.31M | $157 |
| 1,001-5,000 employees | $4.87M | $148 |
| 5,001-10,000 employees | $5.46M | $142 |
| 10,001-25,000 employees | $5.74M | $139 |
| 25,001+ employees | $5.57M | $148 |

### Time to Identify and Contain

```
Average time to identify breach: 204 days
Average time to contain breach: 73 days
Total lifecycle: 277 days

Faster response = lower costs:
- <200 days: $3.93M average
- 200-300 days: $4.86M average
- >300 days: $5.46M average
```

### Cost Multipliers

```
Factors that increase breach costs:
- No security AI/automation: +$1.76M (54% increase)
- High compliance failures: +$1.24M (38% increase)
- Third-party involvement: +$0.58M (18% increase)
- Ransomware attack: +$0.47M (14% increase)
- Cloud misconfiguration: +$0.28M (9% increase)

Factors that decrease breach costs:
- Security AI/automation: -$1.88M (45% reduction)
- Incident response team: -$1.49M (36% reduction)
- Employee training: -$0.23M (7% reduction)
- DevSecOps approach: -$0.25M (8% reduction)
```

## Advanced Features

### 1. Insurance Integration

```
Compare EAL to cyber insurance premiums:

Annual EAL: $64.7M
Insurance Premium Quote: $850,000
Coverage Limit: $25M
Deductible: $500,000

Analysis:
- Insurance covers: 38% of total risk
- Uncovered risk: $40.2M
- Premium as % of EAL: 1.3%
- Better investment: Security remediation (higher ROI)
```

### 2. Trend Analysis

```
Track financial risk over time:

Q1 2025: $72.4M total risk
Q2 2025: $68.1M (-6% after remediation)
Q3 2025: $64.7M (-5% ongoing improvements)

Projected Q4 2025: $58.2M (if current plan executed)
```

### 3. What-If Scenarios

```
Scenario 1: Fix top 5 domains
- Investment: $425,000
- Risk reduction: $20.5M
- New portfolio risk: $44.2M
- ROI: 48x

Scenario 2: Fix all WordPress instances
- Investment: $680,000
- Risk reduction: $22M
- New portfolio risk: $42.7M
- ROI: 32x

Scenario 3: Implement WAF globally
- Investment: $250,000
- Risk reduction: $12M
- New portfolio risk: $52.7M
- ROI: 48x
```

### 4. Board-Level Metrics

```
Key metrics for executive reporting:

1. Total Financial Exposure: $64.7M
2. Insurance Coverage Gap: $40.2M
3. Recommended Security Investment: $1.2M
4. Expected Risk Reduction: $35M
5. Net Position: -$28M improvement
6. Industry Comparison: 1.8x higher than average (needs attention)
```

## Implementation Roadmap

**Week 1-2: Foundation**
- Add industry selection to config
- Implement base EAL calculation
- Use industry average breach costs
- Auto-detect asset value multipliers from findings

**Week 3-4: Enhancement**
- Add manual asset criticality overrides
- Implement ROI analysis for remediation
- Add time window calculations (monthly, quarterly)
- Portfolio aggregation

**Week 5-6: Reporting**
- Financial risk cards in HTML reports
- Executive dashboard
- Portfolio risk summary
- CSV export for further analysis

**Week 7-8: Advanced**
- Trend tracking over time
- What-if scenario modeling
- Insurance gap analysis
- Industry benchmarking

## Success Metrics

- Security budgets approved faster (CFO understands dollar risk)
- Remediation prioritization based on financial impact, not just technical severity
- Board/executive engagement with security metrics
- Reduction in actual breach costs year-over-year

## References

### Industry Data Sources
- IBM Cost of a Data Breach Report 2024
- Ponemon Institute Annual Study
- Verizon Data Breach Investigations Report 2024
- Forrester Total Economic Impact Studies

### Risk Quantification Frameworks
- FAIR (Factor Analysis of Information Risk)
- NIST Cybersecurity Framework (Financial Impact)
- ISO 27005 Risk Assessment
- OCTAVE (Operationally Critical Threat, Asset, and Vulnerability Evaluation)

---

**Document Status:** Research Complete - Design Phase
**Next Steps:** Implement basic EAL calculation, add to reports
**Owner:** Security Engineering + Finance Team
**Dependencies:** Domain Compromise Prediction Model
**Last Updated:** October 16, 2025
