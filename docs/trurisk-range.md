# TruRisk™ Range

TruRisk Range is a predictive risk scoring system inspired by Qualys TruRisk methodology. It provides a numeric risk range (min-max) from 0 to 1000 for each discovered asset based on asset criticality, technology vulnerabilities, and environmental factors without requiring active vulnerability scanning.

## Overview

TruRisk scores are always displayed as numbers only (e.g., "536-820"). The range accounts for uncertainty in actual vulnerability presence and exploitability. A narrower range indicates higher confidence in the prediction.

## Calculation Formula

TruRisk Range adapts the Qualys TruRisk formula:

```
TruRisk = MIN(ACS × Weighted_Severity_Score × Environmental_Multipliers, 1000)
```

### Components

**Asset Criticality Score (ACS)**
- Business importance score (1-5) based on authentication, infrastructure, and domain characteristics
- See [Asset Criticality documentation](./reporting-system.md) for details

**Weighted Severity Score**
- Pre-calculated threat index (0-100) for each technology
- Based on CVE statistics, severity distribution, and KEV count
- Stored in findings.json as `weighted_severity_score`

**Technology Weight**
- Importance multiplier (1.5-3.5) based on technology type
- CDN: 1.5, Frontend: 2.0, Backend/API: 3.5, Database: 3.0
- Stored in findings.json as `technology_weight`

**KEV Multipliers**
- CISA Known Exploited Vulnerabilities increase risk
- 2-4 KEVs: 1.15-1.3×
- 5-9 KEVs: 1.3-1.6×
- 10+ KEVs: 1.4-1.8×

**Environmental Factors**
- Internet exposure: 1.2-1.4×
- WAF/CDN protection: 0.7-0.8×
- API presence: 1.1-1.2×
- Enterprise SSO: 0.8-0.9×

## Risk Ranges

> **Note**: Risk ranges are subject to recalibration based on real-world data and feedback.

Current ranges:
- **850-1000**: Immediate action required, highest priority for security review
- **650-849**: Significant risk exposure, prioritize for remediation
- **400-649**: Moderate risk, address in regular security cycles
- **200-399**: Lower risk exposure, monitor and maintain
- **0-199**: Very low risk, standard maintenance

## Implementation

### Location

TruRisk calculation is implemented in:
- **Core logic**: `pkg/webexposure/truerisk/truerisk.go`
- **Type definitions**: `pkg/webexposure/findings/findings_types.go`
- **Integration**: `pkg/webexposure/report/report.go` (all domain processors)

### Data Flow

1. Domain scanning produces findings with slugs
2. Findings mapped to FindingItems from findings.json
3. Each FindingItem has pre-calculated `weighted_severity_score` and `technology_weight`
4. TRR calculation aggregates scores with weights and multipliers
5. Result stored in Discovery.TrueRiskRange field
6. HTML report displays TRR with color coding

### Sorting

All asset tables (APIs, Web Apps, API Specs, AI Assets, Other) are sorted by TruRisk Max score descending (highest risk first).

## Pre-calculated Scores

Technology scores are pre-calculated and stored in `pkg/webexposure/findings/findings.json`:

```json
{
  "slug": "webapp.framework.drupal",
  "technology_weight": 3.5,
  "weighted_severity_score": 93.08
}
```

These scores are calculated based on:
- Base tier by severity (70 for critical CVEs, 50 for high, 30 for medium, 10 for low)
- Volume adjustment (logarithmic scaling)
- KEV bonus (0-20 points based on KEV count)

## HTML Report Display

TruRisk ranges appear in the report with Qualys-style color coding:
- Red background: 850-1000
- Orange background: 650-849
- Yellow background: 400-649
- Lime background: 200-399
- Green background: 0-199

The appendix section explains the methodology and what users should worry about.

## JSON Output

TruRisk data is included in JSON reports:

```json
{
  "true_risk_range": {
    "min": 536,
    "max": 820,
    "category": "HIGH",
    "confidence": "Medium",
    "contributors": [
      {
        "type": "technology",
        "name": "Drupal",
        "slug": "webapp.framework.drupal",
        "contribution": 325.8,
        "reason": "Technology detected with vulnerabilities"
      }
    ],
    "calculated": "2025-11-03T13:46:59Z"
  }
}
```

## Future Work

- Range recalibration based on real-world validation
- Integration with actual vulnerability scanning results for accuracy comparison
- Historical trending of TruRisk scores over time
- Custom weighting and multiplier configuration
