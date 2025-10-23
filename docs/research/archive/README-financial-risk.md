# Financial Risk Quantification - Quick Reference

## How It Works (Black Box - No Config)

### User Experience

```bash
# User runs scan
web-exposure-detection scan example.com

# Optionally specify industry
web-exposure-detection scan example.com --industry healthcare

# Gets report with dollar values
```

### What Happens Automatically

```
1. Scan detects findings (technologies, auth, patterns)
   ↓
2. Calculate compromise probability (0-100 score)
   ↓
3. Auto-detect asset value from findings
   ↓
4. Calculate Expected Annual Loss (EAL)
   ↓
5. Show in report with full transparency
```

## The Formula

```
Expected Annual Loss (EAL) =
  Probability × Breach_Cost × Asset_Multiplier

Where all 3 components are AUTOMATIC:

1. Probability: From compromise prediction score
   - Score 12 → 4% annual probability
   - Score 42 → 40% annual probability
   - Score 72 → 95% annual probability

2. Breach_Cost: From industry average
   - Technology: $4.88M (default)
   - Healthcare: $10.93M
   - Financial: $5.90M
   - Retail: $3.48M
   - (Use --industry flag to change)

3. Asset_Multiplier: Auto-detected from findings
   - Domain name patterns (portal.*, dev.*, api.*)
   - Auth mechanisms (SSO, MFA, registration)
   - Tech stack complexity
   - Data sensitivity indicators
   - Range: 0.1x to 5.0x
   - Default: 1.0x when uncertain
```

## Real Examples

### Example 1: Low-Risk API

```
Domain: api-service.qg1.apps.qualys.ae
Score: 12/100

AUTO-DETECTED:
  Probability: 4% (low score → conservative)
  Breach Cost: $4.88M (Technology industry default)
  Asset Value: 0.5x
    - api.* domain → +0.3
    - No auth → -0.3
    - Simple stack → -0.2
    - Error page → -0.1
    - Total: 0.5x

RESULT: $97,600 annual risk
  = 0.04 × $4,880,000 × 0.5
```

### Example 2: Enterprise Portal

```
Domain: portal.qg3.apps.qualys.com
Score: 42/100

AUTO-DETECTED:
  Probability: 40% (moderate score)
  Breach Cost: $4.88M (Technology industry)
  Asset Value: 2.5x
    - portal.* domain → +0.4
    - Enterprise SSO → +0.3
    - MFA present → +0.2
    - Registration forms → +0.3
    - 4 technologies → +0.2
    - Rails backend → +0.2
    - Cloudflare CDN → +0.1
    - Total: 2.5x (capped)

RESULT: $4,880,000 annual risk
  = 0.40 × $4,880,000 × 2.5

REMEDIATION ROI:
  Cost: $80,000 (Rails update, MFA hardening, WAF)
  New Score: 25/100 (projected)
  New Risk: $780,800
  Savings: $3,123,200 annually
  ROI: 38x return
```

### Example 3: Legacy WordPress

```
Domain: legacy-app.internal
Score: 55/100

AUTO-DETECTED:
  Probability: 85% (high score → likely breach)
  Breach Cost: $4.88M (Technology industry)
  Asset Value: 1.2x
    - .internal domain → -0.2
    - Registration forms → +0.3
    - WordPress CMS → +0.2
    - No CDN → +0.0
    - No MFA → -0.1
    - Total: 1.2x

RESULT: $4,976,000 annual risk
  = 0.85 × $4,880,000 × 1.2

URGENT: Fix within 7 days
```

### Example 4: Dev Environment

```
Domain: dev.staging.internal
Score: 18/100

AUTO-DETECTED:
  Probability: 6% (low score)
  Breach Cost: $4.88M (Technology industry)
  Asset Value: 0.1x (minimum floor)
    - dev.* → -0.4
    - staging.* → -0.3
    - .internal → -0.2
    - No auth → 0.0
    - Simple stack → 0.0
    - Total: 0.1x (floor applied)

RESULT: $29,280 annual risk
  = 0.06 × $4,880,000 × 0.1
```

## Portfolio Example

```
Organization: TotalAppSec Inc.
Scanned: 50 domains
Industry: Technology (default)

PORTFOLIO RISK: $64.7M annually

Top 5 Risks:
┌──────────────────────┬───────┬──────────┬───────────┬──────────────┐
│ Domain               │ Score │ Prob     │ Mult      │ Annual Risk  │
├──────────────────────┼───────┼──────────┼───────────┼──────────────┤
│ customer-db.internal │ 72    │ 95%      │ 2.0x      │ $9,272,000   │
│ api.payments.com     │ 68    │ 85%      │ 2.5x      │ $10,370,000  │
│ legacy-app.internal  │ 55    │ 85%      │ 1.2x      │ $4,976,000   │
│ portal.company.com   │ 42    │ 40%      │ 2.5x      │ $4,880,000   │
│ www.company.com      │ 38    │ 40%      │ 3.0x      │ $5,856,000   │
└──────────────────────┴───────┴──────────┴───────────┴──────────────┘

Fix top 5 domains:
  Investment: $425,000
  Risk Reduction: $20.5M annually
  ROI: 48x
```

## Auto-Detection Algorithm

### Domain Name Patterns (30% weight)

```
Production (+):
  www.*, portal.*, app.* → +0.4 to +0.5
  pay.*, checkout.*, secure.* → +0.5
  api.* → +0.3

Development (-):
  dev.*, test.*, staging.* → -0.3 to -0.4
  sandbox.*, demo.* → -0.3 to -0.4

Internal (-):
  *.internal, *.local → -0.2
```

### Auth Mechanisms (30% weight)

```
Enterprise Auth (+):
  SAML/SSO → +0.3
  OAuth → +0.3
  MFA → +0.2
  Registration forms → +0.3
  Multiple auth types (3+) → +0.4

Simple/None:
  Basic auth only → +0.1
  No auth → 0.0
```

### Tech Stack (20% weight)

```
Complex (+):
  5+ technologies → +0.3
  Backend framework + DB → +0.4
  Payment tech → +0.5

Simple:
  Web server only → 0.0
  Static site → -0.2
```

### Data Sensitivity (20% weight)

```
High Sensitivity (+):
  Payment processing → +0.8
  Healthcare data → +0.7
  Financial data → +0.6
  User registration → +0.3

Low:
  No data collection → 0.0
  Static content → -0.2
```

## Report Output

```
┌─────────────────────────────────────────────────────────────┐
│ FINANCIAL RISK SUMMARY                                      │
│                                                             │
│ Domain: portal.company.com                                  │
│ Compromise Probability: 42/100 (Moderate Risk)             │
│                                                             │
│ EXPECTED ANNUAL LOSS: $4,880,000                           │
│                                                             │
│ Breakdown:                                                  │
│ ├─ Probability: 40% (within 12 months)                     │
│ ├─ Industry Breach Cost: $4,880,000 (Technology)           │
│ └─ Asset Multiplier: 2.5x (Auto-detected)                  │
│                                                             │
│ Auto-Detection Factors:                                     │
│ ├─ portal.* domain pattern → +0.4                          │
│ ├─ Enterprise SSO detected → +0.3                          │
│ ├─ MFA enabled → +0.2                                      │
│ ├─ User registration forms → +0.3                          │
│ ├─ Complex stack (4 tech) → +0.2                           │
│ └─ Backend database → +0.2                                 │
│                                                             │
│ Risk Windows:                                               │
│ ├─ Monthly: $406,667                                        │
│ ├─ Quarterly: $1,220,000                                    │
│ └─ Annual: $4,880,000                                       │
│                                                             │
│ REMEDIATION ANALYSIS                                        │
│                                                             │
│ Proposed Fixes:           Cost        Risk Reduction       │
│ ├─ Update Rails           $15,000     -8 points            │
│ ├─ Harden MFA             $25,000     -5 points            │
│ └─ Deploy WAF             $40,000     -4 points            │
│ TOTAL:                    $80,000     Score: 42 → 25       │
│                                                             │
│ Post-Remediation Risk: $780,800                             │
│ Annual Savings: $4,099,200                                  │
│ ROI: 51x ($51 saved per $1 spent)                          │
│ Payback Period: 7 days                                      │
└─────────────────────────────────────────────────────────────┘

DISCLAIMER: Estimates based on industry averages and auto-detected
asset criticality. Actual costs vary by organization size, data
types, and regulatory environment. For insurance/compliance,
consult risk management teams.
```

## CLI Usage

```bash
# Basic scan (uses Technology industry default)
web-exposure-detection scan example.com

# Specify industry for more accurate breach costs
web-exposure-detection scan hospital.com --industry healthcare
  # Uses $10.93M average breach cost

web-exposure-detection scan bank.com --industry financial
  # Uses $5.90M average breach cost

web-exposure-detection scan shop.com --industry retail
  # Uses $3.48M average breach cost

# Available industries:
# - technology (default)
# - healthcare
# - financial
# - pharmaceuticals
# - energy
# - industrial
# - consumer
# - media
# - retail
# - hospitality
```

## Key Benefits

**For Security Teams:**
- Prioritize by dollar impact, not just technical severity
- Justify remediation costs with ROI calculations
- Track risk reduction over time

**For Executives/CFOs:**
- Understand risk in business language ($$$)
- Compare security investments to potential losses
- Make data-driven budget decisions

**For Board/Compliance:**
- Report total portfolio exposure
- Show risk concentration
- Demonstrate due diligence

## Implementation Notes

**What We DON'T Need:**
- ❌ Config files
- ❌ Manual asset valuation
- ❌ User input beyond CLI flag
- ❌ Database of domain values
- ❌ Complex setup

**What We DO:**
- ✅ Auto-detect from scan findings
- ✅ Use industry averages
- ✅ Conservative defaults
- ✅ Transparent reporting
- ✅ One CLI flag (--industry)

**Conservative Bias:**
- Floor: 0.1x minimum (prevents zero risk)
- Ceiling: 5.0x maximum (prevents over-estimation)
- Default: 1.0x when uncertain
- Probability calibration: Conservative for low scores

**This ensures we never over-estimate risk, only under-estimate.**

---

**See Also:**
- [financial-risk-quantification.md](./financial-risk-quantification.md) - Full model details
- [asset-value-determination.md](./asset-value-determination.md) - Auto-detection algorithm
- [domain-compromise-prediction.md](./domain-compromise-prediction.md) - Probability model
