# Probability Approaches for Financial Risk Calculation

**Date:** October 17, 2025
**Status:** Decision Pending
**Purpose:** Document different approaches for calculating breach probability in financial risk model

## The Core Challenge

**Question:** How do we determine the probability component in:
```
Expected Annual Loss = Probability × Breach_Cost × Asset_Multiplier
```

**Constraint:** We detect technologies (WordPress, Rails, Nginx) but NOT specific CVEs on individual domains. Technology CVE counts indicate risk profile, not actual vulnerabilities present.

## Option 1: Risk Index (No Probability)

### Model
```
Technology Risk Score: 0-100 (based on tech profile, KEV, complexity)
Asset Value: Auto-detected multiplier
Industry Benchmark: "15-40% of similar profiles breached annually"

Expected Annual Loss Range:
  Conservative: Score × 0.15 × Breach_Cost × Asset_Multiplier
  Aggressive: Score × 0.40 × Breach_Cost × Asset_Multiplier
```

### Presentation
```
Domain: blog.qualys.com
Technology Risk: 85/100 (High)
Asset Impact if Breached: $11.2M
Industry Benchmark: 15-40% of similar assets breached annually

Expected Annual Loss:
  Conservative: $1.68M (15% probability)
  Likely: $3.36M (30% probability)
  Worst Case: $5.6M (50% probability)

Recommended: Use "Likely" for planning
```

### Pros
- Honest about uncertainty
- Provides range for different planning scenarios
- Industry benchmark adds credibility
- Clear that it's an estimate

### Cons
- Range may confuse some stakeholders
- "Which number do I use?" question
- Requires citing industry sources

---

## Option 2: Industry Benchmark Probability

### Model
```
Technology Profile Classification:
  - WordPress + Enterprise Auth + Public → Profile Type A
  - Rails API + MFA → Profile Type B
  - Static Nginx → Profile Type C

Industry Data Mapping:
  Profile A → 35% annual breach rate
  Profile B → 15% annual breach rate
  Profile C → 5% annual breach rate

EAL = Industry_Probability × Breach_Cost × Asset_Multiplier
```

### Presentation
```
Domain: blog.qualys.com
Technology Profile: WordPress + Enterprise Auth + Public
Industry Benchmark: 35% annual breach rate for this profile
Asset Value: $11.2M
Expected Annual Loss: $3.92M

Basis: Industry breach statistics for WordPress deployments
Source: [Verizon DBIR 2024, IBM Cost of Breach Report]
```

### Pros
- Single number (clear for decision making)
- Backed by industry data
- Defensible methodology
- Reproducible

### Cons
- Requires research to map profiles to probabilities
- Industry data may not fit all scenarios
- Need credible sources
- Profiles may not cover all cases

---

## Option 3: Tiered Risk Levels

### Model
```
Risk Score (0-100) → Risk Tier → Probability Range

Tiers:
  CRITICAL (80-100): 40-50% probability
  HIGH (50-79): 25-40% probability
  MEDIUM (30-49): 10-25% probability
  LOW (0-29): 5-10% probability

For reporting, use midpoint of range
```

### Presentation
```
Domain: blog.qualys.com
Risk Tier: CRITICAL (Score: 85/100)

Breach Probability: 45% (tier midpoint)
Breach Impact: $11.2M
Expected Annual Loss: $5.04M

Risk Range: $4.48M - $5.6M
Confidence: Medium (based on technology risk profile)
```

### Pros
- Clear tier system
- Single number with confidence range
- Easy to explain (CRITICAL = high probability)
- Actionable

### Cons
- Tier boundaries are arbitrary
- Midpoint may not be accurate
- Less scientific than industry benchmarks

---

## Option 4: Relative Risk Only (No Dollar Amount)

### Model
```
Risk Score: 0-100 (composite of tech, auth, exposure, complexity)

No probability calculation
No dollar amounts
Pure prioritization
```

### Presentation
```
Portfolio Risk Ranking:

CRITICAL (Fix Immediately):
  1. blog.qualys.com (85/100)
  2. portal-prod.qualys.com (82/100)

HIGH (Fix Within 30 Days):
  3. api.qualys.com (67/100)

MEDIUM (Fix Within 90 Days):
  4. staging.qualys.com (42/100)

No EAL calculations - just priority order
```

### Pros
- Honest (no fake precision)
- Simple to understand
- Clear action items
- No need for probability estimates

### Cons
- No business case for budget
- Can't justify ROI
- Executives want dollar amounts
- Hard to compare security vs other investments

---

## Option 5: Historical Exploitation Rate

### Model
```
Technology Exploitation History:
  - WordPress: 463 KEVs, heavily targeted
  - Rails: 50 KEVs, moderately targeted
  - Nginx: 5 KEVs, rarely targeted

Exploitation Probability = f(KEV_Count, Technology_Popularity)

Example:
  WordPress (463 KEVs) → 40% annual exploitation rate
  Rails (50 KEVs) → 20% annual exploitation rate
  Nginx (5 KEVs) → 5% annual exploitation rate
```

### Presentation
```
Domain: blog.qualys.com
Technology: WordPress
Exploitation History: 463 KEVs (actively targeted)
Estimated Probability: 40% annual
Asset Value: $11.2M
Expected Annual Loss: $4.48M

Basis: WordPress instances are actively exploited (KEV data)
```

### Pros
- Based on real exploitation data (KEV)
- Technology specific
- Concrete evidence
- Defensible

### Cons
- KEV count doesn't directly translate to probability
- Needs calibration/research
- May overestimate for well-maintained instances
- Underestimate for outdated versions

---

## Option 6: Scoring with Calibrated Probability Table

### Model
```
Technology Risk Score: 0-100
Calibration Table (based on research/industry data):

Score → Annual Probability
90-100 → 60%
80-89  → 50%
70-79  → 40%
60-69  → 30%
50-59  → 25%
40-49  → 20%
30-39  → 15%
20-29  → 10%
10-19  → 5%
0-9    → 2%

EAL = Calibrated_Probability × Breach_Cost × Asset_Multiplier
```

### Presentation
```
Domain: blog.qualys.com
Technology Risk Score: 85/100
Calibrated Probability: 50% annual
Asset Value: $11.2M
Expected Annual Loss: $5.6M

Calibration based on industry breach statistics
```

### Pros
- Smooth probability curve
- Single number for decisions
- Can be tuned based on validation
- Professional appearance

### Cons
- Calibration table is somewhat arbitrary
- Requires validation against real breaches
- May give false precision
- Hard to explain "why 50%?"

---

## Comparison Matrix

| Approach | Credibility | Simplicity | Budget Justification | Data Requirements | Decision Ready |
|----------|-------------|------------|---------------------|-------------------|----------------|
| **Option 1: Risk Range** | Medium | Medium | Good | Low | No (range confuses) |
| **Option 2: Industry Benchmark** | High | High | Excellent | High (research) | Yes |
| **Option 3: Tiered Risk** | Medium | High | Good | Low | Yes |
| **Option 4: Relative Only** | High | Very High | Poor | None | Yes (for priority) |
| **Option 5: KEV-Based** | Medium | High | Good | Medium | Yes |
| **Option 6: Calibrated Table** | Medium | High | Good | Medium (tuning) | Yes |

---

## Recommendation (To Be Decided)

**Top 3 Options:**

### 1. Option 2: Industry Benchmark (Most Credible)
- Research industry breach rates by technology profile
- Map detected technologies to profiles
- Use published statistics (Verizon DBIR, IBM, etc.)
- **Best for:** Executive reporting, board presentations

### 2. Option 3: Tiered Risk (Most Practical)
- Simple tier system (CRITICAL/HIGH/MEDIUM/LOW)
- Probability ranges per tier
- Use midpoint for calculations
- **Best for:** Daily operations, prioritization

### 3. Option 5: KEV-Based (Most Defensible)
- Use KEV count as exploitation indicator
- Calibrate KEV → probability mapping
- Technology specific
- **Best for:** Technical audiences, security teams

---

## Decision Criteria

**Choose based on:**

1. **Audience:**
   - Executives/Board → Option 2 (Industry Benchmark)
   - Security Teams → Option 5 (KEV-Based)
   - Mixed → Option 3 (Tiered Risk)

2. **Available Resources:**
   - Can research industry data → Option 2
   - Limited time → Option 3
   - Have KEV data already → Option 5

3. **Risk Tolerance:**
   - Conservative → Option 1 (show ranges)
   - Aggressive → Option 6 (calibrated table)
   - Balanced → Option 3 (tiers)

4. **Validation Capability:**
   - Can track real breaches → Option 6 (tune calibration)
   - Limited feedback → Option 2 (use published data)

---

## Next Steps

1. **Decision Required:** Select approach based on user needs and audience
2. **Research (if Option 2):** Gather industry breach statistics by technology profile
3. **Calibration (if Option 5/6):** Map KEV counts or scores to probabilities
4. **Implementation:** Code the selected approach
5. **Validation:** Track predictions vs actual incidents

---

**Document Status:** Approaches Documented - Awaiting Decision
**Owner:** Product/Engineering
**Last Updated:** October 17, 2025
