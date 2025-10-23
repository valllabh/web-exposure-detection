# Why NOT to Use HTTP Response Semantic Analysis

**Date:** October 17, 2025
**Status:** REJECTED ❌
**Reason:** False positives, no meaningful value over Nuclei findings

## Summary

We investigated using HTTP response content (body text) for semantic criticality scoring but **rejected it** after implementation and testing.

## What We Tried

### Semantic Analysis Approach

Extract text from HTML and analyze:
1. **Operational vs Marketing context** - Count tracking scripts, marketing tools
2. **Data sensitivity** - Search for PII, financial, health keywords
3. **Business function** - Detect admin, infrastructure, data ops keywords
4. **Application complexity** - Count forms, inputs, AJAX calls

**Implementation:** `scripts/semantic-criticality-analysis.py` (NOT for production use)

## Test Results on qualys.com (295 domains)

### Category Changes: 59 domains (20%)

**Problems Found:**

1. **Marketing sites scored TOO HIGH**
   - www.qualys.com: 3.6 → 5.0 (+5.5 adjustment) ❌
   - Detected "personal information" in cookie consent banner (false positive)
   - Detected "admin" in footer navigation links (false positive)
   - **Should decrease** score (marketing = lower risk) but **increased**

2. **Context doesn't override false positives**
   - Marketing context: -0.5
   - PII false positive: +1.0
   - Admin false positive: +1.2
   - Net: +1.7 (WRONG - should be negative)

3. **Average adjustment: +0.71**
   - 90.8% domains got positive adjustments (increased risk)
   - Most adjustments were from false positives
   - Only 1% got negative adjustments (decreased risk)

## Why It Failed

### 1. Duplicates Nuclei Findings

What we tried to extract from HTTP:
- Login forms → Already in `auth.traditional.basic_auth`
- Password fields → Already in findings
- SSO indicators → Already in `auth.enterprise.saml_sso`
- Payment keywords → Could be in findings

**Conclusion:** Nuclei templates already capture this better

### 2. False Positives from Text Analysis

**Marketing Sites:**
```
Privacy Policy Text: "We collect personal information..."
Semantic Analyzer: PII handling detected! +1.0

Footer Links: "Admin Login"
Semantic Analyzer: Admin console detected! +1.2

Cookie Banner: "Do not sell my personal information"
Semantic Analyzer: PII handling detected! +1.0

RESULT: Marketing site scores HIGHER (wrong!)
```

**Should be:** Marketing sites score LOWER (public-facing, less critical)

### 3. Context Cannot Be Reliably Inferred

**Example: www.qualys.com**
```
Detected:
- Heavy tracking (Google Analytics, Marketo) → Marketing
- A/B testing (VWO) → Marketing
- "Admin" in text → Operational?
- "Personal information" → Sensitive data?

Context: MARKETING (correctly detected)
But PII/Admin keywords override it → Final score too high
```

**Problem:** Text keywords create conflicting signals that override context

### 4. No Better Than Domain Patterns

**Current approach works:**
```python
# Simple domain patterns
'portal.': +0.7
'admin.': +0.8
'dev.': -0.7

# Combined with Nuclei findings
auth.enterprise.saml_sso: +0.6
auth.mfa: +0.5

RESULT: Accurate scoring, 100% dev/test detection
```

**Semantic analysis adds:**
- False positives from privacy text
- Conflicting signals
- Complexity without accuracy gain

## What Actually Works

### ✅ Domain Name Patterns
- `portal.*`, `admin.*`, `api.*` - Clear indicators
- `dev.*`, `test.*` - 100% accuracy for non-production
- Simple, fast, deterministic

### ✅ Nuclei Findings
- Already detect auth mechanisms (SAML, MFA, basic)
- Already detect tech stack (WordPress, Rails, nginx)
- Already detect sensitive endpoints
- Comprehensive and accurate

### ✅ Page Title Keywords
- "Portal", "Login", "Admin" in title - Reliable
- "404", "403" for error pages - 100% accurate
- Simple keyword matching works

### ❌ HTTP Body Text Analysis
- Too many false positives
- Privacy policies contain PII keywords
- Footer links contain "admin"
- Marketing copy contains everything

## Lessons Learned

### 1. More Data ≠ Better Accuracy

Having the full HTTP response doesn't mean we should use it all. The body text adds noise, not signal.

### 2. Domain Name > Body Text

```
portal.example.com + title "Portal" = HIGH confidence
example.com + "admin" in footer = LOW confidence (false positive)
```

### 3. Nuclei Findings Are Sufficient

Templates already extract:
- Authentication mechanisms
- Technology stack
- Sensitive endpoints
- Security misconfigurations

We don't need to re-extract from HTML.

### 4. Simple Rules Win

```python
# This works (domain + title + findings)
score = 1.0 + domain_score + title_score + findings_score
✅ Fast, accurate, explainable

# This doesn't (adding semantic analysis)
score = base_score + domain + title + findings + semantic_adjustment
❌ Slow, false positives, confusing
```

## What We Keep

### Use HTTP Response For:

1. **Page Title** - Reliable indicator (`<title>` tag)
2. **Error Page Detection** - 404/403 in title and body
3. **Meta Description** (optional) - Sometimes useful

### DON'T Use HTTP Response For:

1. ❌ Body text keyword searching (false positives)
2. ❌ PII/financial keyword detection (privacy policies)
3. ❌ Business function inference (unreliable)
4. ❌ External script counting (already know from context)
5. ❌ "Semantic" analysis of any kind

## Current Scoring Model (Final)

```python
def calculate_criticality(domain, title, findings):
    score = 1.0  # Base

    # Domain patterns (reliable)
    score += score_domain(domain)  # portal, api, admin, dev/test

    # Title keywords (reliable)
    score += score_title(title)  # Portal, Login, Admin, 404

    # Nuclei findings (comprehensive)
    score += score_findings(findings)  # SAML, MFA, WordPress, etc.

    # Error page detection (reliable)
    if is_error_page(title):
        score -= 0.8

    return max(0.1, min(5.0, score))
```

**No semantic analysis of body text.**

## Files to Ignore

These scripts were experiments, NOT for production:
- `scripts/semantic-criticality-analysis.py` - Creates false positives
- `docs/research/semantic-criticality-from-http-response.md` - Rejected approach

## Recommendation

**Use domain patterns + page title + Nuclei findings ONLY.**

- ✅ Accurate (100% dev/test detection)
- ✅ Fast (<10ms per domain)
- ✅ Explainable (clear factors)
- ✅ Deterministic
- ❌ NO body text analysis
- ❌ NO semantic keyword searching

**Status:** Decision final, do not revisit
**Date:** October 17, 2025
