# Using HTTP Response Data for Criticality Scoring

**Date:** October 17, 2025
**Source:** Nuclei results JSONL file (`nuclei-results/results.jsonl`)
**Purpose:** Extract HTTP response data for rule-based criticality assessment

## Data Location

**File:** `results/{domain}/nuclei-results/results.jsonl`
**Size:** ~50MB (full HTTP responses)
**Format:** JSONL (one JSON object per line)

## Available Data in JSONL

```json
{
  "host": "www.qualys.com",
  "url": "https://www.qualys.com/",
  "template-id": "frontend-tech-detection",
  "response": "<html>...</html>",  // Full HTML body
  "extracted-results": {},
  "matcher-status": true,
  ...
}
```

### Key Fields for Criticality

| Field | Contains | Use For |
|-------|----------|---------|
| `response` | Full HTML body | Title, meta tags, forms, keywords |
| `host` | Domain name | Domain pattern matching |
| `extracted-results` | Nuclei findings | Auth, tech, API patterns |
| `url` | Full URL | Path analysis |
| `matcher-status` | Boolean | Filter valid responses |

## Extractable Data from HTTP Response

### 1. Page Title
```python
import re

html = jsonl_entry['response']
title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE)
title = title_match.group(1) if title_match else ""

# Example: "Enterprise Cyber Risk & Security Platform | Qualys"
```

### 2. Meta Description
```python
# Method 1: name="description"
desc_match = re.search(
    r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']',
    html,
    re.IGNORECASE
)

# Method 2: content first
if not desc_match:
    desc_match = re.search(
        r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']description["\']',
        html,
        re.IGNORECASE
    )

description = desc_match.group(1) if desc_match else ""

# Example: "Discover how Qualys helps your business measure & eliminate cyber threats..."
```

### 3. Password/Login Forms
```python
# Password input fields
has_password_field = bool(re.search(
    r'<input[^>]+type=["\']password["\']',
    html,
    re.IGNORECASE
))

# Login forms
has_login_form = bool(re.search(
    r'<form[^>]*?(login|signin|sign-in|authenticate)',
    html,
    re.IGNORECASE
))

# Registration forms
has_registration = bool(re.search(
    r'<form[^>]*?(register|signup|sign-up|create.account)',
    html,
    re.IGNORECASE
))
```

### 4. Payment/Commerce Keywords
```python
payment_keywords = [
    'checkout', 'payment', 'pay now', 'billing',
    'credit card', 'cvv', 'card number',
    'purchase', 'buy now', 'add to cart'
]

has_payment = any(
    keyword in html.lower()
    for keyword in payment_keywords
)
```

### 5. SSO/Enterprise Auth
```python
sso_indicators = [
    'saml', 'sso', 'single sign-on',
    'microsoft', 'azure ad', 'okta',
    'auth0', 'onelogin', 'keycloak'
]

has_enterprise_auth = any(
    indicator in html.lower()
    for indicator in sso_indicators
)
```

### 6. Error Pages
```python
error_indicators = [
    ('404', 'not found'),
    ('403', 'forbidden'),
    ('500', 'internal server error'),
    ('503', 'service unavailable'),
    ('it works', 'default page'),
    ('nginx', 'welcome to nginx'),
    ('apache', 'apache2 default page')
]

is_error_page = any(
    all(keyword in html.lower() for keyword in pair)
    for pair in error_indicators
)
```

### 7. Framework/Technology Hints
```python
tech_hints = {
    'react': r'(react|data-reactroot|__REACT)',
    'angular': r'(ng-app|ng-controller|angular)',
    'vue': r'(vue|v-if|v-for)',
    'wordpress': r'(wp-content|wp-includes)',
    'django': r'(csrfmiddlewaretoken|django)',
    'rails': r'(csrf-token|rails|_session_id)',
}

detected_tech = {
    tech: bool(re.search(pattern, html, re.IGNORECASE))
    for tech, pattern in tech_hints.items()
}
```

## Rule-Based Scoring with HTTP Data

### Enhanced Scoring Function

```python
def calculate_criticality_from_http(domain, html, nuclei_findings):
    """
    Calculate criticality using domain, HTTP response, and Nuclei findings
    """

    score = 1.0
    factors = []

    # Extract from HTML
    title = extract_title(html)
    description = extract_description(html)

    # 1. Domain Pattern (30%)
    domain_score = score_domain_pattern(domain)
    score += domain_score * 0.30
    if domain_score != 0:
        factors.append(f"Domain: {domain_score:+.1f}")

    # 2. Title & Description (25%)
    title_score = score_keywords(title, TITLE_KEYWORDS)
    desc_score = score_keywords(description, DESC_KEYWORDS)
    page_score = (title_score + desc_score) / 2
    score += page_score * 0.25
    if page_score != 0:
        factors.append(f"Page content: {page_score:+.1f}")

    # 3. HTTP Response Content (20%)
    content_score = 0

    # Error pages (strong negative)
    if is_error_page(html, title):
        content_score -= 0.8
        factors.append("Error page: -0.8")

    # Payment indicators (strong positive)
    elif has_payment_keywords(html):
        content_score += 1.0
        factors.append("Payment: +1.0")

    # Login/auth forms
    elif has_login_form(html):
        content_score += 0.5
        factors.append("Login form: +0.5")

    # Registration
    elif has_registration_form(html):
        content_score += 0.4
        factors.append("Registration: +0.4")

    score += content_score * 0.20

    # 4. Nuclei Findings (20%)
    findings_score = score_nuclei_findings(nuclei_findings)
    score += findings_score * 0.20
    if findings_score > 0:
        factors.append(f"Findings: +{findings_score:.1f}")

    # 5. Technology Stack (5%)
    tech_score = score_detected_tech(html)
    score += tech_score * 0.05
    if tech_score > 0:
        factors.append(f"Tech: +{tech_score:.1f}")

    # Apply bounds
    final_score = max(0.1, min(5.0, round(score, 2)))

    # Category
    if final_score >= 3.5:
        category = "CRITICAL"
    elif final_score >= 2.0:
        category = "HIGH"
    elif final_score >= 1.0:
        category = "MEDIUM"
    else:
        category = "LOW"

    return {
        'score': final_score,
        'category': category,
        'factors': factors
    }
```

## Real Example: www.qualys.com

### Input Data (from JSONL)
```json
{
  "host": "www.qualys.com",
  "response": "<html>...<title>Enterprise Cyber Risk & Security Platform | Qualys</title>..."
}
```

### Extracted Data
```python
title = "Enterprise Cyber Risk & Security Platform | Qualys"
description = "Discover how Qualys helps your business measure & eliminate cyber threats..."

# From HTML analysis
has_login_form = False  # (marketing site, no login)
has_payment = False     # (no checkout)
is_error_page = False   # (valid page)

# Keywords in title
enterprise_keyword = True  # "Enterprise"
platform_keyword = True    # "Platform"
```

### Scoring Calculation
```
Base: 1.0

Domain (www.*): +0.5
  → 0.5 * 0.30 = +0.15

Title ("Enterprise", "Platform"): +0.4
  → 0.4 * 0.25 = +0.10

Content (marketing site): 0.0
  → 0.0 * 0.20 = 0.0

Findings (from Nuclei):
  - Technologies detected: +0.3
  → 0.3 * 0.20 = +0.06

Tech stack (React, etc): +0.2
  → 0.2 * 0.05 = +0.01

Total: 1.0 + 0.15 + 0.10 + 0.0 + 0.06 + 0.01 = 1.32

Final Score: 1.32 (MEDIUM)
Category: MEDIUM
```

## Implementation Steps

### Step 1: Parse JSONL
```python
import json

def read_nuclei_jsonl(filepath):
    """Read JSONL file with HTTP responses"""
    results = []
    with open(filepath, 'r') as f:
        for line in f:
            if line.strip():
                results.append(json.loads(line))
    return results
```

### Step 2: Extract HTTP Data
```python
def extract_http_data(jsonl_entry):
    """Extract useful data from JSONL entry"""
    return {
        'domain': jsonl_entry.get('host', ''),
        'url': jsonl_entry.get('url', ''),
        'html': jsonl_entry.get('response', ''),
        'template_id': jsonl_entry.get('template-id', ''),
        'findings': jsonl_entry.get('extracted-results', {})
    }
```

### Step 3: Score Each Domain
```python
def score_all_domains(jsonl_filepath):
    """Score all domains from JSONL"""

    results = read_nuclei_jsonl(jsonl_filepath)
    scores = {}

    for entry in results:
        data = extract_http_data(entry)

        if not data['html']:  # Skip if no response
            continue

        domain = data['domain']

        # Calculate criticality
        criticality = calculate_criticality_from_http(
            domain=domain,
            html=data['html'],
            nuclei_findings=data['findings']
        )

        # Store (use max score if domain appears multiple times)
        if domain not in scores or criticality['score'] > scores[domain]['score']:
            scores[domain] = criticality

    return scores
```

### Step 4: Aggregate with Findings
```python
def combine_with_findings(criticality_scores, findings_data):
    """Combine criticality scores with findings.json data"""

    for domain, findings in findings_data.items():
        if domain in criticality_scores:
            # Add criticality to findings
            findings['asset_criticality'] = criticality_scores[domain]
        else:
            # Default for domains without HTTP data
            findings['asset_criticality'] = {
                'score': 1.0,
                'category': 'MEDIUM',
                'factors': ['No HTTP data available']
            }

    return findings_data
```

## Advantages of Using HTTP Response

✅ **Rich Data:** Full HTML body with all page content
✅ **Accurate:** Direct analysis vs pattern matching
✅ **Context:** See actual page purpose (login, payment, error)
✅ **Forms:** Detect password, registration, checkout forms
✅ **Keywords:** Extract from title, description, body
✅ **Error Detection:** Identify 404, 403, default pages

## Summary

### Data Flow

```
1. Nuclei Scan
   ↓
2. JSONL with HTTP Responses
   ↓
3. Extract: domain, title, description, HTML body
   ↓
4. Rule-Based Scoring:
   - Domain patterns (30%)
   - Page content (25%)
   - HTTP content (20%)
   - Nuclei findings (20%)
   - Tech stack (5%)
   ↓
5. Criticality Score (0.1 - 5.0)
```

### Implementation Priority

**Week 1:**
- Parse JSONL file
- Extract title, description from HTML
- Basic keyword scoring

**Week 2:**
- Form detection (password, registration)
- Error page detection
- Payment/commerce keywords

**Week 3:**
- Combine with domain patterns
- Integrate with Nuclei findings
- Weight and calibrate

**Week 4:**
- Test on full dataset
- Tune weights
- Add to report generation

---

**Status:** Implementation Ready
**Data Source:** `nuclei-results/results.jsonl`
**Next:** Code the HTTP parsing and scoring functions
**Date:** October 17, 2025
