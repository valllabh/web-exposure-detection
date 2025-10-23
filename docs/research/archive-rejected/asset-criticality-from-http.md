# Asset Criticality Determination from HTTP Response Data

**Date:** October 17, 2025
**Status:** Research & Implementation Guide
**Purpose:** Automatically determine asset criticality using domain names, HTTP responses, titles, and descriptions

## Available Data Sources

### What We Have
1. **Domain Name:** `portal.qg3.apps.qualys.com`
2. **HTTP Response:** Headers, status codes, body content
3. **Title Tag:** `<title>Qualys Portal</title>`
4. **Description Tag:** `<meta name="description" content="...">`
5. **Page Content:** HTML, JavaScript, text

### What We Can Extract
- Domain patterns and keywords
- Page purpose from title/description
- Authentication indicators
- Business function keywords
- Technology stack hints
- Data handling clues

---

## Criticality Scoring Framework

### Criticality Score: 0.1x - 5.0x (Asset Value Multiplier)

```
Base Multiplier: 1.0

Adjustments from 5 categories:
1. Domain Pattern Analysis (30%)
2. Page Purpose & Content (25%)
3. Authentication & Security (20%)
4. Business Function (15%)
5. Data Sensitivity Indicators (10%)

Final: Sum adjustments, apply floor (0.1x) and ceiling (5.0x)
```

---

## Category 1: Domain Pattern Analysis (30%)

### Subdomain Patterns

**Production/Critical (+0.3 to +0.8):**
```python
patterns_high_value = {
    # Customer Facing
    'www': +0.5,
    'portal': +0.6,
    'app': +0.5,
    'customer': +0.7,
    'client': +0.6,

    # Revenue/Finance
    'pay': +0.8,
    'payment': +0.8,
    'checkout': +0.8,
    'billing': +0.7,
    'invoice': +0.6,
    'store': +0.6,
    'shop': +0.6,

    # Authentication/Identity
    'auth': +0.6,
    'login': +0.5,
    'sso': +0.6,
    'identity': +0.6,
    'oauth': +0.5,

    # APIs
    'api': +0.4,
    'gateway': +0.5,

    # Infrastructure
    'admin': +0.4,
    'dashboard': +0.5,
    'console': +0.5,
    'control': +0.5
}
```

**Development/Non-Production (-0.3 to -0.5):**
```python
patterns_low_value = {
    'dev': -0.4,
    'develop': -0.4,
    'development': -0.4,
    'test': -0.4,
    'testing': -0.4,
    'qa': -0.3,
    'stage': -0.3,
    'staging': -0.3,
    'uat': -0.3,
    'sandbox': -0.4,
    'demo': -0.3,
    'preview': -0.2,
    'localhost': -0.5
}
```

**Internal/Private (-0.1 to -0.2):**
```python
patterns_internal = {
    'internal': -0.2,
    'corp': -0.1,
    'intranet': -0.2,
    'private': -0.2,
    '.local': -0.2,
    'vpn': -0.1
}
```

### Domain Length & Complexity
```python
# Shorter, cleaner domains = customer facing = higher value
domain_parts = domain.split('.')

if len(domain_parts) == 2:  # example.com
    adjustment += 0.2
elif len(domain_parts) == 3:  # www.example.com
    adjustment += 0.1
elif len(domain_parts) >= 5:  # svc-123.internal.dev.example.com
    adjustment -= 0.2  # likely internal/infrastructure
```

---

## Category 2: Page Purpose & Content (25%)

### Title Tag Analysis

**Enterprise/Production Indicators (+0.3 to +0.6):**
```python
title_keywords_high = {
    # Customer Portal
    'portal': +0.5,
    'dashboard': +0.4,
    'console': +0.4,
    'customer': +0.5,
    'account': +0.4,

    # Business Apps
    'login': +0.3,
    'sign in': +0.3,
    'workspace': +0.4,
    'platform': +0.4,

    # E-commerce
    'store': +0.5,
    'shop': +0.5,
    'cart': +0.5,
    'checkout': +0.6,

    # SaaS
    'app': +0.4,
    'application': +0.4,
    'service': +0.3
}
```

**Development/Test Indicators (-0.2 to -0.4):**
```python
title_keywords_low = {
    'test': -0.3,
    'staging': -0.3,
    'development': -0.4,
    'demo': -0.3,
    'sandbox': -0.3,
    'example': -0.4,
    'localhost': -0.5
}
```

**Generic/Low Value (0 to -0.2):**
```python
title_keywords_generic = {
    'welcome': 0,
    'home': 0,
    'index': -0.1,
    'default': -0.2,
    'nginx': -0.2,  # default server page
    'apache': -0.2,
    '404': -0.3,
    'error': -0.3
}
```

### Description Tag Analysis

**Business Function Keywords (+0.2 to +0.5):**
```python
description_keywords = {
    # Customer facing
    'customer': +0.3,
    'client': +0.3,
    'user account': +0.3,
    'manage': +0.3,

    # Commerce
    'purchase': +0.4,
    'buy': +0.4,
    'payment': +0.5,
    'subscription': +0.4,

    # Enterprise
    'enterprise': +0.4,
    'business': +0.3,
    'organization': +0.3,
    'team': +0.2,

    # Security/Sensitive
    'secure': +0.2,
    'authentication': +0.3,
    'authorized': +0.2,
    'compliance': +0.3
}
```

### Page Content Hints

**Look for in HTTP response body:**
```python
content_indicators_high = {
    # Forms (data collection)
    '<form': +0.2,
    'type="password"': +0.3,
    'type="email"': +0.2,
    'type="credit-card"': +0.5,

    # Payment processors
    'stripe': +0.5,
    'paypal': +0.5,
    'braintree': +0.5,

    # Auth providers
    'okta': +0.3,
    'auth0': +0.3,
    'saml': +0.4,

    # User data
    'profile': +0.2,
    'account settings': +0.3,
    'personal information': +0.3,
    'billing information': +0.4
}

content_indicators_low = {
    # Static/Informational
    'coming soon': -0.2,
    'under construction': -0.3,
    'maintenance': -0.2,

    # Default pages
    'default page': -0.3,
    'it works': -0.4,
    'test page': -0.4
}
```

---

## Category 3: Authentication & Security (20%)

### Authentication Mechanisms

**From Nuclei Findings:**
```python
auth_multipliers = {
    # Enterprise Auth
    'auth.enterprise.saml_sso': +0.4,
    'auth.enterprise.oauth': +0.4,
    'auth.enterprise.ldap': +0.3,

    # MFA
    'auth.mfa': +0.3,
    'auth.2fa': +0.3,

    # Traditional
    'auth.traditional.registration': +0.3,  # handles PII
    'auth.traditional.password_recovery': +0.2,
    'auth.traditional.basic_auth': +0.1,

    # Multiple auth types (3+)
    'multiple_auth': +0.5
}
```

### From HTTP Headers

**Security Headers (indicate valuable asset):**
```python
header_indicators = {
    # Strict security
    'Strict-Transport-Security': +0.2,
    'Content-Security-Policy': +0.2,
    'X-Frame-Options': +0.1,

    # WAF/Protection
    'X-WAF': +0.3,
    'CF-Ray': +0.2,  # Cloudflare
    'X-Akamai': +0.3,

    # Auth headers
    'WWW-Authenticate': +0.2,
    'Set-Cookie: session': +0.2,
    'Authorization required': +0.3
}
```

### From Response Behavior

**Login/Auth Pages:**
```python
# HTTP 401/403 responses indicate protected resources
if status_code == 401:
    adjustment += 0.3  # requires authentication
elif status_code == 403:
    adjustment += 0.2  # access controlled

# Redirect to login
if 'Location' in headers and 'login' in headers['Location']:
    adjustment += 0.3
```

---

## Category 4: Business Function (15%)

### Functional Role Detection

**From Domain + Title + Description Combined:**
```python
business_functions = {
    # Revenue Critical
    'ecommerce': +0.6,
    'payment_gateway': +0.7,
    'billing_system': +0.6,
    'subscription_service': +0.5,

    # Customer Critical
    'customer_portal': +0.6,
    'support_portal': +0.4,
    'helpdesk': +0.3,
    'crm': +0.5,

    # Operations Critical
    'admin_console': +0.4,
    'control_panel': +0.5,
    'management_dashboard': +0.4,

    # API/Integration
    'api_gateway': +0.4,
    'integration_hub': +0.3,
    'webhook': +0.2,

    # Marketing/Public
    'blog': +0.2,
    'marketing_site': +0.1,
    'documentation': +0.1,
    'static_content': 0
}
```

### Composite Detection Example
```python
def detect_business_function(domain, title, description):
    # E-commerce detection
    if any(x in domain for x in ['shop', 'store', 'cart']) and \
       any(x in title.lower() for x in ['shop', 'store', 'buy']) and \
       any(x in description.lower() for x in ['purchase', 'product']):
        return 'ecommerce', +0.6

    # Customer portal
    if 'portal' in domain and \
       'login' in title.lower() and \
       'customer' in description.lower():
        return 'customer_portal', +0.6

    # Blog/Marketing
    if 'blog' in domain and \
       'blog' in title.lower():
        return 'blog', +0.2

    return 'unknown', 0
```

---

## Category 5: Data Sensitivity Indicators (10%)

### Keywords Indicating Sensitive Data

**From Title + Description + Content:**
```python
sensitivity_keywords = {
    # PCI
    'payment': +0.5,
    'credit card': +0.6,
    'billing': +0.4,
    'transaction': +0.4,

    # PII
    'personal information': +0.4,
    'user data': +0.3,
    'profile': +0.2,
    'account': +0.2,
    'registration': +0.3,

    # PHI (Healthcare)
    'patient': +0.6,
    'medical': +0.6,
    'health': +0.5,
    'hipaa': +0.6,

    # Financial
    'financial': +0.5,
    'banking': +0.6,
    'investment': +0.5,

    # Proprietary
    'confidential': +0.3,
    'proprietary': +0.3,
    'internal only': +0.4
}
```

### Form Field Detection
```python
# Parse HTML for form inputs
form_fields_sensitivity = {
    'ssn': +0.6,
    'social security': +0.6,
    'credit-card': +0.6,
    'cvv': +0.6,
    'tax-id': +0.5,
    'date-of-birth': +0.4,
    'password': +0.3,
    'email': +0.2,
    'phone': +0.2
}
```

---

## Complete Algorithm

```python
def calculate_asset_criticality(domain, http_response, title, description):
    """
    Returns: Asset criticality multiplier (0.1x - 5.0x)
    """

    base = 1.0
    adjustments = 0.0

    # 1. Domain Pattern (30%)
    domain_score = analyze_domain_pattern(domain)
    adjustments += domain_score * 0.30

    # 2. Page Purpose (25%)
    title_score = analyze_title(title)
    desc_score = analyze_description(description)
    content_score = analyze_content(http_response.body)
    page_score = (title_score + desc_score + content_score) / 3
    adjustments += page_score * 0.25

    # 3. Authentication (20%)
    auth_score = analyze_auth(http_response.headers, http_response.body)
    adjustments += auth_score * 0.20

    # 4. Business Function (15%)
    function, function_score = detect_business_function(
        domain, title, description
    )
    adjustments += function_score * 0.15

    # 5. Data Sensitivity (10%)
    sensitivity_score = analyze_data_sensitivity(
        title, description, http_response.body
    )
    adjustments += sensitivity_score * 0.10

    # Calculate final multiplier
    multiplier = base + adjustments

    # Apply bounds
    multiplier = max(0.1, min(5.0, multiplier))

    return {
        'multiplier': round(multiplier, 2),
        'base': base,
        'adjustments': round(adjustments, 2),
        'breakdown': {
            'domain_pattern': round(domain_score * 0.30, 2),
            'page_purpose': round(page_score * 0.25, 2),
            'authentication': round(auth_score * 0.20, 2),
            'business_function': round(function_score * 0.15, 2),
            'data_sensitivity': round(sensitivity_score * 0.10, 2)
        },
        'detected_function': function
    }
```

---

## Real Examples from Qualys.com Data

### Example 1: blog.qualys.com

**Input:**
```
Domain: blog.qualys.com
Title: Facebook (likely incorrect/CDN issue)
Description: Cybersecurity blog covering software, services, and risk insights...
```

**Analysis:**
```python
# Domain Pattern
'blog' in domain → +0.2

# Page Purpose
description contains 'blog', 'cybersecurity' → +0.3

# Authentication
SAML detected from Nuclei → +0.3

# Business Function
blog (marketing/content) → +0.2

# Data Sensitivity
No sensitive data keywords → 0

Total: 1.0 + (0.2*0.3 + 0.3*0.25 + 0.3*0.2 + 0.2*0.15 + 0*0.1)
     = 1.0 + (0.06 + 0.075 + 0.06 + 0.03 + 0)
     = 1.0 + 0.225
     = 1.23x → Round to 1.2x
```

**Result: 1.2x multiplier** (blog with enterprise auth, moderate value)

### Example 2: portal.qg3.apps.qualys.com

**Input:**
```
Domain: portal.qg3.apps.qualys.com
Title: Qualys Portal
Description: (none visible)
```

**Analysis:**
```python
# Domain Pattern
'portal' in domain → +0.6
'.apps.' subdomain → +0.2
Total: +0.8

# Page Purpose
'portal' in title → +0.5

# Authentication
SAML/SSO detected → +0.4

# Business Function
Customer portal detected → +0.6

# Data Sensitivity
'portal' + 'login' implies user data → +0.3

Total: 1.0 + (0.8*0.3 + 0.5*0.25 + 0.4*0.2 + 0.6*0.15 + 0.3*0.1)
     = 1.0 + (0.24 + 0.125 + 0.08 + 0.09 + 0.03)
     = 1.0 + 0.565
     = 1.57x → Round to 1.6x
```

**Result: 1.6x multiplier** (enterprise portal, high value)

### Example 3: qualysapi.qg2.apps.qualys.com

**Input:**
```
Domain: qualysapi.qg2.apps.qualys.com
Title: Qualys - Login
Description: (none)
```

**Analysis:**
```python
# Domain Pattern
'qualysapi' → +0.4
'.apps.' → +0.2
Total: +0.6

# Page Purpose
'Login' in title → +0.3

# Authentication
Login page → +0.3

# Business Function
API gateway → +0.4

# Data Sensitivity
API with login → +0.3

Total: 1.0 + (0.6*0.3 + 0.3*0.25 + 0.3*0.2 + 0.4*0.15 + 0.3*0.1)
     = 1.0 + (0.18 + 0.075 + 0.06 + 0.06 + 0.03)
     = 1.0 + 0.405
     = 1.41x → Round to 1.4x
```

**Result: 1.4x multiplier** (API with auth, moderate-high value)

---

## Edge Cases & Fallbacks

### Missing Data
```python
if not title or title in ['', 'Untitled']:
    # Use domain pattern only, reduce confidence
    multiplier *= 0.8

if not description:
    # Rely on domain + title + content
    # No penalty, just less data

if status_code == 404 or 'error' in title.lower():
    # Error pages are low value
    multiplier = max(0.1, multiplier - 0.5)
```

### Conflicting Signals
```python
# Example: staging.portal.company.com
if ('staging' in domain or 'test' in domain) and \
   ('portal' in domain or 'portal' in title):
    # Staging wins (non-production)
    multiplier = max(0.5, multiplier * 0.6)
```

### Default Pages
```python
default_page_indicators = [
    'it works',
    'apache',
    'nginx',
    'default page',
    'coming soon',
    'under construction'
]

if any(indicator in title.lower() for indicator in default_page_indicators):
    multiplier = 0.1  # minimal value
```

---

## Implementation Checklist

- [ ] Parse domain name for patterns
- [ ] Extract title from HTML `<title>` tag
- [ ] Extract description from `<meta name="description">`
- [ ] Analyze HTTP headers for security/auth indicators
- [ ] Parse response body for form fields, keywords
- [ ] Combine Nuclei auth findings
- [ ] Apply weighted scoring formula
- [ ] Apply floor (0.1x) and ceiling (5.0x)
- [ ] Generate explanation for multiplier
- [ ] Store in report data structure

---

## Output Format

```json
{
  "domain": "portal.qg3.apps.qualys.com",
  "asset_criticality": {
    "multiplier": 1.6,
    "confidence": "high",
    "breakdown": {
      "domain_pattern": 0.24,
      "page_purpose": 0.13,
      "authentication": 0.08,
      "business_function": 0.09,
      "data_sensitivity": 0.03
    },
    "detected_signals": {
      "domain_type": "customer_portal",
      "auth_type": "enterprise_sso",
      "business_function": "customer_portal",
      "data_handling": "user_accounts"
    },
    "explanation": "Enterprise portal (portal.*) with SAML/SSO authentication, indicates customer-facing application with user data handling. Multiplier: 1.6x"
  }
}
```

---

## Validation Strategy

### Phase 1: Manual Review
- Calculate multipliers for 50 sample domains
- Security team reviews for accuracy
- Adjust weights based on feedback

### Phase 2: Comparative Validation
- Compare auto-detected multipliers to business owner input
- Track differences, identify patterns
- Tune algorithm

### Phase 3: Outcome Validation
- Track which domains actually get breached
- Compare predicted criticality to actual impact
- Refine over time

---

## Next Steps

1. **Implement domain pattern analyzer** (regex-based)
2. **Implement title/description parser** (keyword matching)
3. **Implement content analyzer** (form detection, keyword extraction)
4. **Combine with existing Nuclei auth findings**
5. **Apply weighted scoring**
6. **Add to report generation**
7. **Validate with real data**
8. **Iterate based on feedback**

---

**Document Status:** Implementation Ready
**Priority:** High (prerequisite for financial risk model)
**Owner:** Engineering Team
**Last Updated:** October 17, 2025
