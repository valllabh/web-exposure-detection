# Semantic Criticality Analysis from HTTP Response

**Date:** October 17, 2025
**Problem:** Current approach duplicates Nuclei findings (auth, payment, etc.)
**Solution:** Extract DIFFERENT insights from HTTP response that templates DON'T provide

## Problem Statement

Current implementation extracts:
- Password fields → Already in `auth.traditional.basic_auth`
- SSO indicators → Already in `auth.enterprise.saml_sso`
- Login forms → Already detected by templates
- Payment keywords → Could be in findings

**This is redundant!** We need to extract insights Nuclei templates CANNOT provide.

## What Nuclei Templates DON'T Tell Us

### 1. Operational vs Marketing Context

**Marketing Site Signals:**
```html
<!-- Heavy tracking/analytics -->
<script src="google-analytics.com"></script>
<script src="googletagmanager.com"></script>
<script src="marketo.net/munchkin.js"></script>
<script src="drift.com"></script>  <!-- Chat widget -->
<script src="clarity.ms"></script> <!-- MS analytics -->
<script src="visualwebsiteoptimizer.com"></script> <!-- A/B testing -->

<!-- Marketing language in description -->
<meta name="description" content="Discover how Qualys helps your business...">
<meta property="og:type" content="website">

<!-- Social sharing optimized -->
<meta property="og:image" content="...">
<meta name="twitter:card" content="summary">
```

**Operational Tool Signals:**
```html
<!-- Minimal tracking -->
<script src="internal-monitoring.js"></script>

<!-- Operational language -->
<title>Admin Console - Manage Users</title>
<meta name="description" content="Login to manage system configuration">

<!-- No social metadata -->
<!-- No A/B testing tools -->
<!-- No chat widgets -->
```

**Scoring:**
- Marketing site with heavy tracking: **-0.5** (lower risk, public-facing)
- Operational tool with minimal tracking: **+0.8** (higher risk, internal function)

### 2. Data Sensitivity from Content

**Extract body text and analyze for keywords:**

```python
# High sensitivity indicators
pii_keywords = [
    'personal information', 'pii', 'personally identifiable',
    'social security', 'ssn', 'passport', 'driver license',
    'date of birth', 'dob', 'address', 'phone number'
]

financial_keywords = [
    'credit card', 'bank account', 'routing number',
    'financial records', 'transaction history', 'payment details',
    'account balance', 'wire transfer'
]

health_keywords = [
    'medical records', 'patient data', 'hipaa', 'phi',
    'health information', 'diagnosis', 'prescription'
]

compliance_keywords = [
    'gdpr', 'ccpa', 'sox', 'pci-dss', 'pci compliance',
    'data protection', 'privacy policy'
]

# Internal/confidential indicators
confidential_keywords = [
    'confidential', 'proprietary', 'internal only',
    'restricted access', 'classified', 'sensitive'
]
```

**Scoring:**
- Mentions PII/health data: **+1.0**
- Mentions financial data: **+0.9**
- Mentions compliance requirements: **+0.7**
- Mentions "confidential"/"internal only": **+0.8**

### 3. Business Function from Text

**Analyze page content (not just title) to understand function:**

```python
# Critical business functions
admin_functions = [
    'user management', 'admin console', 'control panel',
    'system configuration', 'database admin', 'access control',
    'permissions', 'roles', 'privileges'
]

data_operations = [
    'data export', 'bulk operations', 'batch processing',
    'report generation', 'query builder', 'data warehouse'
]

infrastructure_ops = [
    'deployment', 'production environment', 'server management',
    'infrastructure', 'kubernetes', 'cloud resources'
]

# vs Supporting functions
marketing_ops = [
    'newsletter signup', 'contact us', 'request demo',
    'free trial', 'pricing', 'solutions'
]

support_functions = [
    'help center', 'documentation', 'knowledge base',
    'faq', 'support ticket', 'community forum'
]
```

**Scoring:**
- Admin/infrastructure functions: **+1.2**
- Data operations: **+0.9**
- Support/marketing functions: **-0.3**

### 4. Third-Party Integration Risk

**Analyze external script sources:**

```python
# Extract all external scripts
external_scripts = extract_script_sources(html)

# Categorize
tracking_services = ['google-analytics', 'googletagmanager', 'clarity', 'mixpanel']
marketing_tools = ['marketo', 'hubspot', 'salesforce', 'drift']
ab_testing = ['optimizely', 'vwo', 'google-optimize']
cdn_services = ['cloudflare', 'akamai', 'fastly']

# Count integrations
heavy_integration = len(external_scripts) > 10  # Many third parties
light_integration = len(external_scripts) < 3   # Minimal dependencies
```

**Scoring:**
- Heavy third-party integration (>10): **-0.4** (likely marketing/public)
- Light integration (<3): **+0.3** (likely internal/operational)
- Enterprise SSO only (Okta, Auth0): **+0.5** (internal tool)

### 5. Security Posture from Response

**Analyze HTTP response headers (already in JSONL):**

```python
security_headers = {
    'Content-Security-Policy': +0.2,
    'X-Frame-Options': +0.1,
    'Strict-Transport-Security': +0.1,
    'X-Content-Type-Options': +0.1,
    'Referrer-Policy': +0.1
}

# Missing critical headers
missing_csp = -0.2
missing_hsts = -0.1
```

**Note:** Response headers might already be in Nuclei findings, check first.

### 6. Application Complexity

**Analyze page structure:**

```python
# Extract from HTML
form_count = len(re.findall(r'<form', html, re.IGNORECASE))
input_count = len(re.findall(r'<input', html, re.IGNORECASE))
api_endpoints = extract_api_calls_from_js(html)  # From inline JS
ajax_calls = len(re.findall(r'fetch\(|XMLHttpRequest|axios', html))

# Simple page vs complex app
simple_page = form_count <= 1 and input_count < 5
complex_app = form_count >= 3 or input_count > 20
```

**Scoring:**
- Complex application (many forms/inputs): **+0.4**
- Simple content page: **-0.2**

### 7. User Base Indicators

**Extract from content text:**

```python
enterprise_indicators = [
    'enterprise customers', 'fortune 500', 'large organizations',
    'enterprise license', 'dedicated account manager'
]

consumer_indicators = [
    'free account', 'personal use', 'individual users',
    'consumer pricing', 'basic plan'
]

internal_indicators = [
    'employees only', 'internal use', 'staff portal',
    'employee directory', 'intranet'
]
```

**Scoring:**
- Enterprise/B2B: **+0.5**
- Internal/employees only: **+0.8**
- Consumer/free tier: **-0.2**

## Implementation Approach

### Step 1: Extract Text Content

```python
def extract_text_content(html: str) -> str:
    """Extract meaningful text from HTML (strip tags)"""
    # Remove script and style tags
    html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL | re.IGNORECASE)

    # Remove HTML tags
    text = re.sub(r'<[^>]+>', ' ', html)

    # Clean whitespace
    text = re.sub(r'\s+', ' ', text).strip()

    return text.lower()
```

### Step 2: Analyze Context

```python
def analyze_operational_context(html: str, text: str) -> Tuple[float, str]:
    """Determine if operational or marketing"""

    # Count tracking scripts
    tracking_count = len(re.findall(
        r'google-analytics|googletagmanager|mixpanel|segment|amplitude',
        html,
        re.IGNORECASE
    ))

    # Count marketing tools
    marketing_count = len(re.findall(
        r'marketo|hubspot|salesforce|drift|intercom|zendesk',
        html,
        re.IGNORECASE
    ))

    # Check for A/B testing
    has_ab_testing = bool(re.search(
        r'optimizely|vwo|google-optimize',
        html,
        re.IGNORECASE
    ))

    # Analyze description language
    description = extract_description_from_html(html)
    marketing_language = any(word in description.lower() for word in [
        'discover', 'learn', 'explore', 'transform', 'revolutionize'
    ])

    operational_language = any(word in description.lower() for word in [
        'login', 'manage', 'configure', 'admin', 'control'
    ])

    # Score
    if (tracking_count >= 3 or marketing_count >= 2 or has_ab_testing):
        return -0.5, "MARKETING"  # Lower risk, public site
    elif operational_language:
        return +0.8, "OPERATIONAL"  # Higher risk, internal tool
    elif marketing_language:
        return -0.3, "MARKETING"
    else:
        return 0.0, "UNKNOWN"
```

### Step 3: Analyze Data Sensitivity

```python
def analyze_data_sensitivity(text: str) -> Tuple[float, List[str]]:
    """Look for data sensitivity indicators in content"""

    indicators = []
    score = 0.0

    # PII indicators
    if any(kw in text for kw in ['personal information', 'pii', 'ssn']):
        score += 1.0
        indicators.append("PII handling")

    # Financial data
    if any(kw in text for kw in ['financial records', 'bank account', 'transaction']):
        score += 0.9
        indicators.append("Financial data")

    # Health data
    if any(kw in text for kw in ['medical records', 'patient data', 'hipaa']):
        score += 1.0
        indicators.append("Health data (HIPAA)")

    # Compliance
    if any(kw in text for kw in ['gdpr', 'pci-dss', 'sox']):
        score += 0.7
        indicators.append("Compliance requirements")

    # Confidential/internal
    if any(kw in text for kw in ['confidential', 'internal only', 'restricted']):
        score += 0.8
        indicators.append("Confidential/restricted")

    return score, indicators
```

### Step 4: Analyze Business Function

```python
def analyze_business_function(text: str) -> Tuple[float, str]:
    """Determine business function from content"""

    # Admin functions
    if any(kw in text for kw in ['admin console', 'user management', 'control panel']):
        return +1.2, "ADMIN"

    # Data operations
    if any(kw in text for kw in ['data export', 'report generation', 'query builder']):
        return +0.9, "DATA_OPS"

    # Infrastructure
    if any(kw in text for kw in ['deployment', 'infrastructure', 'production environment']):
        return +1.0, "INFRASTRUCTURE"

    # Marketing
    if any(kw in text for kw in ['newsletter', 'contact us', 'free trial', 'pricing']):
        return -0.3, "MARKETING"

    # Support
    if any(kw in text for kw in ['help center', 'documentation', 'knowledge base']):
        return -0.1, "SUPPORT"

    return 0.0, "UNKNOWN"
```

## Real Example Analysis

### www.qualys.com

**HTTP Response Analysis:**
```
External Scripts: 15+
- Google Analytics, GTM (tracking)
- Marketo (marketing automation)
- Drift (chat widget)
- VWO (A/B testing)
- Clarity (MS analytics)
- Pingdom (monitoring)

Description: "Discover how Qualys helps your business..."
Language: Marketing (discover, learn, transform)

Body Content (extracted):
- "Free Trial", "Request Demo", "Pricing"
- "Solutions", "Products", "Resources"
- No mentions of: admin, configure, manage, internal
```

**Semantic Analysis:**
```
Context: MARKETING (-0.5)
  - Heavy tracking (5+ services)
  - Marketing automation (Marketo)
  - A/B testing (VWO)
  - Chat widget (Drift)

Data Sensitivity: NONE (0.0)
  - No PII/financial mentions
  - Public marketing content
  - No compliance keywords

Business Function: MARKETING (-0.3)
  - Free trial, pricing mentions
  - Customer-facing content
  - No operational language

Integration Risk: HIGH_EXTERNAL (-0.4)
  - 15+ third-party scripts
  - Multiple tracking pixels
  - External dependencies

FINAL ADJUSTMENT: -1.2
(Original score 3.6 - 1.2 = 2.4)
Reclassified: HIGH → MEDIUM
```

### portal-bo.gov1.qualys.us

**HTTP Response Analysis:**
```
External Scripts: 2
- Internal monitoring only
- No marketing tools
- No tracking pixels

Title: "Qualys Portal"
Description: (none)

Body Content (extracted):
- "Login", "Username", "Password"
- "MFA", "Reset Password", "SSO"
- "Admin", "User Management"
- NO marketing language
```

**Semantic Analysis:**
```
Context: OPERATIONAL (+0.8)
  - Minimal external scripts
  - No marketing tools
  - Operational language (login, admin)

Data Sensitivity: MODERATE (+0.5)
  - User credentials
  - Admin functions mentioned
  - Access control

Business Function: ADMIN (+1.2)
  - User management mentioned
  - Admin console indicators
  - Control panel language

Integration Risk: LOW_EXTERNAL (+0.3)
  - Only 2 external scripts
  - Enterprise SSO (internal)

FINAL ADJUSTMENT: +2.8
(Original score 4.1 + 0 = 4.1)
Remains: CRITICAL
```

## Proposed Scoring Model

```python
def calculate_semantic_criticality(html: str) -> Dict:
    """
    Semantic analysis beyond Nuclei findings
    """

    # Extract text content
    text = extract_text_content(html)

    semantic_score = 0.0
    factors = []

    # 1. Operational vs Marketing context
    context_score, context_type = analyze_operational_context(html, text)
    semantic_score += context_score
    factors.append(f"Context: {context_type} ({context_score:+.1f})")

    # 2. Data sensitivity
    sensitivity_score, sensitivity_indicators = analyze_data_sensitivity(text)
    semantic_score += sensitivity_score
    if sensitivity_indicators:
        factors.append(f"Data: {', '.join(sensitivity_indicators)} ({sensitivity_score:+.1f})")

    # 3. Business function
    function_score, function_type = analyze_business_function(text)
    semantic_score += function_score
    factors.append(f"Function: {function_type} ({function_score:+.1f})")

    # 4. Integration risk
    integration_score, integration_count = analyze_integration_risk(html)
    semantic_score += integration_score
    factors.append(f"Integrations: {integration_count} ({integration_score:+.1f})")

    return {
        'semantic_score': round(semantic_score, 2),
        'context': context_type,
        'sensitivity_indicators': sensitivity_indicators,
        'function': function_type,
        'factors': factors
    }
```

## Integration with Existing Scoring

```python
# Final criticality calculation
def calculate_final_criticality(domain, title, findings, html):
    # Base scoring (from existing logic)
    base_result = calculate_criticality(domain, title, findings, html)

    # Semantic analysis (new)
    semantic_result = calculate_semantic_criticality(html)

    # Combine
    final_score = base_result['score'] + semantic_result['semantic_score']
    final_score = max(0.1, min(5.0, round(final_score, 2)))

    # Merge factors
    all_factors = base_result['factors'] + semantic_result['factors']

    return {
        'score': final_score,
        'base_score': base_result['score'],
        'semantic_adjustment': semantic_result['semantic_score'],
        'context': semantic_result['context'],
        'factors': all_factors
    }
```

## Advantages of Semantic Analysis

1. **Not Redundant** - Extracts insights Nuclei templates CANNOT provide
2. **Context-Aware** - Understands marketing vs operational purpose
3. **Data-Sensitive** - Detects mentions of PII, financial, health data
4. **Business-Aligned** - Identifies critical business functions
5. **Integration Risk** - Assesses third-party dependencies

## Next Steps

1. Implement text extraction and cleaning
2. Build keyword dictionaries for each category
3. Test on qualys.com dataset
4. Refine scoring weights
5. Combine with base criticality scoring

**Status:** Design Complete
**Implementation:** Python POC first, then Go
**Date:** October 17, 2025
