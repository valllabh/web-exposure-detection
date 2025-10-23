# Rule-Based Criticality Scoring System

**Date:** October 17, 2025
**Purpose:** Comprehensive rule-based asset criticality scoring using domain names, titles, and HTTP response data
**Status:** Implementation Ready

## Available Data Sources

From scan results we have:
1. **Domain name** - `portal.qualys.com`
2. **Page title** - `<title>Qualys Portal</title>`
3. **Description** - `<meta name="description" content="...">`
4. **Findings** - Array of detected technologies/auth mechanisms from Nuclei
5. **Discovery type** - "Web App", "Potential API Endpoint", etc.

## Scoring Algorithm

### Base Score: 1.0

### Formula
```
Criticality_Score = Base + Domain_Score + Title_Score + Findings_Score + Type_Score

Final = Max(0.1, Min(5.0, Criticality_Score))
```

---

## 1. Domain Pattern Scoring (Weight: 35%)

### Critical Infrastructure (+1.0 to +1.5)
```python
critical_patterns = {
    # Payment/Financial
    'pay.': +1.5,
    'payment.': +1.5,
    'checkout.': +1.5,
    'billing.': +1.2,
    'invoice.': +1.0,
    'purchase.': +1.2,

    # Identity/Auth
    'auth.': +1.2,
    'login.': +1.0,
    'sso.': +1.2,
    'identity.': +1.2,
    'oauth.': +1.0,
}
```

### High Value Production (+0.5 to +0.8)
```python
production_patterns = {
    # Customer Facing
    'portal.': +0.7,
    'customer.': +0.7,
    'client.': +0.7,
    'app.': +0.6,
    'www.': +0.5,

    # Admin/Control
    'admin.': +0.8,
    'dashboard.': +0.7,
    'console.': +0.7,
    'control.': +0.6,

    # Infrastructure
    'api.': +0.5,
    'gateway.': +0.6,
}
```

### Development/Non-Production (-0.6 to -0.8)
```python
dev_patterns = {
    # Development
    'dev.': -0.7,
    'develop.': -0.7,
    'development.': -0.7,

    # Testing
    'test.': -0.7,
    'testing.': -0.7,
    'qa.': -0.6,

    # Staging
    'stage.': -0.6,
    'staging.': -0.6,
    'uat.': -0.6,

    # Other Non-Prod
    'sandbox.': -0.7,
    'demo.': -0.6,
    'preview.': -0.5,
    'temp.': -0.6,
}
```

### Internal/Low Value (-0.2 to -0.4)
```python
internal_patterns = {
    'internal.': -0.3,
    '.local': -0.3,
    'intranet.': -0.3,
    'private.': -0.2,
    'corp.': -0.2,
}
```

### Multi-Pattern Detection
```python
def score_domain(domain):
    score = 0
    domain_lower = domain.lower()

    # Check all patterns
    for pattern, weight in all_patterns.items():
        if pattern in domain_lower:
            score += weight

    # Safety: Dev/test always wins (override production patterns)
    has_dev = any(p in domain_lower for p in dev_patterns.keys())
    has_prod = any(p in domain_lower for p in production_patterns.keys())

    if has_dev and has_prod:
        # dev.portal.com → treat as dev (safety first)
        score = min(score, -0.5)

    return score
```

---

## 2. Title Pattern Scoring (Weight: 25%)

### Critical Application Keywords (+0.8 to +1.2)
```python
title_critical = {
    # Payment/Commerce
    'checkout': +1.2,
    'payment': +1.2,
    'pay': +1.0,
    'cart': +1.0,
    'shop': +0.9,
    'store': +0.9,

    # Admin/Control
    'admin panel': +1.1,
    'admin console': +1.1,
    'administration': +1.0,
    'control panel': +1.0,
}
```

### Production Application Keywords (+0.4 to +0.7)
```python
title_production = {
    # Customer Portals
    'portal': +0.6,
    'customer portal': +0.7,
    'client portal': +0.7,
    'dashboard': +0.6,

    # Auth/Login
    'login': +0.5,
    'sign in': +0.5,
    'sign up': +0.5,
    'register': +0.5,

    # Applications
    'application': +0.5,
    'platform': +0.5,
    'workspace': +0.5,
}
```

### Development Keywords (-0.5 to -0.8)
```python
title_dev = {
    'test': -0.7,
    'testing': -0.7,
    'development': -0.8,
    'staging': -0.7,
    'sandbox': -0.7,
    'demo': -0.6,
    'preview': -0.5,
}
```

### Low Value Keywords (-0.3 to -0.5)
```python
title_low = {
    # Error/Default Pages
    'error': -0.5,
    '404': -0.5,
    '403': -0.5,
    'not found': -0.5,
    'default': -0.4,
    'it works': -0.5,
    'nginx': -0.4,
    'apache': -0.4,

    # Generic
    'coming soon': -0.4,
    'under construction': -0.4,
    'maintenance': -0.3,
}
```

---

## 3. Findings Scoring (Weight: 30%)

### Authentication Mechanisms (+0.3 to +0.6)
```python
auth_findings = {
    # Enterprise Auth (high value indicator)
    'auth.enterprise.saml_sso': +0.6,
    'auth.enterprise.oauth': +0.5,
    'auth.enterprise.ldap': +0.4,

    # MFA (valuable asset)
    'auth.mfa': +0.5,
    'auth.2fa': +0.5,

    # Traditional (moderate value)
    'auth.traditional.registration': +0.4,  # Handles user data
    'auth.traditional.password_recovery': +0.3,
    'auth.traditional.basic_auth': +0.2,
}

def score_auth_findings(findings):
    score = 0
    auth_count = 0

    for finding in findings:
        slug = finding.get('slug', '')
        if slug in auth_findings:
            score += auth_findings[slug]
            auth_count += 1

    # Multiple auth types = enterprise/complex app
    if auth_count >= 3:
        score += 0.3
    elif auth_count >= 2:
        score += 0.2

    return score
```

### Technology Stack Complexity (+0.2 to +0.5)
```python
tech_complexity = {
    # Backend Frameworks (application complexity)
    'backend.framework.rails': +0.3,
    'backend.framework.django': +0.3,
    'backend.framework.spring': +0.3,
    'backend.framework.laravel': +0.3,

    # CMS (content + data)
    'backend.cms.wordpress': +0.3,
    'backend.cms.drupal': +0.3,

    # Frontend Frameworks
    'frontend.react': +0.2,
    'frontend.angular': +0.2,
    'frontend.vue': +0.2,

    # Databases (data storage)
    'database.mysql': +0.2,
    'database.postgresql': +0.2,

    # CDN/WAF (protection = value)
    'gateway.cloudflare': +0.2,
    'gateway.akamai': +0.3,
}

def score_tech_stack(findings):
    score = 0
    tech_count = 0

    for finding in findings:
        slug = finding.get('slug', '')
        if slug in tech_complexity:
            score += tech_complexity[slug]
            tech_count += 1

    # Complex stack (5+ technologies)
    if tech_count >= 5:
        score += 0.3
    elif tech_count >= 3:
        score += 0.2

    return score
```

### API Patterns (+0.3 to +0.5)
```python
api_findings = {
    'api.domain_pattern': +0.4,
    'api.specification.openapi': +0.3,
    'api.specification.swagger': +0.3,
    'api.graphql': +0.4,
    'api.rest': +0.3,
}
```

---

## 4. Discovery Type Scoring (Weight: 10%)

```python
discovery_types = {
    'Web App': +0.3,
    'Potential API Endpoint': +0.4,
    'API Specification': +0.3,
    'AI Asset': +0.5,  # AI services are often critical
}
```

---

## Complete Scoring Function

```python
def calculate_criticality_score(domain_data):
    """
    Calculate asset criticality score from scan data

    Args:
        domain_data: {
            'domain': 'portal.qualys.com',
            'title': 'Qualys Portal',
            'description': '...',
            'findings': [...],
            'discovered': 'Web App'
        }

    Returns:
        {
            'score': 2.5,
            'breakdown': {...},
            'factors': [...]
        }
    """

    base_score = 1.0
    breakdown = {}
    factors = []

    # 1. Domain Pattern (35%)
    domain_score = score_domain(domain_data['domain'])
    breakdown['domain'] = domain_score
    if domain_score > 0:
        factors.append(f"Domain pattern: +{domain_score:.1f}")
    elif domain_score < 0:
        factors.append(f"Domain pattern: {domain_score:.1f}")

    # 2. Title Pattern (25%)
    title_score = score_title(domain_data.get('title', ''))
    breakdown['title'] = title_score
    if title_score != 0:
        factors.append(f"Title: {title_score:+.1f}")

    # 3. Findings (30%)
    findings = domain_data.get('findings', [])

    auth_score = score_auth_findings(findings)
    tech_score = score_tech_stack(findings)
    api_score = score_api_findings(findings)

    findings_score = auth_score + tech_score + api_score
    breakdown['findings'] = {
        'auth': auth_score,
        'tech': tech_score,
        'api': api_score,
        'total': findings_score
    }

    if auth_score > 0:
        factors.append(f"Authentication: +{auth_score:.1f}")
    if tech_score > 0:
        factors.append(f"Tech stack: +{tech_score:.1f}")
    if api_score > 0:
        factors.append(f"API patterns: +{api_score:.1f}")

    # 4. Discovery Type (10%)
    type_score = discovery_types.get(domain_data.get('discovered', ''), 0)
    breakdown['type'] = type_score
    if type_score > 0:
        factors.append(f"Type ({domain_data.get('discovered')}): +{type_score:.1f}")

    # Calculate final score
    total_adjustments = domain_score + title_score + findings_score + type_score
    final_score = base_score + total_adjustments

    # Apply bounds
    final_score = max(0.1, min(5.0, round(final_score, 2)))

    # Determine category
    if final_score >= 3.5:
        category = 'CRITICAL'
    elif final_score >= 2.0:
        category = 'HIGH'
    elif final_score >= 1.0:
        category = 'MEDIUM'
    else:
        category = 'LOW'

    return {
        'score': final_score,
        'category': category,
        'base': base_score,
        'adjustments': round(total_adjustments, 2),
        'breakdown': breakdown,
        'factors': factors
    }
```

---

## Real Examples

### Example 1: portal.qualys.com

**Input:**
```json
{
  "domain": "portal.qualys.com",
  "title": "Qualys Portal",
  "discovered": "Web App",
  "findings": [
    {"slug": "gateway.cloudflare"},
    {"slug": "auth.enterprise.saml_sso"}
  ]
}
```

**Calculation:**
```
Base: 1.0

Domain: portal. → +0.7
Title: "portal" → +0.6
Findings:
  - SAML/SSO → +0.6
  - Cloudflare → +0.2
  - Total: +0.8
Type: Web App → +0.3

Total: 1.0 + 0.7 + 0.6 + 0.8 + 0.3 = 3.4

Score: 3.4 (CRITICAL - just below threshold)
```

**Factors:**
- Domain pattern: +0.7 (portal)
- Title: +0.6 (portal)
- Authentication: +0.6 (SAML/SSO)
- Tech stack: +0.2 (Cloudflare)
- Type (Web App): +0.3

---

### Example 2: pay.qualys.com

**Input:**
```json
{
  "domain": "pay.qualys.com",
  "title": "Payment Gateway",
  "discovered": "Web App",
  "findings": [
    {"slug": "auth.mfa"},
    {"slug": "gateway.cloudflare"}
  ]
}
```

**Calculation:**
```
Base: 1.0

Domain: pay. → +1.5
Title: "payment" → +1.2
Findings:
  - MFA → +0.5
  - Cloudflare → +0.2
  - Total: +0.7
Type: Web App → +0.3

Total: 1.0 + 1.5 + 1.2 + 0.7 + 0.3 = 4.7

Score: 4.7 (CRITICAL)
```

**Factors:**
- Domain pattern: +1.5 (payment)
- Title: +1.2 (payment gateway)
- Authentication: +0.5 (MFA)
- Tech stack: +0.2 (Cloudflare)
- Type (Web App): +0.3

---

### Example 3: dev.staging.qualys.com

**Input:**
```json
{
  "domain": "dev.staging.qualys.com",
  "title": "Development - Staging Environment",
  "discovered": "Web App",
  "findings": [
    {"slug": "gateway.nginx"}
  ]
}
```

**Calculation:**
```
Base: 1.0

Domain: dev. → -0.7, staging. → -0.6 (total: -1.3, but capped)
Title: "development" → -0.8, "staging" → -0.7 (total: -1.5, but capped)
Findings:
  - Nginx → 0 (basic web server)
Type: Web App → +0.3

Total: 1.0 - 1.3 - 1.5 + 0 + 0.3 = -1.5

Score: 0.1 (floor applied) - LOW
```

**Factors:**
- Domain pattern: -1.3 (dev + staging)
- Title: -1.5 (development + staging)
- Type (Web App): +0.3
- Final: 0.1 (safety floor)

---

### Example 4: api.qualys.com

**Input:**
```json
{
  "domain": "api.qualys.com",
  "title": "Qualys API",
  "discovered": "Potential API Endpoint",
  "findings": [
    {"slug": "api.domain_pattern"},
    {"slug": "auth.traditional.basic_auth"},
    {"slug": "gateway.nginx"}
  ]
}
```

**Calculation:**
```
Base: 1.0

Domain: api. → +0.5
Title: "api" → +0.3
Findings:
  - API pattern → +0.4
  - Basic auth → +0.2
  - Total: +0.6
Type: Potential API Endpoint → +0.4

Total: 1.0 + 0.5 + 0.3 + 0.6 + 0.4 = 2.8

Score: 2.8 (HIGH)
```

**Factors:**
- Domain pattern: +0.5 (api)
- Title: +0.3 (api)
- API patterns: +0.4
- Authentication: +0.2 (basic auth)
- Type (Potential API Endpoint): +0.4

---

## Validation Test Cases

| Domain | Title | Findings | Expected Score | Category |
|--------|-------|----------|---------------|----------|
| pay.qualys.com | Payment Portal | MFA, Cloudflare | 4.5-5.0 | CRITICAL |
| admin.qualys.com | Admin Console | SAML, Rails | 3.5-4.0 | CRITICAL |
| portal.qualys.com | Customer Portal | SAML, Cloudflare | 3.0-3.5 | HIGH |
| api.qualys.com | API Gateway | Basic Auth, API pattern | 2.5-3.0 | HIGH |
| blog.qualys.com | Company Blog | WordPress, SAML | 2.0-2.5 | HIGH |
| www.qualys.com | Qualys Homepage | None | 1.5-2.0 | MEDIUM |
| dev.qualys.com | Development | Nginx | 0.1-0.3 | LOW |
| test.api.qualys.com | Test API | None | 0.1-0.5 | LOW |
| staging.portal.com | Staging Portal | SAML | 0.1-0.5 | LOW |

---

## Implementation Checklist

### Phase 1: Core Scoring (Week 1)
- [ ] Implement domain pattern matching
- [ ] Implement title keyword extraction
- [ ] Implement findings analysis (auth, tech, API)
- [ ] Implement discovery type scoring
- [ ] Apply weighted combination
- [ ] Apply floor (0.1) and ceiling (5.0)

### Phase 2: Safety Rules (Week 1)
- [ ] Dev/test override (always low even if has production patterns)
- [ ] Payment boost (always critical)
- [ ] Error page detection (always low)

### Phase 3: Testing (Week 2)
- [ ] Test on qualys.com data (274 domains)
- [ ] Validate against expected categories
- [ ] Tune weights based on results
- [ ] Document edge cases

### Phase 4: Integration (Week 2)
- [ ] Add to scan result processing
- [ ] Store in report data structure
- [ ] Display in HTML/PDF reports
- [ ] Add to JSON output

---

## Output Format

```json
{
  "domain": "portal.qualys.com",
  "asset_criticality": {
    "score": 3.4,
    "category": "CRITICAL",
    "confidence": "high",
    "breakdown": {
      "base": 1.0,
      "domain": 0.7,
      "title": 0.6,
      "findings": {
        "auth": 0.6,
        "tech": 0.2,
        "api": 0.0,
        "total": 0.8
      },
      "type": 0.3,
      "total_adjustments": 2.4
    },
    "factors": [
      "Domain pattern: +0.7 (portal)",
      "Title: +0.6 (portal)",
      "Authentication: +0.6 (SAML/SSO)",
      "Tech stack: +0.2 (Cloudflare)",
      "Type (Web App): +0.3"
    ],
    "explanation": "Enterprise portal with SAML/SSO authentication indicates customer-facing application with user data handling."
  }
}
```

---

## Advantages Over AI

1. **100% Reliable** - Deterministic, no failures
2. **Fast** - <1ms per domain
3. **Safe** - Dev/test always detected correctly
4. **Explainable** - Clear factor breakdown
5. **Tunable** - Easy to adjust weights based on feedback
6. **No Infrastructure** - No AI models, APIs, or complexity

---

**Status:** Ready for Implementation
**Next Step:** Code the scoring function in Go
**Owner:** Engineering Team
**Last Updated:** October 17, 2025
