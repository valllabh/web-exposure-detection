# Web Exposure Detection Research

Consolidated research findings and implementation roadmap.

**Last Updated**: October 21, 2025

## Executive Summary

This document consolidates all research into web exposure detection, criticality scoring, risk quantification, and threat intelligence. After extensive testing of AI/LLM approaches, rule based methods proved superior for production use. Current focus is on explainable scoring that demonstrates customer value.

## Current Implementation Status

### Completed
- **Criticality Scoring**: Data driven implementation using criticality_delta from findings.json, Qualys aligned 1-5 scale
- **Industry Classification API**: OpenRouter integration with llama-3.2-3b-instruct
- **CLI Command**: `classify` command for industry detection
- **Compliance Detection**: HIPAA, PCI DSS, GDPR, SOC 2
- **Report Integration**: Criticality scores displayed in HTML reports with color coded badges

### Ready for Implementation
- **Financial Risk Quantification**: EAL calculation with industry specific breach costs
- **Webapp Classification**: Nuclei template for business function detection
- **Industry Integration in Scan**: Add industry classification to scan workflow, cache results, update findings.json schema

### Future Work
- **STRIDE Risk Framework**: Threat specific intelligence mapping
- **Report Visualization**: Enhanced dashboards and charts

## Criticality Scoring (Stage 3)

### Final Approach: Rule Based

**Decision**: Rule based scoring chosen over AI/LLM after comprehensive testing.

**Rationale**:
- AI/LLM: 0% accuracy, 2000-5000ms latency
- HTTP semantic analysis: 90% false positive rate
- Rule based: 100% accuracy, <10ms latency

### Scoring Algorithm

**Components**:
1. **Domain Patterns**: Exact/substring/regex matching against known critical patterns
2. **Page Titles**: Semantic indicators from HTTP responses
3. **Nuclei Findings**: CVE criticality, template tags, severity

**Score Range**: 0.1 to 5.0

**Categories**:
- **CRITICAL** (3.5-5.0): Production systems, payment, auth, admin
- **HIGH** (2.0-3.5): Customer facing, data processing
- **MEDIUM** (1.0-2.0): Internal tools, corporate sites
- **LOW** (0.1-1.0): Marketing, blogs, documentation

### Domain Pattern Rules

```
CRITICAL (Base 3.5-5.0):
- Exact: api, admin, portal, dashboard, console, secure
- Contains: payment, billing, checkout, account, auth, login
- Regex: prod|production, admin.*panel, customer.*portal

HIGH (Base 2.0-3.5):
- Exact: app, web, service, platform
- Contains: customer, client, user, data, analytics
- Regex: .*app.*|.*service.*

MEDIUM (Base 1.0-2.0):
- Exact: internal, intranet, vpn, dev, staging
- Contains: employee, staff, team

LOW (Base 0.1-1.0):
- Exact: www, blog, news, docs, help, support
- Contains: marketing, corporate, about, info
```

### Page Title Rules

```
CRITICAL (+1.5):
- Admin Panel, Dashboard, Console, Control Panel
- Login, Sign In, Authentication
- Payment, Billing, Checkout

HIGH (+1.0):
- Customer Portal, Client Area
- Application, Platform, Service
- Data Management, Analytics

MEDIUM (+0.5):
- Internal, Employee Portal
- Development, Staging

LOW (+0.0):
- Blog, News, Articles
- Corporate, About, Contact
```

### Nuclei Findings Rules

```
CRITICAL (+2.0):
- CVE with CVSS >= 9.0
- Tags: rce, sqli, auth-bypass, xxe, ssti
- Severity: critical + exploitable

HIGH (+1.5):
- CVE with CVSS 7.0-8.9
- Tags: xss, lfi, ssrf, idor
- Severity: high + known exploit

MEDIUM (+1.0):
- CVE with CVSS 4.0-6.9
- Tags: disclosure, config-error
- Severity: medium

LOW (+0.5):
- CVE with CVSS < 4.0
- Tags: info, detect
- Severity: low, info
```

### Implementation ✅ COMPLETED

**Files**:
- `pkg/webexposure/criticality/criticality.go`: Data driven scoring engine
- `pkg/webexposure/criticality/init.go`: Logger initialization
- `pkg/webexposure/report/report.go`: Integration in report generation
- `pkg/webexposure/findings/criticality_types.go`: Type definitions

**Data Structure** (Implemented):
```go
type Criticality struct {
    Score    int                    // 1-5 (Qualys scale)
    Category string                 // CRITICAL, HIGH, MEDIUM, LOW, MINIMAL
    Factors  []*CriticalityFactor   // Scoring breakdown
}

type CriticalityFactor struct {
    Factor string  // Display name
    Slug   string  // Finding slug
    Delta  float64 // Score contribution
}
```

**Approach**: Data driven via findings.json criticality_delta field instead of hardcoded rules. More flexible and maintainable.

**Performance**: <10ms per domain ✅

## Financial Risk Quantification (Stage 4)

### Expected Annual Loss (EAL)

**Formula**:
```
EAL = Compromise_Probability × Breach_Cost × Asset_Value_Multiplier
```

### Industry Breach Costs (IBM 2024)

| Industry           | Average Breach Cost |
| ------------------ | ------------------- |
| Healthcare         | $10.93M             |
| Financial Services | $5.90M              |
| Technology         | $4.88M              |
| Pharmaceuticals    | $5.01M              |
| Energy             | $5.28M              |
| Retail             | $3.48M              |
| Manufacturing      | $4.73M              |
| Media              | $3.15M              |
| Default            | $4.88M              |

### Compromise Probability

**Calculation**:
```
Base_Probability = 0.001 (0.1% annual)

Multipliers:
- Critical findings: 10x
- High findings: 5x
- Medium findings: 2x
- Low findings: 1.5x
- No findings: 1x

Internet facing: 2x
External attack surface: 1.5x
```

**Example**:
```
Domain: api.example.com
Findings: 2 critical, 5 high
Internet facing: Yes

Probability = 0.001 × 10 × 2 = 0.02 (2%)
Breach Cost = $4.88M (Technology)
EAL = 0.02 × $4,880,000 = $97,600
```

### Asset Value Multiplier

**Based on Business Function**:
```
CRITICAL (5x):
- Payment processing
- Customer data storage
- Authentication services
- Admin panels

HIGH (3x):
- Customer portals
- SaaS dashboards
- API gateways
- E-commerce

MEDIUM (2x):
- Internal tools
- Development environments
- Corporate sites

LOW (1x):
- Marketing sites
- Blogs
- Documentation
```

### Implementation

**CLI Flag**: `--industry <name>`

**Report Output**:
```
Financial Risk Summary
======================
Domain: api.example.com
Industry: Technology
Breach Cost: $4.88M
Compromise Probability: 2.0%
Expected Annual Loss: $97,600

Top Risk Domains:
1. payment.example.com: $450,000
2. api.example.com: $97,600
3. admin.example.com: $85,000
```

## Industry Classification

### OpenRouter Integration

**Model**: `meta-llama/llama-3.2-3b-instruct`

**Input**:
- Domain name
- Page title
- Meta description
- H1 headings
- Body text snippets

**Output**:
```json
{
  "industry": "Healthcare",
  "confidence": "high",
  "reasoning": "Medical terminology, HIPAA compliance references",
  "compliance": ["HIPAA", "GDPR"],
  "keywords": ["patient", "medical", "healthcare"]
}
```

### Industry Categories (15 Types)

1. Healthcare
2. Financial Services
3. Technology
4. Retail
5. Manufacturing
6. Energy
7. Education
8. Government
9. Media
10. Telecommunications
11. Transportation
12. Real Estate
13. Legal
14. Hospitality
15. Other

### CLI Usage

```bash
# Classify single domain
./web-exposure-detection classify example.com

# Classify with scan
./web-exposure-detection scan example.com --classify
```

### Integration Status ✅ CLI COMPLETED

**Completed**:
- OpenRouter API client (`pkg/webexposure/industry/industry_api.go`)
- Industry detection logic
- CLI command (`cmd/web-exposure-detection/classify.go`)
- Structured JSON output
- Type definitions (`pkg/webexposure/industry/industry_types.go`)

**Pending** (Not in scan workflow yet):
- Scan workflow integration (add --classify flag to scan command)
- findings.json schema update (add industry field)
- Report metadata (display industry in reports)
- Caching support (avoid re-classification)

## Webapp Classification

### Business Function Types

**Purpose**: Enhance criticality scoring with business context.

### Type Patterns

**Payment Processing** (Criticality Delta: +2.0)
- Domain: payment, checkout, billing, pay, stripe, paypal
- Title: Payment, Checkout, Billing
- Indicators: Credit card forms, payment gateways
- Tech: Stripe, PayPal, Square APIs

**Admin Panel** (Delta: +1.8)
- Domain: admin, console, control, manage
- Title: Admin Panel, Dashboard, Control
- Indicators: Login required, user management
- Tech: Admin frameworks, CMS backends

**E-commerce** (Delta: +1.3)
- Domain: shop, store, cart, checkout
- Title: Shop, Store, Products
- Indicators: Product listings, shopping cart
- Tech: Shopify, WooCommerce, Magento

**SaaS Dashboard** (Delta: +1.2)
- Domain: app, dashboard, platform
- Title: Dashboard, Application
- Indicators: User accounts, data visualization
- Tech: React, Vue, Angular SPAs

**Customer Portal** (Delta: +1.1)
- Domain: portal, customer, client, my
- Title: Customer Portal, Client Area
- Indicators: Account management, support tickets
- Tech: Customer portals, self-service

**Developer Portal** (Delta: +1.0)
- Domain: developer, api, docs.api
- Title: Developer, API Documentation
- Indicators: API keys, documentation
- Tech: API management, SDK downloads

**Authentication Service** (Delta: +1.5)
- Domain: auth, login, sso, oauth
- Title: Login, Sign In, Authentication
- Indicators: Login forms, OAuth flows
- Tech: Auth0, Okta, Keycloak

**DevOps/CI/CD** (Delta: +0.8)
- Domain: jenkins, gitlab, ci, build
- Title: Jenkins, GitLab, Build
- Indicators: Build pipelines, deployment
- Tech: Jenkins, GitLab CI, GitHub Actions

**Blog/Marketing** (Delta: +0.0)
- Domain: blog, news, www, marketing
- Title: Blog, News, Articles
- Indicators: Blog posts, marketing content
- Tech: WordPress, Medium, Ghost

**Corporate Website** (Delta: +0.0)
- Domain: www, corporate, about
- Title: About, Company, Corporate
- Indicators: Company info, contact forms
- Tech: Static sites, CMS

### Implementation Plan

**Nuclei Template**: `webapp-type-detection.yaml`

```yaml
id: webapp-type-detection
info:
  name: WebApp Type Detection
  severity: info
  tags: webapp,classification

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: or
    matchers:
      - type: word
        part: body
        words:
          - "payment"
          - "checkout"
          - "billing"
        name: payment_processing

      - type: word
        part: body
        words:
          - "admin panel"
          - "dashboard"
          - "control panel"
        name: admin_panel

    extractors:
      - type: kval
        kval:
          - webapp_type
```

**Integration**: Criticality calculator reads webapp type and applies delta.

## STRIDE Risk Framework

### Threat Category Mapping

**Purpose**: Map findings to actionable threat intelligence categories instead of abstract criticality scores.

### STRIDE Categories

**S - Spoofing** (Authentication):
- Findings: Weak auth, default creds, auth bypass
- Impact: Identity theft, unauthorized access
- Mitigations: MFA, strong passwords, OAuth

**T - Tampering** (Data Integrity):
- Findings: SQLi, command injection, insecure uploads
- Impact: Data modification, code injection
- Mitigations: Input validation, parameterized queries

**R - Repudiation** (Accountability):
- Findings: Missing logs, no audit trails
- Impact: Cannot track malicious actions
- Mitigations: Comprehensive logging, SIEM

**I - Information Disclosure** (Confidentiality):
- Findings: Exposed secrets, directory listing, verbose errors
- Impact: Data leaks, credential exposure
- Mitigations: Encryption, access controls, error handling

**D - Denial of Service** (Availability):
- Findings: Rate limiting issues, resource exhaustion
- Impact: Service downtime, business disruption
- Mitigations: Rate limiting, CDN, auto-scaling

**E - Elevation of Privilege** (Authorization):
- Findings: IDOR, privilege escalation, insecure permissions
- Impact: Unauthorized access to admin functions
- Mitigations: RBAC, least privilege, authorization checks

### Nuclei Finding Mapping

**Mapping Rules**:
```yaml
Spoofing:
  - default-credentials
  - weak-authentication
  - auth-bypass
  - session-fixation

Tampering:
  - sql-injection
  - command-injection
  - xxe
  - file-upload

Repudiation:
  - missing-security-headers
  - no-audit-logs
  - insecure-logging

Information Disclosure:
  - exposed-secrets
  - directory-listing
  - verbose-errors
  - sensitive-data-exposure

Denial of Service:
  - rate-limit-bypass
  - resource-exhaustion
  - slowloris

Elevation of Privilege:
  - idor
  - privilege-escalation
  - insecure-permissions
  - path-traversal
```

### Report Output

**STRIDE Summary**:
```
Threat Analysis (STRIDE)
========================

Spoofing (Authentication): 3 findings
- default-login-credentials (CRITICAL)
- weak-password-policy (HIGH)
- missing-mfa (MEDIUM)

Tampering (Data Integrity): 2 findings
- sql-injection (CRITICAL)
- command-injection (HIGH)

Information Disclosure: 5 findings
- exposed-api-keys (CRITICAL)
- directory-listing (MEDIUM)
- verbose-error-messages (LOW)

Recommended Actions:
1. [Spoofing] Implement MFA and rotate credentials
2. [Tampering] Apply input validation and parameterized queries
3. [Information Disclosure] Rotate API keys and disable directory listing
```

### Implementation Timeline

**Week 1-2**: Mapping engine and data structures
**Week 3**: Template tag updates
**Week 4**: Report generation
**Week 5**: Visualization and dashboards

## Product Strategy

### What Resonates with AppSec Leaders

**Key Insight**: Focus on prospect value demonstration with minimal data.

### Value Propositions

**1. Explainable Criticality** (Killer Feature)
- Transparent scoring vs black box AI
- Show WHY each asset scored as critical
- Rule based reasoning customer can trust

**2. Crisp Intelligence**
- Asset inventory: "You have 47 internet facing assets"
- Tech stack: "Running 12 different frameworks"
- CVE mapping: "23 known vulnerabilities affecting your stack"

**3. Tier Based Prioritization**
- CRITICAL: 5 assets (fix immediately)
- HIGH: 12 assets (fix this quarter)
- MEDIUM: 15 assets (monitor)
- LOW: 15 assets (backlog)

**4. Noise Reduction**
- Focus on actionable findings
- Eliminate false positives
- Context aware severity

**5. Business Impact**
- Financial risk quantification
- Industry specific breach costs
- Expected annual loss (EAL)

### Differentiators

**vs Qualys/Tenable**: Explainable scoring, not vulnerability count
**vs SecurityScorecard**: Technical depth, not external reputation
**vs Wiz**: Attack surface focus, not cloud config
**vs AI Tools**: Deterministic rules, not probabilistic models

### Sales Messaging

"Show your prospects their attack surface, tech stack, and prioritized risks in 5 minutes. Our explainable criticality scoring tells them exactly WHY each asset matters, backed by industry specific financial impact."

## Implementation Roadmap

### Q4 2025

**Criticality Scoring** ✅ COMPLETED
- [x] Implement data driven calculator using criticality_delta from findings.json
- [x] Integrate in report generation for all asset types
- [x] Generate criticality scores in reports
- [x] HTML display with color coded badges

**Financial Risk** (Weeks 1-2)
- [ ] Add industry flag to CLI
- [ ] Calculate compromise probability
- [ ] Apply breach cost multipliers
- [ ] Generate EAL calculations
- [ ] Update reports with financial risk

**Industry Integration** (Weeks 3-4)
- [ ] Add --classify flag to scan command (CLI classify already works)
- [ ] Integrate OpenRouter API in scan workflow
- [ ] Cache industry results
- [ ] Update findings.json schema with industry field
- [ ] Add industry to reports

**Webapp Classification** (Weeks 5-6)
- [ ] Create webapp type Nuclei template
- [ ] Implement pattern matching
- [ ] Integrate with criticality scoring via criticality_delta
- [ ] Add to findings.json
- [ ] Update reports

### Q1 2026

**STRIDE Framework** (Weeks 1-5)
- [ ] Build threat category mapping engine
- [ ] Update Nuclei template tags
- [ ] Generate STRIDE reports
- [ ] Add threat visualizations
- [ ] Create actionable recommendations

**Enhanced Reporting** (Weeks 6-8)
- [ ] Redesign HTML report
- [ ] Add interactive charts
- [ ] Include financial risk summaries
- [ ] Add STRIDE threat analysis
- [ ] PDF generation improvements

## Archived Research

### Rejected Approaches

**AI/LLM Criticality Scoring**
- Tested: GPT-4, Claude, Llama 3.1, Phi-3
- Results: 0% accuracy, 2000-5000ms latency
- Reason: Hallucinations, inconsistency, cost
- Location: `archive-rejected/ai-vs-rule-based-criticality.md`

**HTTP Semantic Analysis**
- Approach: Parse HTTP body for criticality signals
- Results: 90% false positive rate
- Reason: Marketing copy misleads, too noisy
- Location: `archive-rejected/semantic-criticality-from-http-response.md`

**Probabilistic Models**
- Approach: Statistical probability of compromise
- Results: Too complex, hard to explain
- Reason: Customers want deterministic scoring
- Location: `archive-rejected/probability-approaches.md`

### Reference Documents

Still available in `docs/research/` for implementation details:
- `rule-based-criticality-scoring.md`: Algorithm specification
- `rule-scoring-test-results.md`: Validation proof
- `jsonl-criticality-scoring-implementation.md`: JSONL processing guide
- `POC-qualys-financial-risk.md`: Real world example
- `test-data-for-rules.json`: Test dataset

## Testing Results

### Criticality Scoring Validation

**Test Domains**: 11 real world examples

**Results**:
- Development/test detection: 100% accuracy
- Production detection: 100% accuracy
- False positives: 0%
- Performance: <10ms per domain

**Test Cases**:
```
CRITICAL (Correct):
- api.stripe.com: 5.0
- admin.shopify.com: 4.8
- portal.salesforce.com: 4.5

HIGH (Correct):
- app.github.com: 3.2
- dashboard.heroku.com: 3.0
- web.whatsapp.com: 2.8

MEDIUM (Correct):
- intranet.company.com: 1.8
- dev.example.com: 1.5

LOW (Correct):
- blog.company.com: 0.5
- www.company.com: 0.3
```

### Financial Risk POC

**Domain**: qualys.com
**Industry**: Technology
**Findings**: 15 total (3 high, 12 medium)

**Calculation**:
```
Base Probability: 0.001
Finding Multiplier: 5x (high findings)
Internet Facing: 2x
Final Probability: 0.01 (1%)

Breach Cost: $4.88M
EAL: 0.01 × $4,880,000 = $48,800
```

**Validation**: Matches industry benchmarks for technology companies.

## Conclusion

Research has evolved from initial exploration to validated implementation designs. Core technical approach is proven: rule based criticality combined with financial risk quantification, enhanced by industry and webapp classification, with future STRIDE threat intelligence.

Latest thinking emphasizes customer value through explainable scoring that demonstrates prospect attack surface and prioritized risks in minutes, not days.

All designs are ready for Go implementation following the roadmap above.

## References

- IBM Cost of Data Breach Report 2024
- Qualys VMDR Documentation
- OWASP Risk Rating Methodology
- NIST Cybersecurity Framework
- Microsoft STRIDE Threat Model
- OpenRouter API Documentation

---

**Document Owner**: TotalAppSec Team
**Review Cycle**: Quarterly
**Next Review**: January 2026
