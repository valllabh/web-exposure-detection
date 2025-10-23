# Domain Compromise Prediction Model

**Date:** October 16, 2025
**Status:** Research - Design Phase
**Purpose:** Design a predictive model to assess the probability of domain compromise based on aggregated findings

## Executive Summary

This document extends the technology-level exploitability scoring to **domain-level compromise prediction**. While individual vulnerability scores answer "how exploitable is WordPress?", this model answers "what's the probability THIS DOMAIN gets compromised given ALL its findings?"

**Key Innovation:** Move from individual technology risk assessment to holistic domain-level breach prediction by modeling attack surfaces, attack chains, environmental factors, and aggregated vulnerability exposure.

## Problem Statement

### Current State

**Per-Technology Data (from findings.json):**
- CVE/KEV/CWE statistics (e.g., Rails has 50 total CVEs, 2 KEV)
- Weakness categories (e.g., React has CWE-79 XSS)
- Exploitability scores (from exploitability-scoring.md)

**Per-Domain Data (from Nuclei scans):**
- Detected technologies used (Nginx, Rails, Cloudflare, SAML/SSO)
- Finding patterns (registration forms, API endpoints, auth mechanisms)
- Page characteristics (titles, response types)
- Domain count (how many domains use each technology)

**Critical Constraint:** We do NOT have domain-specific CVE lists. We only know:
1. Which technologies a domain uses
2. The inherent CVE/KEV risk of each technology (from findings.json)
3. What Nuclei findings were detected

**Gap:** We don't predict the overall compromise likelihood for the ENTIRE DOMAIN considering:
- Aggregated risk from ALL detected technologies
- Finding patterns indicating attack surface
- Technology combinations and exposure breadth
- Attacker economics and effort required

**Goal:** Predict domain compromise probability (0-100%) using:
- Technology stack risk aggregation
- Finding pattern analysis (auth mechanisms, exposed endpoints)
- Attack surface modeling
- Timeline predictions (likely to be compromised in 30/90/365 days)

## Domain vs Technology Risk

### Technology-Level Exploitability Score (Current)
**Scope:** Individual software component
**Question:** "How exploitable is WordPress 5.8?"
**Inputs:** CVEs, KEV status, EPSS scores, CWEs for that technology
**Output:** Exploitability score (0-100)
**Use Case:** Patch prioritization for specific software

### Domain-Level Compromise Prediction (This Model)
**Scope:** Entire domain and all detected findings
**Question:** "What's the probability example.com gets breached?"
**Inputs:** ALL findings across ALL technologies + environment + attack surface
**Output:** Compromise probability (0-100%) + timeline + attack path analysis
**Use Case:** Portfolio risk management, executive reporting, insurance assessments

## Compromise Prediction Factors

### 1. Aggregated Technology Risk (40% weight)

Combines exploitability scores from ALL detected technologies for the domain.

**Data Source:**
- Domain's Nuclei findings list technologies detected (e.g., `gateway.nginx`, `backend.framework.rails`)
- Each technology's CVE/KEV/CWE stats from findings.json
- Technology exploitability scores (from exploitability-scoring.md)

**Formula:**
```
Technology_Risk = weighted_average(exploitability_scores)

Weights by classification:
- Backend frameworks (Rails, Django, Laravel): 3.5 (primary attack target)
- Web servers (Nginx, Apache, Envoy): 2.5 (infrastructure layer)
- CDN/Proxies (Cloudflare): 1.5 (external, managed)
- Frontend frameworks (React, Angular, Vue): 2.0 (client-side, moderate)
- Auth systems (SAML/SSO, OAuth): 3.0 (credential access)

Technology_Risk_Score = Σ(tech_exploitability_i × weight_i) / Σ(weight_i)

Where tech_exploitability_i comes from:
  Phase 1: Technology CVE/KEV-based scoring
  Phase 2: EPSS-enhanced technology scoring
```

**Example:**
```
Domain: portal.qualys.com
Technologies detected:
  - gateway.cloudflare (exploitability: 12/100, weight: 1.5)
  - gateway.nginx (exploitability: 18/100, weight: 2.5)
  - backend.framework.rails (exploitability: 42/100, weight: 3.5)
  - auth.enterprise.saml_sso (exploitability: 28/100, weight: 3.0)

Technology_Risk = (12×1.5 + 18×2.5 + 42×3.5 + 28×3.0) / (1.5+2.5+3.5+3.0)
                = (18 + 45 + 147 + 84) / 10.5
                = 294 / 10.5
                = 28.0/100 = 0.28
```

**Rationale:** Not all technologies have equal compromise potential. Backend frameworks are exploited more frequently than CDN services.

### 2. Attack Surface Breadth (20% weight)

More exposed functionality = more attack vectors = higher compromise probability.

**Data Source:**
- Count of detected technologies (more tech = larger surface)
- Count of detected findings (each finding = potential attack vector)
- Finding types indicating exposure:
  - `auth.traditional.registration` (user signup)
  - `auth.traditional.password_recovery` (password reset)
  - `auth.traditional.basic_auth` (login forms)
  - `api.server.*` (API endpoints)
  - `api.domain_pattern` (API naming patterns)

**Formula:**
```
Surface_Score = min(100,
  (tech_count × 4) +                     // More tech = more complexity
  (total_findings_count × 2) +           // Each finding = potential vector
  (has_registration × 15) +              // User input channels
  (has_password_recovery × 12) +         // Password flows
  (has_login_form × 10) +                // Auth endpoints
  (api_indicator_count × 8) +            // API exposure
  (has_mfa × -10)                        // MFA reduces surface risk
)

Normalized: Surface_Score / 100
```

**Example:**
```
Domain: portal.qualys.com
Findings:
  - Technologies: 4 (Cloudflare, Nginx, Rails, SAML/SSO)
  - Total findings: 7
  - auth.traditional.registration: YES
  - auth.traditional.password_recovery: YES
  - auth.traditional.basic_auth: YES
  - auth.mfa: YES
  - auth.enterprise.saml_sso: YES
  - api indicators: 0

Surface_Score = (4×4) + (7×2) + (1×15) + (1×12) + (1×10) + (0×8) + (1×-10)
              = 16 + 14 + 15 + 12 + 10 + 0 - 10
              = 57/100 = 0.57
```

**Rationale:** Attackers need only ONE way in. More auth mechanisms and endpoints = more opportunities. MFA reduces effective attack surface.

### 3. Attack Chain Potential (25% weight)

Technology and finding combinations create attack chains beyond individual risks.

**Data Source:**
- Detected technology combinations
- Finding patterns that enable multi-step attacks
- CWE categories from technology metadata

**High-Risk Patterns:**

| Pattern | Indicators | Risk Score | Rationale |
|---------|-----------|------------|-----------|
| **High-CVE Backend + Auth Forms** | Rails/Django with CVEs + login/registration | 70 | Direct exploitation path to authenticated context |
| **API Exposure + Framework Weaknesses** | API indicators + backend with injection CWEs | 65 | API endpoints often less hardened |
| **Legacy Auth + Modern Stack** | Basic auth + contemporary framework | 55 | Auth gap in modern app |
| **Multiple Auth Mechanisms** | 3+ auth types (basic, SAML, OAuth, registration) | 60 | Complexity increases attack surface |
| **Enterprise SSO Only** | SAML/SSO with MFA, no basic auth | 25 | Centralized, hardened auth |

**Detection Rules:**
```
Chain_Score = max(pattern_scores) where pattern matches findings

Pattern matching:
1. High-CVE Backend + Auth Forms:
   - Technology with total_cves > 30 AND classification="webapp"
   - auth.traditional.* findings present
   - Score: 70

2. API Exposure + Injection-prone Tech:
   - api.* findings present
   - Technology with CWE-89 (SQLi) or CWE-78 (Command Injection) in top categories
   - Score: 65

3. Legacy Auth Pattern:
   - auth.traditional.basic_auth present
   - Backend framework detected (modern)
   - NO auth.enterprise.* or auth.mfa
   - Score: 55

4. Auth Complexity:
   - Count distinct auth.* finding types
   - If >= 3: Score: 60
   - If >= 5: Score: 75

5. Hardened SSO:
   - auth.enterprise.saml_sso present
   - auth.mfa present
   - NO auth.traditional.* (except password recovery)
   - Score: 25 (reduces risk)

Normalized: max(pattern_scores) / 100
```

**Example:**
```
Domain: portal.qualys.com
Technologies:
  - backend.framework.rails (total_cves: 156, KEV: 2)
Findings:
  - auth.enterprise.saml_sso
  - auth.mfa
  - auth.traditional.password_recovery
  - auth.traditional.registration
  - auth.traditional.basic_auth

Pattern matches:
  1. High-CVE Backend + Auth Forms: MATCH (Rails has 156 CVEs + has registration/basic auth) → 70
  2. Auth Complexity: 4 auth types → 60
  3. Hardened SSO: NO MATCH (has basic_auth)

Chain_Score = max(70, 60) = 70/100 = 0.70
```

**Rationale:** Technology combinations and finding patterns reveal attack paths that individual scores miss.

### 4. Environmental Risk Factors (10% weight)

Deployment characteristics and technology choices that affect exploitability.

**Data Source:**
- Page title patterns (error pages, default pages)
- Technology choices (managed CDN vs self-hosted)
- Auth mechanism sophistication

**Risk Indicators:**

| Indicator | Detection | Score | Rationale |
|-----------|-----------|-------|-----------|
| **Error Pages Exposed** | title: "404 Not Found", "502 Bad Gateway", "403 Forbidden" | +15 | Information leakage about tech stack |
| **Default Pages** | title: "Welcome to nginx", "Apache2 Default Page" | +20 | Unconfigured/unfinished deployment |
| **Self-hosted Infrastructure** | Nginx/Apache WITHOUT Cloudflare/CDN | +12 | No WAF, DDoS protection |
| **No CDN/WAF** | Missing gateway.cloudflare or similar | +15 | No protective layer |
| **Legacy Auth Only** | auth.traditional.* without auth.enterprise.* or auth.mfa | +18 | Weaker authentication |
| **Modern Auth Stack** | auth.enterprise.saml_sso + auth.mfa | -15 | Hardened authentication (reduces risk) |
| **API Exposure** | api.* findings present | +10 | Often less protected than UI |

**Formula:**
```
Env_Risk = min(100, Σ(risk_indicators))

Calculation:
1. Check page title for error/default patterns
2. Check for CDN/WAF presence (Cloudflare, etc.)
3. Evaluate auth mechanism sophistication
4. Check for API exposure
5. Sum scores, cap at 100

Normalized: Env_Risk / 100
```

**Example:**
```
Domain: portal.qualys.com
Analysis:
  - Title: "Qualys Portal" (not error page) → 0
  - Has gateway.cloudflare → CDN present, no penalty
  - Has auth.enterprise.saml_sso + auth.mfa → -15 (bonus)
  - Has auth.traditional.* also → +18 (mixed auth)
  - No API indicators → 0

Env_Risk = 0 + 0 + (-15) + 18 + 0 = 3
Normalized: 3/100 = 0.03

vs

Domain: kube.qg3.apps.qualys.it
Analysis:
  - Title: "404 Not Found" → +15
  - Has gateway.nginx, no CDN → +15
  - No auth findings detected → 0
  - No API indicators → 0

Env_Risk = 15 + 15 + 0 + 0 = 30
Normalized: 30/100 = 0.30
```

**Rationale:** Deployment choices (CDN, auth mechanisms, exposed errors) are "force multipliers" that affect exploitability regardless of CVEs.

### 5. Temporal Risk Factors (5% weight)

Technology maturity and KEV presence indicating exploitation likelihood.

**Data Source:**
- KEV counts from technology metadata (findings.json)
- CVE severity distribution per technology

**Factors:**

| Factor | Data Source | Score | Rationale |
|--------|-------------|-------|-----------|
| **High KEV Count** | Any technology with KEV > 0 | KEV_count × 20 | Proven real-world exploitation |
| **Critical CVE Present** | Any technology with critical > 0 | 15 per tech | High severity = targeted |
| **High CVE Load** | Technology with total_cves > 50 | 20 | Large attack surface |

**Formula:**
```
Temporal_Risk = min(100,
  Σ(tech_kev_count × 20) +           // Known exploitation
  (tech_with_critical_count × 15) +  // High severity presence
  (tech_with_high_cve_load × 20)     // Large vulnerability surface
)

Normalized: Temporal_Risk / 100

Where:
  tech_kev_count = number of technologies with KEV > 0
  tech_with_critical_count = number of technologies with critical_cves > 0
  tech_with_high_cve_load = number of technologies with total_cves > 50
```

**Example:**
```
Domain: portal.qualys.com
Technologies:
  - gateway.cloudflare: total=0, critical=0, KEV=0
  - gateway.nginx: total=0, critical=0, KEV=0
  - backend.framework.rails: total=156, critical=8, KEV=2
  - auth.enterprise.saml_sso: total=0, critical=0, KEV=0

Analysis:
  - Technologies with KEV > 0: 1 (Rails) → 1 × 20 = 20
  - Technologies with critical > 0: 1 (Rails) → 1 × 15 = 15
  - Technologies with total > 50: 1 (Rails) → 1 × 20 = 20

Temporal_Risk = 20 + 15 + 20 = 55
Normalized: 55/100 = 0.55
```

**Rationale:** KEV presence proves real-world exploitation. High CVE counts indicate larger attack surface.

## Composite Compromise Prediction Score

### Formula

```
Compromise_Probability = (
  (Technology_Risk × 0.40) +
  (Attack_Surface × 0.20) +
  (Attack_Chain_Potential × 0.25) +
  (Environmental_Risk × 0.10) +
  (Temporal_Risk × 0.05)
) × 100

Output: 0-100 scale
```

### Categorization

| Score | Category | Meaning | Recommended Action |
|-------|----------|---------|-------------------|
| 0-15 | **Minimal** | Low-value target, hardened, or static | Monitor quarterly |
| 16-30 | **Low** | Some exposure, but limited attack paths | Review bi-monthly |
| 31-50 | **Moderate** | Exploitable findings present, defendable | Remediate within 30 days |
| 51-70 | **High** | Multiple attack paths, likely targeted | Remediate within 7 days |
| 71-85 | **Critical** | Imminent compromise risk | Remediate within 24 hours |
| 86-100 | **Severe** | Active exploitation likely underway | Immediate response |

### Timeline Predictions

Based on score, estimate time-to-compromise:

```
Expected_Time_to_Compromise_Days =
  if score >= 85: "0-7 days (active targeting likely)"
  if score >= 70: "7-30 days (opportunistic scanning)"
  if score >= 50: "30-90 days (automated exploitation)"
  if score >= 30: "90-180 days (targeted campaigns)"
  else: "180+ days (low priority target)"
```

## Example Calculations

### Example 1: Simple API Endpoint

**Profile:**
```
Domain: nac-le-service.qg1.apps.qualys.ae
Nuclei findings:
  - gateway.nginx
  - api.domain_pattern
  - page.title: "HTTP Status 404 – Not Found"

Technology metadata (from findings.json):
  - gateway.nginx: total_cves=0, critical=0, KEV=0, exploitability=12/100
```

**Calculation:**
```
1. Technology_Risk:
   - gateway.nginx: exploitability 12/100, weight 2.5
   - Weighted: (12×2.5) / 2.5 = 12/100 = 0.12

2. Attack_Surface:
   - Tech count: 1 → 1×4 = 4
   - Total findings: 3 → 3×2 = 6
   - Has registration: NO → 0
   - Has password recovery: NO → 0
   - Has login: NO → 0
   - API indicators: 1 → 1×8 = 8
   - Has MFA: NO → 0
   - Surface = (4+6+0+0+0+8+0) = 18/100 = 0.18

3. Attack_Chain_Potential:
   - API Exposure + Injection-prone: NO (Nginx has no injection CWEs)
   - High-CVE Backend + Auth: NO (no auth findings)
   - Score: 0.0

4. Environmental_Risk:
   - Error page (404): +15
   - No CDN (only Nginx): +15
   - Legacy auth only: NO → 0
   - API exposure: +10
   - Env_Risk = (15+15+10) = 40/100 = 0.40

5. Temporal_Risk:
   - Tech with KEV: 0 → 0
   - Tech with critical: 0 → 0
   - Tech with high CVE load (>50): 0 → 0
   - Temporal_Risk = 0/100 = 0.0

Compromise_Probability = (0.12×0.40 + 0.18×0.20 + 0×0.25 + 0.40×0.10 + 0×0.05) × 100
                       = (0.048 + 0.036 + 0 + 0.04 + 0) × 100
                       = 12.4

Score: 12/100 (Minimal Risk)
Timeline: 180+ days
Category: Low-value API endpoint, minimal exposure
```

### Example 2: Enterprise Portal with Auth

**Profile:**
```
Domain: portal.qg3.apps.qualys.com
Nuclei findings:
  - gateway.cloudflare
  - gateway.nginx
  - backend.framework.rails
  - auth.enterprise.saml_sso
  - auth.mfa
  - auth.traditional.basic_auth
  - auth.traditional.password_recovery
  - auth.traditional.registration
  - page.title: "Qualys Portal"

Technology metadata (from findings.json):
  - gateway.cloudflare: total_cves=0, critical=0, KEV=0, exploitability=8/100
  - gateway.nginx: total_cves=0, critical=0, KEV=0, exploitability=12/100
  - backend.framework.rails: total_cves=156, critical=8, KEV=2, exploitability=45/100
  - auth.enterprise.saml_sso: total_cves=12, critical=0, KEV=0, exploitability=18/100
```

**Calculation:**
```
1. Technology_Risk:
   - Cloudflare: 8/100, weight 1.5 → 12
   - Nginx: 12/100, weight 2.5 → 30
   - Rails: 45/100, weight 3.5 → 157.5
   - SAML/SSO: 18/100, weight 3.0 → 54
   - Weighted: (12+30+157.5+54) / 10.5 = 253.5/10.5 = 24.1/100 = 0.241

2. Attack_Surface:
   - Tech count: 4 → 4×4 = 16
   - Total findings: 9 → 9×2 = 18
   - Has registration: YES → 15
   - Has password recovery: YES → 12
   - Has login (basic_auth): YES → 10
   - API indicators: 0 → 0
   - Has MFA: YES → -10
   - Surface = (16+18+15+12+10+0-10) = 61/100 = 0.61

3. Attack_Chain_Potential:
   - High-CVE Backend + Auth Forms: MATCH (Rails 156 CVEs + registration/basic_auth) → 70
   - Auth Complexity: 4 auth types (saml_sso, mfa, basic_auth, registration) → 60
   - Hardened SSO: NO (has basic_auth alongside SSO)
   - Chain_Score = max(70, 60) = 70/100 = 0.70

4. Environmental_Risk:
   - Error page: NO → 0
   - Has CDN (Cloudflare): No penalty → 0
   - Modern auth stack: YES (saml_sso + mfa) → -15
   - Legacy auth also present: YES → +18
   - API exposure: NO → 0
   - Env_Risk = (0+0-15+18+0) = 3/100 = 0.03

5. Temporal_Risk:
   - Tech with KEV > 0: 1 (Rails) → 1×20 = 20
   - Tech with critical > 0: 1 (Rails) → 1×15 = 15
   - Tech with high CVE load (>50): 1 (Rails) → 1×20 = 20
   - Temporal_Risk = (20+15+20) = 55/100 = 0.55

Compromise_Probability = (0.241×0.40 + 0.61×0.20 + 0.70×0.25 + 0.03×0.10 + 0.55×0.05) × 100
                       = (0.0964 + 0.122 + 0.175 + 0.003 + 0.0275) × 100
                       = 42.4

Score: 42/100 (Moderate Risk)
Timeline: 30-90 days
Category: Moderate - Rails with KEV but hardened with SSO+MFA
Action: Remediate within 30 days, prioritize Rails update
```

### Example 3: Unprotected Legacy Application

**Profile:**
```
Domain: legacy-app.qualys.internal
Nuclei findings:
  - gateway.nginx
  - backend.cms.wordpress
  - backend.language.php
  - auth.traditional.basic_auth
  - auth.traditional.registration
  - page.title: "WordPress Admin"

Technology metadata (from findings.json):
  - gateway.nginx: total_cves=0, critical=0, KEV=0, exploitability=12/100
  - backend.cms.wordpress: total_cves=658, critical=25, KEV=8, exploitability=68/100
  - backend.language.php: total_cves=892, critical=42, KEV=12, exploitability=58/100
```

**Calculation:**
```
1. Technology_Risk:
   - Nginx: 12/100, weight 2.5 → 30
   - WordPress: 68/100, weight 3.5 → 238
   - PHP: 58/100, weight 3.5 → 203
   - Weighted: (30+238+203) / 9.5 = 471/9.5 = 49.6/100 = 0.496

2. Attack_Surface:
   - Tech count: 3 → 3×4 = 12
   - Total findings: 6 → 6×2 = 12
   - Has registration: YES → 15
   - Has password recovery: NO → 0
   - Has login (basic_auth): YES → 10
   - API indicators: 0 → 0
   - Has MFA: NO → 0
   - Surface = (12+12+15+0+10+0+0) = 49/100 = 0.49

3. Attack_Chain_Potential:
   - High-CVE Backend + Auth Forms: MATCH (WordPress 658 CVEs + registration/basic_auth) → 70
   - API Exposure + Injection: NO
   - Legacy Auth Pattern: MATCH (basic_auth + no MFA) → 55
   - Auth Complexity: 2 types → 0 (below threshold)
   - Chain_Score = max(70, 55) = 70/100 = 0.70

4. Environmental_Risk:
   - Error page: NO (WordPress Admin page) → 0
   - No CDN (only Nginx): +15
   - Modern auth stack: NO → 0
   - Legacy auth only: YES → +18
   - API exposure: NO → 0
   - Env_Risk = (0+15+0+18+0) = 33/100 = 0.33

5. Temporal_Risk:
   - Tech with KEV > 0: 2 (WordPress, PHP) → 2×20 = 40
   - Tech with critical > 0: 2 (WordPress, PHP) → 2×15 = 30
   - Tech with high CVE load (>50): 3 (all) → 3×20 = 60
   - Temporal_Risk = min(100, 40+30+60) = 100/100 = 1.0

Compromise_Probability = (0.496×0.40 + 0.49×0.20 + 0.70×0.25 + 0.33×0.10 + 1.0×0.05) × 100
                       = (0.1984 + 0.098 + 0.175 + 0.033 + 0.05) × 100
                       = 55.4

Score: 55/100 (High Risk)
Timeline: 30-90 days
Category: High - Multiple technologies with KEV, no MFA, legacy auth
Action: URGENT - Remediate within 7 days
Recommendation: Update WordPress & PHP immediately, implement MFA, add WAF
```

## Attack Path Visualization

For high-risk domains, identify and visualize the most likely attack path:

```
Domain: vulnerable-site.com
Compromise Probability: 68/100 (High Risk)

Most Likely Attack Path:
┌─────────────────────────────────────────────────────┐
│ Step 1: Reconnaissance                              │
│ ├─ Directory listing reveals /wp-content structure  │
│ ├─ .git exposure leaks source code                  │
│ └─ wp-admin panel discovered                        │
├─────────────────────────────────────────────────────┤
│ Step 2: Credential Access                           │
│ ├─ .git history contains database credentials       │
│ └─ XML-RPC enables password brute force             │
├─────────────────────────────────────────────────────┤
│ Step 3: Initial Access                              │
│ ├─ WordPress 5.8 has 2 KEV vulnerabilities          │
│ ├─ Unauthenticated RCE via plugin (CVE-2024-1234)  │
│ └─ Alternative: Brute force wp-admin                │
├─────────────────────────────────────────────────────┤
│ Step 4: Persistence                                 │
│ ├─ Upload malicious plugin via admin access         │
│ └─ Create admin user backdoor                       │
└─────────────────────────────────────────────────────┘

Estimated Attacker Effort: Low (automated tools available)
Estimated Time to Exploit: 2-8 hours
```

## Implementation Requirements

### Data Collection
From existing findings:
- Technology exploitability scores (from exploitability-scoring.md model)
- All detected findings with severity
- CVE/KEV/CWE data per technology
- Exposed endpoints and services
- Security headers status
- Subdomain enumeration results

New data needed:
- Attack chain detection rules (pattern matching)
- Environmental risk scoring rules
- Technology weight mappings
- Timeline prediction models

### Schema Extension

```json
{
  "domain": "example.com",
  "scan_date": "2025-10-16T12:00:00Z",
  "compromise_prediction": {
    "score": 68.28,
    "category": "High Risk",
    "confidence": 0.85,
    "timeline": {
      "expected_compromise_window": "7-30 days",
      "confidence_interval": "90%"
    },
    "components": {
      "technology_risk": {
        "score": 51.85,
        "weight": 0.40,
        "contribution": 20.74
      },
      "attack_surface": {
        "score": 44.0,
        "weight": 0.20,
        "contribution": 8.8
      },
      "attack_chains": {
        "score": 100.0,
        "weight": 0.25,
        "contribution": 25.0,
        "detected_chains": [
          {
            "type": "info_disclosure_to_credential_access",
            "severity": "Critical",
            "path": [".git exposure", "source code disclosure", "hardcoded credentials"],
            "multiplier": 2.5
          }
        ]
      },
      "environmental_risk": {
        "score": 100.0,
        "weight": 0.10,
        "contribution": 10.0,
        "factors": [
          {"type": "exposed_admin", "score": 30},
          {"type": "git_exposure", "score": 35},
          {"type": "directory_listing", "score": 15},
          {"type": "missing_headers", "score": 24}
        ]
      },
      "temporal_risk": {
        "score": 74.7,
        "weight": 0.05,
        "contribution": 3.74,
        "factors": [
          {"type": "kev_age_days", "value": 180, "score": 19.7},
          {"type": "eol_technologies", "count": 2, "score": 40},
          {"type": "days_since_update", "value": 90, "score": 15}
        ]
      }
    },
    "attack_path": {
      "most_likely": [
        "Reconnaissance via .git exposure",
        "Credential extraction from source code",
        "Authentication via stolen credentials",
        "Exploitation of WordPress 5.8 KEV vulnerability",
        "Persistence via malicious plugin upload"
      ],
      "alternative_paths": 2,
      "attacker_effort": "Low",
      "tools_required": ["gitdumper", "wpscan", "metasploit"],
      "skill_level": "Intermediate"
    },
    "recommendations": [
      {
        "priority": 1,
        "action": "Remove .git directory from web root",
        "impact": "Prevents credential exposure",
        "risk_reduction": 25
      },
      {
        "priority": 2,
        "action": "Update WordPress to latest version",
        "impact": "Patches 2 KEV vulnerabilities",
        "risk_reduction": 35
      },
      {
        "priority": 3,
        "action": "Implement WAF rules for wp-admin",
        "impact": "Blocks automated attacks",
        "risk_reduction": 15
      }
    ]
  },
  "technologies": [ /* existing tech data */ ],
  "findings": [ /* existing findings */ ]
}
```

### Report Visualization

**Executive Summary Card:**
```
┌─────────────────────────────────────────────────────────┐
│ Domain Compromise Prediction                            │
│                                                         │
│ example.com                                             │
│                                                         │
│            ███████████████░░░░░ 68/100                  │
│                                                         │
│ Category: HIGH RISK                                     │
│ Expected Compromise: 7-30 days                          │
│ Action Required: Remediate within 7 days                │
│                                                         │
│ Primary Risk: Attack chain from .git exposure           │
│               to WordPress KEV exploitation             │
└─────────────────────────────────────────────────────────┘
```

**Component Breakdown:**
```
Risk Factor Contributions:
Technology Risk:      ████████████░░░░░░░░ 52/100 (41% impact)
Attack Chains:        ████████████████████ 100/100 (50% impact)
Attack Surface:       ████████░░░░░░░░░░░░ 44/100 (18% impact)
Environment:          ████████████████████ 100/100 (20% impact)
Temporal Factors:     ███████████████░░░░░ 75/100 (7% impact)
```

**Portfolio View (Multiple Domains):**
```
Domain Portfolio Risk Assessment

Critical (71-100):
  ├─ vulnerable-site.com      ████████████████░░ 85/100  ⚠ Immediate action
  └─ old-wordpress.com         ███████████████░░░ 74/100  ⚠ Urgent

High (51-70):
  ├─ staging.example.com       ████████████░░░░░░ 68/100
  ├─ legacy-app.com            ███████████░░░░░░░ 62/100
  └─ test.internal.com         ██████████░░░░░░░░ 55/100

Moderate (31-50):
  ├─ blog.example.com          ███████░░░░░░░░░░░ 38/100
  └─ docs.example.com          ██████░░░░░░░░░░░░ 34/100

Low (0-30):
  ├─ www.example.com           ████░░░░░░░░░░░░░░ 23/100
  └─ static.example.com        ██░░░░░░░░░░░░░░░░ 8/100

Average Portfolio Risk: 52/100 (Moderate-High)
Domains Requiring Immediate Action: 2
Estimated Breach Probability (90 days): 45%
```

## Validation and Calibration

### Validation Data Sources
1. **Public Breach Databases**
   - Have I Been Pwned
   - Risk Based Security breach database
   - Correlation: Did high-scored domains actually get breached?

2. **Honeypot Data**
   - Deploy identical configurations with different risk profiles
   - Measure time-to-compromise
   - Validate timeline predictions

3. **Red Team Exercises**
   - Internal penetration testing
   - Compare predicted attack paths vs actual paths taken
   - Measure effort vs predictions

4. **Industry Benchmarks**
   - Verizon DBIR statistics
   - Ponemon Cost of Data Breach reports
   - MITRE ATT&CK framework mappings

### Calibration Process
```
1. Collect baseline data (3-6 months)
2. Compare predictions to actual incidents
3. Calculate accuracy metrics:
   - True Positive Rate (correctly predicted compromises)
   - False Positive Rate (false alarms)
   - Precision (of high-risk predictions, what % were breached)
   - Recall (of actual breaches, what % were predicted)
4. Adjust component weights based on correlation analysis
5. Re-test and iterate quarterly
```

### Success Metrics
- **Prediction Accuracy:** 75%+ of High/Critical domains should show attempted exploitation within predicted timeline
- **False Positive Rate:** <15% of High/Critical predictions should remain clean after 90 days
- **Actionability:** 80%+ of remediation recommendations should reduce score by predicted amount
- **Business Value:** Measurable reduction in successful breaches for organizations using the model

## Advanced Features (Future)

### 1. Machine Learning Enhancement
- Train ML model on breach outcome data
- Features: all current factors + additional signals
- Output: More accurate probability estimates
- Continuous learning from new incidents

### 2. Industry Context
- Sector-specific risk profiles (finance vs retail vs media)
- Industry threat intelligence integration
- Peer benchmarking ("Your risk is 2.3x industry average")

### 3. Asset Criticality Weighting
- Not all domains are equally important
- Multiply compromise probability by business impact
- Risk = Probability × Impact
- Enables true risk-based prioritization

### 4. Threat Actor Profiling
- Different attackers target different vulnerabilities
- Model specific threat actor TTPs
- "Your profile matches 80% of targets hit by APT28"
- Adjust predictions based on threat intelligence

### 5. Simulation and What-If Analysis
- "If I patch WordPress, how much does score drop?"
- "What's the ROI of implementing WAF?"
- Interactive remediation planning

### 6. Continuous Monitoring
- Re-scan daily/weekly
- Alert on score increases
- Track risk trends over time
- Predictive alerting ("Score trending toward Critical")

### 7. Compliance Mapping
- Map findings to compliance frameworks (PCI-DSS, SOC 2, ISO 27001)
- Show compliance gaps contributing to compromise risk
- Generate compliance reports

## Economic Analysis

### Attacker Economics
Different compromise probabilities attract different attackers:

| Score Range | Attacker Profile | Motivation | Sophistication |
|-------------|-----------------|------------|----------------|
| 85-100 | Automated botnets, script kiddies | Easy targets, mass exploitation | Low |
| 70-85 | Opportunistic criminals | Moderate effort, high success rate | Medium |
| 50-70 | Targeted campaigns | Specific data/access goals | Medium-High |
| 30-50 | APT groups, nation-states | Strategic targets only | High |
| 0-30 | Rarely targeted | Not worth the effort | N/A |

### Defender Economics
ROI of remediation vs expected breach costs:

```
Expected_Annual_Loss = Compromise_Probability × Average_Breach_Cost

Example:
  Domain score: 68/100
  Probability of breach in 1 year: ~60% (based on historical correlation)
  Average breach cost for org: $2.5M

  Expected Annual Loss = 0.60 × $2,500,000 = $1,500,000

  Remediation cost: $50,000 (WordPress update, WAF deployment, pentest)
  Risk reduction: 68 → 25 (43 point drop)
  New probability: ~10%
  New Expected Annual Loss = 0.10 × $2,500,000 = $250,000

  ROI = ($1,500,000 - $250,000 - $50,000) / $50,000 = 24x
```

## Integration with Existing Systems

### SIEM/SOAR Integration
- Push high-risk domains to SIEM for enhanced monitoring
- Trigger automated playbooks for Critical scores
- Enrich security events with compromise probability

### Vulnerability Management
- Prioritize vulnerability scans for high-risk domains
- Auto-assign critical findings to security team
- SLA mapping based on risk score

### Asset Management (CMDB)
- Enrich asset records with risk scores
- Track risk over time per asset
- Identify risk concentrations

### Ticketing Systems
- Auto-create tickets for High+ risk domains
- Assign based on score and expertise required
- Track remediation SLA compliance

## Summary and Recommendations

### Key Innovations
1. **Holistic Assessment:** Considers entire domain, not just individual vulnerabilities
2. **Attack Chain Detection:** Models real-world multi-step attacks
3. **Predictive Timeline:** Estimates when compromise likely to occur
4. **Actionable Output:** Specific remediation steps with risk reduction quantified
5. **Economic Framing:** Enables ROI-based decision making

### Implementation Roadmap

**Phase 1: Foundation (Week 1-2)**
- Implement basic aggregation model
- Technology risk + Attack surface + Environmental factors
- No chain detection yet
- Validate against known breached domains

**Phase 2: Chain Detection (Week 3-4)**
- Build attack chain rule engine
- Define 10-15 common attack patterns
- Integrate chain scores into model
- Test against red team scenarios

**Phase 3: Temporal & Refinement (Week 5-6)**
- Add temporal risk factors
- Integrate with existing EPSS/KEV data
- Calibrate component weights
- User testing and feedback

**Phase 4: Validation & Tuning (Week 7-8)**
- Collect real-world validation data
- Statistical analysis of prediction accuracy
- Adjust weights and thresholds
- Document methodology

**Phase 5: Advanced Features (Week 9-12)**
- Attack path visualization
- Remediation simulation
- Portfolio analytics
- Industry benchmarking

### Success Criteria
- 75%+ prediction accuracy within 90 days
- <15% false positive rate
- Measurable reduction in breach incidents
- Positive user feedback on actionability
- Adoption by security teams for prioritization

## References

### Breach Statistics
- Verizon 2024 Data Breach Investigations Report
- IBM Cost of a Data Breach Report 2024
- Ponemon Institute Cyber Resilience Study

### Attack Frameworks
- MITRE ATT&CK Framework
- OWASP Top 10
- NIST Cybersecurity Framework

### Predictive Models
- FIRST EPSS (Exploit Prediction Scoring System)
- CISA KEV Catalog
- Recorded Future Threat Intelligence

### Industry Tools
- Qualys TruRisk (asset-level risk scoring)
- Tenable VPR (vulnerability priority rating)
- BitSight Security Ratings (external assessment)
- SecurityScorecard (continuous monitoring)

---

**Document Status:** Research Complete - Design Phase
**Next Steps:** Stakeholder review, approve implementation plan, begin Phase 1
**Owner:** Security Engineering Team
**Dependencies:** Exploitability Scoring Model (prerequisite)
**Last Updated:** October 16, 2025
