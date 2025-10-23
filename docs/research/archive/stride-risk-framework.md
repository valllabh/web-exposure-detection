# STRIDE-Inspired Risk Framework for Web Exposure Detection

**Date:** October 21, 2025
**Status:** Research & Design
**Purpose:** Apply STRIDE threat modeling methodology to web exposure findings to show comprehensive risk profiles

## Executive Summary

This framework adapts Microsoft's STRIDE threat modeling methodology to categorize and quantify web exposure risks. Instead of generic criticality scores, we map each finding to specific STRIDE threat categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege), providing security teams with actionable threat intelligence and business stakeholders with concrete risk scenarios.

**Key Innovation:** Each discovered web asset gets a STRIDE threat profile showing which specific attack vectors are exposed, not just an abstract criticality score.

## Current State vs STRIDE Approach

### Current Implementation

**What we have:**
```json
{
  "domain": "cdn2.qualys.com",
  "criticality": {
    "score": 3,
    "category": "MEDIUM",
    "factors": [
      {"factor": "XML API", "score_delta": 0.2}
    ]
  }
}
```

**Limitation:** Score is abstract. "MEDIUM criticality" doesn't tell security teams WHAT threats exist or HOW to mitigate them.

### STRIDE Enhanced Approach

**What we propose:**
```json
{
  "domain": "portal.company.com",
  "criticality": {
    "score": 4,
    "category": "HIGH"
  },
  "stride_risk_profile": {
    "threats_identified": ["S", "T", "I", "E"],
    "threat_details": {
      "spoofing": {
        "exposed": true,
        "severity": "HIGH",
        "findings": ["auth.traditional.registration", "auth.enterprise.saml_sso"],
        "risk_scenario": "Attackers can impersonate users via stolen credentials or SAML token manipulation",
        "attack_vectors": [
          "Credential stuffing against registration endpoints",
          "SAML assertion replay attacks",
          "Session token theft"
        ],
        "mitigations": ["Implement MFA", "Add rate limiting", "Enable SAML encryption"]
      },
      "tampering": {
        "exposed": true,
        "severity": "MEDIUM",
        "findings": ["api.server.json", "webapp.type.corporate"],
        "risk_scenario": "Data in transit or API responses can be modified",
        "attack_vectors": [
          "Man in the middle attacks on API calls",
          "Form parameter manipulation"
        ],
        "mitigations": ["Enforce HTTPS everywhere", "Implement request signing", "Add integrity checks"]
      },
      "information_disclosure": {
        "exposed": true,
        "severity": "CRITICAL",
        "findings": ["frontend.react", "storage.local_storage", "api.server.json"],
        "risk_scenario": "Sensitive data exposure through client side storage and API responses",
        "attack_vectors": [
          "LocalStorage data extraction via XSS",
          "API response information leakage",
          "Client side code analysis reveals business logic"
        ],
        "mitigations": ["Minimize client storage", "Sanitize API responses", "Code obfuscation"]
      },
      "elevation_of_privilege": {
        "exposed": true,
        "severity": "HIGH",
        "findings": ["auth.enterprise.saml_sso", "webapp.admin_console"],
        "risk_scenario": "Privilege escalation through auth bypass or role manipulation",
        "attack_vectors": [
          "SAML attribute injection for role elevation",
          "Admin console enumeration",
          "Authorization bypass vulnerabilities"
        ],
        "mitigations": ["Validate SAML assertions", "Implement RBAC strictly", "Audit privilege grants"]
      },
      "repudiation": {
        "exposed": false,
        "severity": "LOW",
        "findings": [],
        "risk_scenario": "No specific repudiation threats identified",
        "attack_vectors": [],
        "mitigations": []
      },
      "denial_of_service": {
        "exposed": false,
        "severity": "LOW",
        "findings": [],
        "risk_scenario": "Standard DoS exposure (all internet assets)",
        "attack_vectors": ["Volumetric DDoS"],
        "mitigations": ["Use CDN/WAF with DDoS protection"]
      }
    },
    "risk_score_breakdown": {
      "spoofing_risk": 35,
      "tampering_risk": 20,
      "repudiation_risk": 5,
      "information_disclosure_risk": 40,
      "denial_of_service_risk": 10,
      "elevation_of_privilege_risk": 30,
      "total_stride_score": 140
    },
    "top_risks": [
      "Information Disclosure (CRITICAL)",
      "Spoofing (HIGH)",
      "Elevation of Privilege (HIGH)"
    ]
  }
}
```

## STRIDE Threat Categories for Web Exposure

### S - Spoofing (Authentication Threats)

**Definition:** Illegally accessing systems using another user's identity or impersonating services.

**Web Exposure Indicators:**
- Authentication mechanisms detected: `auth.*` findings
- Registration endpoints: `auth.traditional.registration`
- Enterprise SSO: `auth.enterprise.saml_sso`, `auth.enterprise.oauth2`
- MFA presence: `auth.mfa`
- Login pages: `webapp.type.login_page`

**Risk Calculation:**
```
Spoofing_Risk = Base(10) + Adjustments

Adjustments:
+ Has registration endpoint: +15 (credential stuffing target)
+ Has enterprise SSO: +10 (SAML/OAuth vulnerabilities)
+ NO MFA detected: +15 (weak auth)
+ Has MFA detected: -10 (stronger auth)
+ Login page exposed: +5

Max: 50 points
```

**Example Findings Mapping:**
| Finding | STRIDE Threat | Risk Points | Scenario |
|---------|---------------|-------------|----------|
| `auth.traditional.registration` | Spoofing | +15 | Credential stuffing, account enumeration |
| `auth.enterprise.saml_sso` | Spoofing | +10 | SAML assertion manipulation |
| `auth.mfa` (absence) | Spoofing | +15 | No second factor defense |
| `webapp.type.login_page` | Spoofing | +5 | Phishing target |

**Attack Scenarios:**
1. **Credential Stuffing:** Automated login attempts using breached credentials
2. **SAML Replay:** Intercepting and replaying SAML assertions
3. **Session Hijacking:** Stealing session tokens via XSS or network sniffing
4. **OAuth Token Theft:** Compromising OAuth flows for account takeover

**Mitigation Priorities:**
- Implement MFA on all auth endpoints
- Add rate limiting and CAPTCHA
- Enable SAML encryption and signing
- Use short lived tokens with rotation

### T - Tampering (Data Integrity Threats)

**Definition:** Malicious modification of data in storage, transit, or processing.

**Web Exposure Indicators:**
- API endpoints: `api.server.*` (JSON, XML, GraphQL)
- Forms and input: `webapp.type.*`
- Database hints: `tech.database.*` (if exposed)
- Upload functionality: `webapp.type.file_upload`

**Risk Calculation:**
```
Tampering_Risk = Base(5) + Adjustments

Adjustments:
+ Has API endpoints: +10 (data modification target)
+ Has file upload: +15 (malicious file injection)
+ Database exposed: +20 (direct data tampering)
+ No HTTPS enforcement: +10 (MITM attacks)
+ Has GraphQL: +5 (mutation attacks)

Max: 50 points
```

**Example Findings Mapping:**
| Finding | STRIDE Threat | Risk Points | Scenario |
|---------|---------------|-------------|----------|
| `api.server.json` | Tampering | +10 | API parameter manipulation |
| `api.graphql` | Tampering | +5 | Mutation injection attacks |
| `webapp.type.file_upload` | Tampering | +15 | Malicious file uploads |
| `tech.database.exposed` | Tampering | +20 | Direct database modification |

**Attack Scenarios:**
1. **API Manipulation:** Modifying request parameters to alter data
2. **MITM Attacks:** Intercepting and changing data in transit
3. **File Upload Exploits:** Uploading malicious files (web shells, malware)
4. **SQL Injection:** Database tampering via injection vulnerabilities

**Mitigation Priorities:**
- Input validation and sanitization
- Request integrity verification (HMAC, signatures)
- Secure file upload with type validation
- Database access controls and query parameterization

### R - Repudiation (Accountability Threats)

**Definition:** Users or attackers can deny actions without proof due to lack of logging or auditing.

**Web Exposure Indicators:**
- Financial transactions: `webapp.type.payment`, `api.payment_processing`
- Admin consoles: `webapp.type.admin_console`
- User registration: `auth.traditional.registration`
- High value operations detected

**Risk Calculation:**
```
Repudiation_Risk = Base(5) + Adjustments

Adjustments:
+ Has payment processing: +20 (financial transactions)
+ Has admin console: +10 (privileged operations)
+ Has user registration: +5 (account creation)
+ No audit logging visible: +10 (assumed if no security headers)

Max: 50 points
```

**Example Findings Mapping:**
| Finding | STRIDE Threat | Risk Points | Scenario |
|---------|---------------|-------------|----------|
| `webapp.type.payment` | Repudiation | +20 | Users deny making purchases |
| `webapp.type.admin_console` | Repudiation | +10 | Admins deny privilege abuse |
| `auth.traditional.registration` | Repudiation | +5 | Deny creating fake accounts |

**Attack Scenarios:**
1. **Transaction Denial:** Users claim they didn't make purchases
2. **Privilege Abuse:** Admins perform unauthorized actions and deny them
3. **Account Creation Denial:** Attackers create accounts and deny ownership
4. **Data Modification Denial:** Changes made without attribution

**Mitigation Priorities:**
- Implement comprehensive audit logging
- Add cryptographic non repudiation (digital signatures)
- Enable tamper evident logs
- Two person authorization for critical operations

### I - Information Disclosure (Confidentiality Threats)

**Definition:** Exposure of information to unauthorized parties.

**Web Exposure Indicators:**
- Client side storage: `storage.local_storage`, `storage.session_storage`, `storage.cookies`
- API responses: `api.server.*`
- Frontend frameworks: `frontend.*` (React, Vue, Angular expose logic)
- Error messages: `webapp.error_exposure`
- Technology stack exposure: All `tech.*` findings

**Risk Calculation:**
```
Information_Disclosure_Risk = Base(15) + Adjustments

Adjustments:
+ Has local/session storage: +15 (client side data exposure)
+ Has API endpoints: +10 (response data leakage)
+ Frontend framework: +10 (source code analysis)
+ Technology versions exposed: +5 (recon advantage)
+ Has auth + no encryption: +15 (credential exposure)
+ Error messages exposed: +10 (information leakage)

Max: 80 points (highest because most common)
```

**Example Findings Mapping:**
| Finding | STRIDE Threat | Risk Points | Scenario |
|---------|---------------|-------------|----------|
| `storage.local_storage` | Information Disclosure | +15 | Sensitive data in browser storage |
| `api.server.json` | Information Disclosure | +10 | API responses reveal business logic |
| `frontend.react` | Information Disclosure | +10 | Source code analysis reveals secrets |
| `tech.webserver.nginx.1.18.0` | Information Disclosure | +5 | Version info aids targeted attacks |
| `webapp.error.stack_trace` | Information Disclosure | +10 | Error messages reveal internals |

**Attack Scenarios:**
1. **Client Storage Extraction:** XSS or malware stealing localStorage data
2. **API Response Mining:** Analyzing API responses for sensitive data
3. **Source Code Analysis:** Reverse engineering frontend code for logic/secrets
4. **Technology Fingerprinting:** Using version info to find known vulnerabilities
5. **Error Message Exploitation:** Stack traces revealing file paths and structure

**Mitigation Priorities:**
- Minimize client side data storage
- Sanitize API responses (return only necessary fields)
- Obfuscate/minify frontend code
- Hide technology versions
- Implement custom error pages (no stack traces)

### D - Denial of Service (Availability Threats)

**Definition:** Attacks that make systems unavailable to legitimate users.

**Web Exposure Indicators:**
- Public internet facing (all discovered assets)
- No CDN/WAF: absence of `gateway.cloudflare`, `gateway.akamai`
- Resource intensive endpoints: `api.graphql`, `api.server.*`
- Upload endpoints: `webapp.type.file_upload`

**Risk Calculation:**
```
Denial_of_Service_Risk = Base(10) + Adjustments

Adjustments:
+ No CDN detected: +15 (no DDoS protection)
+ Has resource intensive APIs: +10 (amplification attacks)
+ Has file upload: +10 (storage exhaustion)
+ Has GraphQL: +5 (query complexity attacks)
- Has CDN (Cloudflare/Akamai): -10 (DDoS mitigation)

Max: 50 points
```

**Example Findings Mapping:**
| Finding | STRIDE Threat | Risk Points | Scenario |
|---------|---------------|-------------|----------|
| No CDN detected | Denial of Service | +15 | Volumetric DDoS attacks |
| `api.graphql` | Denial of Service | +5 | Complex query DoS |
| `webapp.type.file_upload` | Denial of Service | +10 | Storage exhaustion |
| `gateway.cloudflare` | Denial of Service | -10 | DDoS protection present |

**Attack Scenarios:**
1. **Volumetric DDoS:** Network flooding attacks
2. **Application Layer DoS:** Slow requests, resource exhaustion
3. **GraphQL Query Complexity:** Expensive queries overwhelming backend
4. **Storage Exhaustion:** Uploading large files to fill disk
5. **API Rate Abuse:** Overwhelming API endpoints without rate limits

**Mitigation Priorities:**
- Deploy CDN with DDoS protection
- Implement rate limiting
- Add request size limits
- Query complexity analysis for GraphQL
- Resource quotas and monitoring

### E - Elevation of Privilege (Authorization Threats)

**Definition:** Unprivileged users gaining privileged access or bypassing authorization.

**Web Exposure Indicators:**
- Admin consoles: `webapp.type.admin_console`, `webapp.type.dashboard`
- Enterprise auth: `auth.enterprise.*` (privilege management complexity)
- APIs: `api.server.*` (authorization bypass opportunities)
- Role based access: presence of complex auth suggests roles

**Risk Calculation:**
```
Elevation_of_Privilege_Risk = Base(5) + Adjustments

Adjustments:
+ Has admin console: +20 (privilege escalation target)
+ Has enterprise SSO: +10 (SAML attribute injection)
+ Has API endpoints: +10 (authorization bypass)
+ Has complex auth (multiple methods): +5
+ No MFA on admin: +10

Max: 60 points
```

**Example Findings Mapping:**
| Finding | STRIDE Threat | Risk Points | Scenario |
|---------|---------------|-------------|----------|
| `webapp.type.admin_console` | Elevation of Privilege | +20 | Unauthorized admin access |
| `auth.enterprise.saml_sso` | Elevation of Privilege | +10 | SAML role attribute injection |
| `api.server.json` | Elevation of Privilege | +10 | API authorization bypass |
| Multiple auth methods | Elevation of Privilege | +5 | Complex attack surface |

**Attack Scenarios:**
1. **Admin Console Bypass:** Unauthorized access to admin functions
2. **SAML Attribute Injection:** Modifying SAML assertions to gain admin roles
3. **API Authorization Bypass:** Accessing privileged API endpoints
4. **Horizontal Privilege Escalation:** Accessing other users' data
5. **Vertical Privilege Escalation:** Regular user to admin elevation

**Mitigation Priorities:**
- Strict RBAC implementation
- Validate all SAML/OAuth claims
- API authorization on every request
- MFA for privileged operations
- Regular authorization testing

## STRIDE Risk Scoring System

### Individual Threat Scores

Each STRIDE category gets a score from 0 to 50+ points based on findings:
- **0-10:** Minimal risk
- **11-20:** Low risk
- **21-30:** Medium risk
- **31-40:** High risk
- **41+:** Critical risk

### Composite STRIDE Score

```
Total_STRIDE_Score = S + T + R + I + D + E

Range: 0 to 300 points

Risk Levels:
- 0-50: Overall Low Risk
- 51-100: Overall Medium Risk
- 101-150: Overall High Risk
- 151+: Overall Critical Risk
```

### Mapping to Existing Criticality

The STRIDE score complements (not replaces) the existing Qualys aligned criticality:

```json
{
  "criticality": {
    "score": 4,
    "category": "HIGH"
  },
  "stride_analysis": {
    "total_score": 140,
    "severity": "CRITICAL",
    "threat_breakdown": {
      "spoofing": 35,
      "tampering": 20,
      "repudiation": 5,
      "information_disclosure": 40,
      "denial_of_service": 10,
      "elevation_of_privilege": 30
    }
  }
}
```

## Implementation Design

### Data Structure

**New Types:**

```go
// pkg/webexposure/stride/stride_types.go

package stride

// ThreatCategory represents one STRIDE category
type ThreatCategory struct {
    Category        string   `json:"category"`         // "Spoofing", "Tampering", etc.
    Exposed         bool     `json:"exposed"`          // Is this threat present?
    Severity        string   `json:"severity"`         // LOW, MEDIUM, HIGH, CRITICAL
    RiskScore       int      `json:"risk_score"`       // 0-50+ points
    Findings        []string `json:"findings"`         // Finding slugs contributing
    RiskScenario    string   `json:"risk_scenario"`    // What can happen
    AttackVectors   []string `json:"attack_vectors"`   // How attacks occur
    Mitigations     []string `json:"mitigations"`      // Recommended fixes
}

// STRIDERiskProfile represents complete STRIDE analysis
type STRIDERiskProfile struct {
    ThreatsIdentified []string                   `json:"threats_identified"` // ["S", "T", "I", "E"]
    ThreatDetails     map[string]*ThreatCategory `json:"threat_details"`
    RiskScoreBreakdown map[string]int            `json:"risk_score_breakdown"`
    TotalScore        int                        `json:"total_stride_score"`
    OverallSeverity   string                     `json:"overall_severity"`
    TopRisks          []string                   `json:"top_risks"` // Top 3 threats
}
```

### Calculation Algorithm

**pkg/webexposure/stride/stride.go:**

```go
package stride

import (
    "web-exposure-detection/pkg/webexposure/findings"
)

// CalculateSTRIDERisk analyzes findings and produces STRIDE threat profile
func CalculateSTRIDERisk(domain string, findingsSlugs []string) *STRIDERiskProfile {
    profile := &STRIDERiskProfile{
        ThreatsIdentified: []string{},
        ThreatDetails: make(map[string]*ThreatCategory),
        RiskScoreBreakdown: make(map[string]int),
    }

    // Analyze each STRIDE category
    profile.ThreatDetails["spoofing"] = analyzeSpoofing(findingsSlugs)
    profile.ThreatDetails["tampering"] = analyzeTampering(findingsSlugs)
    profile.ThreatDetails["repudiation"] = analyzeRepudiation(findingsSlugs)
    profile.ThreatDetails["information_disclosure"] = analyzeInformationDisclosure(findingsSlugs)
    profile.ThreatDetails["denial_of_service"] = analyzeDenialOfService(findingsSlugs)
    profile.ThreatDetails["elevation_of_privilege"] = analyzeElevationOfPrivilege(findingsSlugs)

    // Calculate scores and identify exposed threats
    totalScore := 0
    for category, threat := range profile.ThreatDetails {
        score := threat.RiskScore
        profile.RiskScoreBreakdown[category+"_risk"] = score
        totalScore += score

        if threat.Exposed {
            profile.ThreatsIdentified = append(profile.ThreatsIdentified,
                getCategoryLetter(category))
        }
    }

    profile.TotalScore = totalScore
    profile.OverallSeverity = determineOverallSeverity(totalScore)
    profile.TopRisks = identifyTopRisks(profile.ThreatDetails)

    return profile
}

// analyzeSpoofing checks for authentication related threats
func analyzeSpoofing(findingsSlugs []string) *ThreatCategory {
    threat := &ThreatCategory{
        Category: "Spoofing",
        Exposed: false,
        RiskScore: 10, // Base score
        Findings: []string{},
        AttackVectors: []string{},
        Mitigations: []string{},
    }

    hasMFA := false
    hasAuth := false

    for _, slug := range findingsSlugs {
        switch {
        case strings.HasPrefix(slug, "auth.traditional.registration"):
            threat.RiskScore += 15
            threat.Findings = append(threat.Findings, slug)
            threat.AttackVectors = append(threat.AttackVectors,
                "Credential stuffing against registration endpoints",
                "Account enumeration")
            hasAuth = true

        case strings.HasPrefix(slug, "auth.enterprise.saml_sso"):
            threat.RiskScore += 10
            threat.Findings = append(threat.Findings, slug)
            threat.AttackVectors = append(threat.AttackVectors,
                "SAML assertion replay attacks",
                "SAML attribute manipulation")
            hasAuth = true

        case strings.HasPrefix(slug, "auth.enterprise.oauth2"):
            threat.RiskScore += 10
            threat.Findings = append(threat.Findings, slug)
            threat.AttackVectors = append(threat.AttackVectors,
                "OAuth token theft",
                "Authorization code interception")
            hasAuth = true

        case strings.HasPrefix(slug, "auth.mfa"):
            hasMFA = true
            threat.Findings = append(threat.Findings, slug)

        case strings.HasPrefix(slug, "webapp.type.login_page"):
            threat.RiskScore += 5
            threat.Findings = append(threat.Findings, slug)
            threat.AttackVectors = append(threat.AttackVectors,
                "Phishing page clone target")
        }
    }

    // Adjust for MFA
    if hasAuth && !hasMFA {
        threat.RiskScore += 15
        threat.AttackVectors = append(threat.AttackVectors,
            "No MFA protection allows single factor compromise")
        threat.Mitigations = append(threat.Mitigations,
            "Implement MFA on all authentication endpoints")
    } else if hasMFA {
        threat.RiskScore -= 10
        threat.Mitigations = append(threat.Mitigations,
            "MFA present but ensure bypass protections")
    }

    // Determine if exposed
    threat.Exposed = len(threat.Findings) > 0 && hasAuth
    threat.Severity = determineSeverity(threat.RiskScore)

    if threat.Exposed {
        threat.RiskScenario = "Attackers can impersonate users via stolen credentials, SAML/OAuth token manipulation, or authentication bypass"
    } else {
        threat.RiskScenario = "No authentication mechanisms detected"
    }

    // Add standard mitigations
    if threat.Exposed {
        threat.Mitigations = append(threat.Mitigations,
            "Add rate limiting and CAPTCHA",
            "Enable session monitoring and anomaly detection",
            "Use short lived tokens with rotation")
    }

    return threat
}

// Similar functions for other STRIDE categories:
// - analyzeTampering()
// - analyzeRepudiation()
// - analyzeInformationDisclosure()
// - analyzeDenialOfService()
// - analyzeElevationOfPrivilege()

func determineSeverity(score int) string {
    if score >= 41 {
        return "CRITICAL"
    } else if score >= 31 {
        return "HIGH"
    } else if score >= 21 {
        return "MEDIUM"
    } else if score >= 11 {
        return "LOW"
    }
    return "MINIMAL"
}

func determineOverallSeverity(totalScore int) string {
    if totalScore >= 151 {
        return "CRITICAL"
    } else if totalScore >= 101 {
        return "HIGH"
    } else if totalScore >= 51 {
        return "MEDIUM"
    }
    return "LOW"
}

func identifyTopRisks(threats map[string]*ThreatCategory) []string {
    // Sort threats by risk score and return top 3
    // Implementation details...
    return []string{}
}
```

### Integration Points

**1. Update Discovery Type:**

```go
// pkg/webexposure/report/report_types.go
type Discovery struct {
    Domain           string                  `json:"domain"`
    Title            string                  `json:"title,omitempty"`
    Description      string                  `json:"description,omitempty"`
    Discovered       string                  `json:"discovered"`
    FindingItems     []*findings.FindingItem `json:"findings"`
    Criticality      *findings.Criticality   `json:"criticality,omitempty"`
    STRIDERiskProfile *stride.STRIDERiskProfile `json:"stride_risk_profile,omitempty"` // NEW
}
```

**2. Update processDomain():**

```go
// In pkg/webexposure/report/report.go
criticality := criticality.CalculateCriticality(domain, domainResult.Title, findingSlugs)
domainResult.Criticality = criticality

// NEW: Calculate STRIDE risk profile
strideProfile := stride.CalculateSTRIDERisk(domain, findingSlugs)
domainResult.STRIDERiskProfile = strideProfile

logger.Info().Msgf("Domain %s: criticality=%d (%s), STRIDE score=%d (%s), threats=%v",
    domain, criticality.Score, criticality.Category,
    strideProfile.TotalScore, strideProfile.OverallSeverity,
    strideProfile.ThreatsIdentified)
```

**3. Update Summary Statistics:**

```go
// Add to Summary type
type Summary struct {
    // ... existing fields ...

    // STRIDE statistics
    STRIDEStats *STRIDEStatistics `json:"stride_stats,omitempty"`
}

type STRIDEStatistics struct {
    TotalDomainsAnalyzed     int            `json:"total_domains_analyzed"`
    AverageSTRIDEScore       int            `json:"average_stride_score"`
    HighestSTRIDEScore       int            `json:"highest_stride_score"`
    HighestRiskDomain        string         `json:"highest_risk_domain"`
    ThreatDistribution       map[string]int `json:"threat_distribution"` // How many domains exposed to each threat
    MostCommonThreats        []string       `json:"most_common_threats"` // Top 3 threats across portfolio
}
```

## Reporting Enhancements

### HTML Report - STRIDE Threat Cards

**Add to templates/report.html:**

```html
<!-- STRIDE Risk Profile Section -->
{{if .STRIDERiskProfile}}
<div class="stride-analysis">
    <h3>STRIDE Threat Analysis</h3>

    <div class="stride-summary">
        <div class="stride-score">
            <span class="score-label">STRIDE Risk Score:</span>
            <span class="score-value score-{{.STRIDERiskProfile.OverallSeverity | lower}}">
                {{.STRIDERiskProfile.TotalScore}}
            </span>
            <span class="severity-badge severity-{{.STRIDERiskProfile.OverallSeverity | lower}}">
                {{.STRIDERiskProfile.OverallSeverity}}
            </span>
        </div>

        <div class="threats-detected">
            <span class="threats-label">Threats Identified:</span>
            <span class="threat-letters">{{join .STRIDERiskProfile.ThreatsIdentified ", "}}</span>
        </div>
    </div>

    <div class="stride-breakdown">
        <h4>Threat Breakdown</h4>

        {{range $category, $threat := .STRIDERiskProfile.ThreatDetails}}
        {{if $threat.Exposed}}
        <div class="threat-card threat-{{$threat.Severity | lower}}">
            <div class="threat-header">
                <h5>
                    <span class="stride-letter">{{getCategoryLetter $category}}</span>
                    {{$threat.Category}}
                </h5>
                <span class="threat-score">Risk: {{$threat.RiskScore}}</span>
                <span class="severity-tag severity-{{$threat.Severity | lower}}">{{$threat.Severity}}</span>
            </div>

            <div class="threat-scenario">
                <strong>Risk Scenario:</strong>
                <p>{{$threat.RiskScenario}}</p>
            </div>

            <div class="attack-vectors">
                <strong>Attack Vectors:</strong>
                <ul>
                {{range $threat.AttackVectors}}
                    <li>{{.}}</li>
                {{end}}
                </ul>
            </div>

            <div class="mitigations">
                <strong>Recommended Mitigations:</strong>
                <ul>
                {{range $threat.Mitigations}}
                    <li>{{.}}</li>
                {{end}}
                </ul>
            </div>

            <div class="contributing-findings">
                <strong>Contributing Findings:</strong>
                <div class="findings-tags">
                {{range $threat.Findings}}
                    <span class="finding-tag">{{.}}</span>
                {{end}}
                </div>
            </div>
        </div>
        {{end}}
        {{end}}
    </div>

    <div class="top-risks">
        <h4>Priority Threats</h4>
        <ol>
        {{range .STRIDERiskProfile.TopRisks}}
            <li>{{.}}</li>
        {{end}}
        </ol>
    </div>
</div>
{{end}}
```

### CLI Output Enhancement

**Add STRIDE summary to terminal output:**

```
Domain: portal.company.com [HIGH CRITICALITY]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STRIDE Risk Analysis: 140 points (CRITICAL)
Threats: S, T, I, E

Top Risks:
  1. Information Disclosure (CRITICAL) - Score: 40
     → Client storage exposes sensitive data
     → API responses reveal business logic

  2. Spoofing (HIGH) - Score: 35
     → No MFA on enterprise auth
     → Credential stuffing vulnerability

  3. Elevation of Privilege (HIGH) - Score: 30
     → Admin console accessible
     → SAML attribute injection risk

Recommended Actions:
  • Implement MFA on all authentication endpoints
  • Minimize client side data storage
  • Strict RBAC implementation
  • Add rate limiting and CAPTCHA
```

### Executive Dashboard

**Portfolio Level STRIDE View:**

```
┌─────────────────────────────────────────────────────────────┐
│ STRIDE THREAT LANDSCAPE - Portfolio View                   │
│                                                             │
│ Total Domains: 259                                          │
│ Average STRIDE Score: 87 (HIGH)                             │
│                                                             │
│ Threat Distribution:                                        │
│ ┌───────────────────────────────────────────────────┐       │
│ │ S - Spoofing              156 domains (60%)       │       │
│ │ T - Tampering              89 domains (34%)       │       │
│ │ R - Repudiation            23 domains (9%)        │       │
│ │ I - Information Disclosure 245 domains (95%)      │       │
│ │ D - Denial of Service      201 domains (78%)      │       │
│ │ E - Elevation of Privilege  67 domains (26%)      │       │
│ └───────────────────────────────────────────────────┘       │
│                                                             │
│ Most Critical Threat: Information Disclosure                │
│ - 95% of portfolio exposed                                  │
│ - Average I score: 42 points                                │
│ - Primary vectors: Client storage, API responses            │
│                                                             │
│ Highest Risk Domains by STRIDE Score:                       │
│ 1. portal-bo.gov1.qualys.us    185 (S,T,I,E) CRITICAL      │
│ 2. api.payments.company.com    172 (S,T,I,E) CRITICAL      │
│ 3. admin.legacy.company.com    168 (S,I,E,D) CRITICAL      │
│                                                             │
│ Remediation Impact:                                         │
│ • Fix Info Disclosure (245 domains): -$28M annual risk     │
│ • Implement MFA (156 domains): -$15M annual risk           │
│ • Add rate limiting (all): -$8M annual risk                │
└─────────────────────────────────────────────────────────────┘
```

## Usage Examples

### CLI Commands

**Basic scan with STRIDE analysis:**
```bash
./bin/web-exposure-detection scan qualys.com
# Automatically includes STRIDE analysis in report
```

**View STRIDE focused output:**
```bash
# JSON query for STRIDE scores
jq '.apis_found[] | {domain, stride: .stride_risk_profile.total_score, threats: .stride_risk_profile.threats_identified}' \
  results/qualys.com/web-exposure-result.json

# Filter domains by specific STRIDE threats
jq '.apis_found[] | select(.stride_risk_profile.threat_details.spoofing.exposed == true) | .domain' \
  results/qualys.com/web-exposure-result.json

# Get all domains with Information Disclosure risk
jq '.apis_found[] | select(.stride_risk_profile.threat_details.information_disclosure.severity == "CRITICAL") | .domain' \
  results/qualys.com/web-exposure-result.json
```

## Benefits Over Current Approach

### For Security Teams

**Current State:**
- "This domain has MEDIUM criticality"
- Generic scoring doesn't guide remediation

**STRIDE Enhanced:**
- "This domain exposed to Spoofing (35 pts), Information Disclosure (40 pts), Elevation of Privilege (30 pts)"
- Specific threats guide targeted mitigations
- Attack vectors listed for each threat
- Prioritized mitigation recommendations

### For Development Teams

**Current State:**
- Fix "MEDIUM criticality findings"
- No clear understanding of actual risks

**STRIDE Enhanced:**
- "Fix Information Disclosure by removing sensitive data from localStorage"
- "Mitigate Spoofing by implementing MFA"
- Clear, actionable tasks tied to real attack scenarios

### For Business Stakeholders

**Current State:**
- "We have 82 HIGH criticality web apps"
- Abstract numbers don't convey business impact

**STRIDE Enhanced:**
- "95% of our portfolio is vulnerable to Information Disclosure attacks (data theft)"
- "156 domains can be compromised via Spoofing attacks (account takeovers)"
- Threat categories business can understand

### For Compliance/Audit

**Current State:**
- Generic risk scores
- Difficult to map to compliance frameworks

**STRIDE Enhanced:**
- STRIDE maps directly to ISO 27001, NIST, PCI DSS controls
- "Information Disclosure" → Confidentiality requirements
- "Tampering" → Integrity requirements
- "Denial of Service" → Availability requirements
- "Spoofing/Elevation" → Authentication/Authorization requirements

## Integration with Financial Risk

STRIDE analysis can enhance the financial risk model:

```json
{
  "domain": "portal.company.com",
  "criticality": {"score": 4, "category": "HIGH"},
  "stride_risk_profile": {
    "total_score": 140,
    "overall_severity": "CRITICAL",
    "threats_identified": ["S", "T", "I", "E"]
  },
  "financial_risk": {
    "expected_annual_loss": 3904000,
    "breakdown_by_threat": {
      "spoofing_loss": 1365400,
      "tampering_loss": 780800,
      "information_disclosure_loss": 1561600,
      "elevation_of_privilege_loss": 1172400
    },
    "threat_specific_scenarios": {
      "spoofing": {
        "scenario": "Account takeover via credential stuffing",
        "probability": 0.42,
        "impact": "$3.25M per incident",
        "annual_loss": "$1.37M"
      },
      "information_disclosure": {
        "scenario": "Data breach via client storage extraction",
        "probability": 0.48,
        "impact": "$3.25M per incident",
        "annual_loss": "$1.56M"
      }
    }
  }
}
```

## Implementation Roadmap

### Phase 1: Core STRIDE Analysis (Week 1-2)
- Create stride package with types
- Implement STRIDE calculation functions
- Unit tests for each threat category
- Basic integration with report generation

### Phase 2: Reporting Enhancement (Week 3)
- Update HTML templates with STRIDE threat cards
- Add STRIDE summary to CLI output
- JSON schema updates
- Portfolio level STRIDE statistics

### Phase 3: Advanced Features (Week 4)
- Attack vector enumeration
- Mitigation recommendation engine
- Threat specific financial risk breakdown
- Compliance mapping

### Phase 4: Documentation & Testing (Week 5)
- User documentation
- Example reports
- End to end testing
- Performance optimization

## Success Metrics

- **Clarity:** Security teams can explain specific threats instead of abstract scores
- **Actionability:** Developers get concrete mitigation tasks
- **Prioritization:** Portfolio view shows which threats affect most domains
- **Compliance:** Easy mapping to security frameworks and standards
- **Communication:** Business stakeholders understand "Information Disclosure" better than "Criticality Score 3"

## References

### STRIDE Resources
- Microsoft Security Development Lifecycle (SDL) Threat Modeling
- "Uncover Security Design Flaws Using The STRIDE Approach" (Microsoft Learn)
- OWASP Threat Modeling Cheat Sheet
- "Threat Modeling: Designing for Security" by Adam Shostack

### Industry Standards
- ISO/IEC 27005 Information Security Risk Management
- NIST SP 800-30 Guide for Conducting Risk Assessments
- OWASP Top 10 (maps to STRIDE categories)
- CWE/SANS Top 25 (vulnerability to STRIDE mapping)

---

**Document Status:** Research Complete - Design Phase
**Next Steps:** Implement core STRIDE calculation package
**Dependencies:** Existing findings.json metadata
**Last Updated:** October 21, 2025
