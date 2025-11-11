# Content Generation Analysis

**Purpose:** Analyze how each piece of content in visual-layer-content-examples.md can be generated from existing data without AI

**Date:** 2025-10-28

---

## Analysis Approach

For each content piece, I'm evaluating:
1. **Can we generate it from existing JSON data?** (Yes/No)
2. **What data source?** (specific JSON paths)
3. **Does it require AI?** (flag separately)
4. **Restructuring needed?** (if not generatable)

---

## LAYER 1A: Exposed Applications

### Content Example (perplexity.ai)
```
25 Applications Discovered
├─ 23 Web Applications
├─ 2 API Servers
├─ 1 API Specification
└─ 0 AI Assets

27 Internet-Accessible Domains
41 Total Domains Discovered
```

### Analysis

| Content | Generatable | Data Source | Notes |
|---------|-------------|-------------|-------|
| 25 Applications | ✅ YES | `summary.total_apps` | Direct |
| 23 Web Applications | ✅ YES | `summary.web_apps_found` | Direct |
| 2 API Servers | ✅ YES | `summary.apis_found` | Direct |
| 1 API Specification | ✅ YES | `summary.api_specifications_found` | Direct |
| 0 AI Assets | ✅ YES | `summary.ai_assets_found` | Direct |
| 27 Internet Domains | ✅ YES | `summary.domain_metrics.internet_exposed` | Direct |
| 41 Total Domains | ✅ YES | `summary.domain_metrics.total_discovered` | Direct |

**VERDICT: ✅ FULLY GENERATABLE**

### Content Example (qualys.com) - Extended Version
```
Application Breakdown:
• Customer-Facing Portals (15)
• Partner/Integration APIs (12)
• Marketing & Documentation (18)
• Product Trial/Demo Environments (8)
• Legacy/EOL Products (6)
• Internal Tools Exposed (8)
```

### Analysis

| Content | Generatable | Notes |
|---------|-------------|-------|
| Category breakdown | ❌ NO | We don't classify apps into these business categories |

**ISSUE:** Our data model does not capture:
- Business purpose of applications (customer facing vs internal)
- Application lifecycle (legacy/EOL vs active)
- Content type (marketing vs product)

**OPTIONS:**
1. **Remove this breakdown** - stick to basic counts (23 web apps, 2 APIs)
2. **Add detection logic** - classify based on URL patterns, content analysis
3. **Use AI** - classify each app into categories (MUST FLAG AS AI GENERATED)

**RECOMMENDATION:** Remove detailed breakdown. Use only what we have:
```
67 Applications Discovered
├─ 52 Web Applications
├─ 12 API Servers
├─ 5 API Specifications
└─ 3 AI Assets

78 Internet-Accessible Domains
124 Total Domains Discovered
```

---

## LAYER 1B: Internal Applications (Shadow Layer)

### Content Example
```
Based on industry benchmarks,
AI/Technology companies typically operate
~35-40 internal applications

Potential Internal Assets:
• Development/Staging Environments
• Internal APIs & Microservices
• Admin Dashboards & Tools
• Data Processing Pipelines
• Model Training Infrastructure
```

### Analysis

| Content | Generatable | Data Source | Notes |
|---------|-------------|-------------|-------|
| Industry name | ⚠️ PARTIAL | Need industry classification | See below |
| Internal app count range | ❌ NO | External benchmark data required | Not in our data |
| Asset type bullets | ❌ NO | Industry templates required | Not in our data |

**ISSUES:**
1. **Industry Classification:** Do we have this in our data? Need to check.
2. **Benchmark Data:** Requires external data source (Gartner, Forrester)
3. **Industry Templates:** Need predefined templates per industry

**DATA CHECK NEEDED:**
- Is there industry classification in the JSON?
- Where would this come from?

**OPTIONS:**
1. **Hardcode benchmark ranges** - create lookup table per industry
2. **Remove this layer** - too speculative without real data
3. **Generic messaging** - "Companies typically have 2-3x more internal applications"

**RECOMMENDATION:** This layer requires:
- Industry classification (where does this come from?)
- External benchmark data (can be hardcoded lookup table)
- Template system for industry specific bullets (can be hardcoded)

**NOT AI REQUIRED** - but needs external data source integration

---

## LAYER 2: Infrastructure

### Content Example
```
Gateway & CDN:
• Cloudflare (23 instances)

Authentication Services:
• Google Auth (8 instances)
• Apple Auth (5 instances)

POTENTIAL
└─ 3 Weakness Patterns Identified
   (Infrastructure components show
    no direct CVE applicability)
```

### Analysis

| Content | Generatable | Data Source | Notes |
|---------|-------------|-------------|-------|
| Cloudflare (23 instances) | ✅ YES | `technology_exposure.technologies[].count` | Direct |
| Google Auth (8) | ✅ YES | Same as above | Direct |
| Apple Auth (5) | ✅ YES | Same as above | Direct |
| Category grouping | ⚠️ PARTIAL | `technology_exposure.technologies[].labels` | Need logic |
| "3 Weakness Patterns" | ❓ UNCLEAR | Where does this come from? | See below |
| CVE applicability note | ✅ YES | `technology_exposure.technologies[].security.cve_applicable` | Direct |

**ISSUE: Category Grouping**

We have labels for each tech:
- Cloudflare: `["CDN", "Security", "DNS"]`
- Google Auth: `["Social Authentication", "OAuth"]`
- Apple Auth: `["Social Authentication", "OAuth"]`

**OPTION 1:** Group by first label
```
CDN:
• Cloudflare (23 instances)

Social Authentication:
• Google Auth (8 instances)
• Apple Auth (5 instances)
```

**OPTION 2:** Group by slug prefix
- `gateway.*` → Gateway & CDN
- `auth.*` → Authentication Services
- `frontend.*` → Frontend Frameworks

**RECOMMENDATION:** Use labels for grouping. If tech has multiple labels, use first one. Can be done programmatically.

**MAJOR ISSUE: "3 Weakness Patterns Identified"**

Where does this number come from?

Looking at the data, I see infrastructure techs (Cloudflare, Auth) have:
- `cve_applicable: false`
- `cwe_applicable: false`
- `vulnerabilities: []`

But the content says "3 Weakness Patterns" - where is this?

**PROBLEM:** The example says infrastructure has weakness patterns but no CVE applicability. But if `cwe_applicable: false`, then there are ZERO weakness patterns, not 3.

**This is INCONSISTENT with the data model.**

**OPTIONS:**
1. **Remove weakness count** - just say "no direct CVE applicability"
2. **Show 0 patterns** - be honest
3. **Fix the data model** - maybe some infrastructure CAN have CWEs?

**RECOMMENDATION:** Restructure to:
```
POTENTIAL
└─ Infrastructure components show no direct CVE applicability
```

Remove the "3 Weakness Patterns" claim - it's not backed by data.

### Extended Example (qualys.com)
```
POTENTIAL
├─ 89 Vulnerabilities
├─ 3 Exploitable (CISA KEV)
└─ 12 Weakness Patterns

Critical Infrastructure Risks:
• Outdated Nginx Versions (12 instances)
• Apache 2.4.x with known CVEs (8)
• F5 BIG-IP CVE-2023-46747 (CVSS 9.8)
• SSL/TLS Configuration Weaknesses (18)
```

### Analysis

| Content | Generatable | Notes |
|---------|-------------|-------|
| 89 Vulnerabilities | ✅ YES | Sum vulnerabilities from infra techs |
| 3 Exploitable (KEV) | ✅ YES | Count KEV flagged vulns |
| 12 Weakness Patterns | ✅ YES | Count unique CWEs |
| Specific CVE callouts | ⚠️ PARTIAL | Have data but need prioritization logic |
| Version details | ❓ UNCLEAR | Do we capture versions? |

**ISSUE: Technology Versions**

Example shows "Nginx 1.18.x" and "Apache 2.4.x"

Do we capture versions in our tech data?

**DATA CHECK NEEDED:** Does `technology_exposure.technologies[]` include version info?

**ISSUE: Specific CVE Selection**

Example shows "F5 BIG-IP CVE-2023-46747 (CVSS 9.8)"

We have vulnerabilities, but how do we SELECT which ones to highlight?

**OPTIONS:**
1. **Show top N by CVSS score**
2. **Show only KEV flagged**
3. **Show critical severity only**

**NOT AI** - just sorting/filtering logic

---

## LAYER 3: Technology Stacks

### Content Example
```
6 Technologies Detected

POTENTIAL
├─ 343 Vulnerabilities
├─ 13 Exploitable (CISA KEV)
├─ 27 Critical | 76 High | 184 Medium | 23 Low
└─ 5 Weakness Patterns

Top Weakness Patterns:
• Use of Unmaintained Third Party Components (CWE-1104)
• Cross-Site Scripting (XSS) (CWE-79)
• Improper Input Validation (CWE-20)
• Inclusion of Functionality from Untrusted Control Sphere (CWE-829)
• URL Redirection to Untrusted Site (CWE-601)
```

### Analysis

| Content | Generatable | Data Source | Notes |
|---------|-------------|-------------|-------|
| 6 Technologies | ✅ YES | `technology_exposure.count` | Direct |
| 343 Vulnerabilities | ✅ YES | `summary.security.total_vulnerabilities` | Direct |
| 13 Exploitable (KEV) | ✅ YES | `summary.security.kev_count` | Direct |
| Severity breakdown | ✅ YES | `summary.security.{critical,high,medium,low}_count` | Direct |
| 5 Weakness Patterns | ✅ YES | Count of `summary.security.top_weaknesses` | Direct |
| CWE list with names | ✅ YES | `summary.security.top_weaknesses[].{id,name,count}` | Direct |

**VERDICT: ✅ FULLY GENERATABLE**

This is the cleanest layer - everything maps directly to JSON data.

### Extended Example (qualys.com)
```
Top Weakness Patterns:
• SQL Injection (CWE-89) - 47 instances
• Cross-Site Scripting (CWE-79) - 38 instances
...

High-Risk Technology Inventory:
• Legacy Java Frameworks (3 EOL versions)
• End-of-Life JavaScript Libraries (5)
• Outdated Python Packages (8)
• Ruby on Rails < 6.0 (2 instances)
• Unmaintained Open Source Components (12)

Technology Diversity Risk:
• 6 Different Programming Languages
• 4 Database Systems (MySQL, PostgreSQL, MongoDB, Redis)
• 3 Frontend Frameworks (React, Angular, Vue)
• Multiple Authentication Systems (OAuth, SAML, LDAP)
```

### Analysis

**CWE Instance Counts:**
- ✅ YES - from `summary.security.top_weaknesses[].count`

**High Risk Technology Inventory:**
- ❌ NO - requires:
  - EOL detection (need external data: when did Java X reach EOL?)
  - Version comparison logic
  - "Outdated" definition (how old is outdated?)
  - "Unmaintained" detection (when was last update?)

**Technology Diversity Risk:**
- ⚠️ PARTIAL - we have tech list, but:
  - Need to extract programming language from tech data
  - Need to classify techs into categories (DB, frontend, auth)
  - This could be done with labels or slug patterns

**OPTIONS FOR HIGH RISK INVENTORY:**
1. **Remove it** - stick to vulnerability counts
2. **Add EOL data source** - integrate external EOL database
3. **Simple age heuristic** - flag techs with vulns > 2 years old
4. **Use AI to classify** - detect EOL/outdated (MUST FLAG)

**RECOMMENDATION:**
- Keep CWE instance counts (generatable)
- Remove "High Risk Technology Inventory" (not generatable without external data)
- Simplify "Technology Diversity" to just counts we can derive from labels

---

## LAYER 4: Data

### Content Example
```
Critical Business Assets:
• AI Model Training Data
• User Query History & Analytics
• Customer Account Information
• Proprietary Search Algorithms
• Competitive Intelligence Data

Industry: AI-Powered Search & Discovery
Estimated Breach Impact: $8-12M

Based on:
• Technology sector breach costs (IBM)
• Regulatory fines (GDPR, CCPA)
• Competitive damage to AI startup
• Customer trust loss
```

### Analysis

| Content | Generatable | Notes |
|---------|-------------|-------|
| Business assets list | ❌ NO | Requires industry knowledge |
| Industry name | ⚠️ PARTIAL | Need industry classification |
| Breach cost range | ❌ NO | Requires calculation + external data |
| Cost breakdown | ❌ NO | Requires external data (IBM report) |

**MAJOR ISSUE:** This entire layer is NOT in our scan data.

**This is business context, not technical data.**

**OPTIONS:**
1. **Remove this layer entirely**
2. **Add industry classification** - then use templates per industry
3. **Use AI to infer assets** (MUST FLAG AS AI)
4. **Make it generic** - remove industry specific assets

**BREACH COST CALCULATION:**

Could be formula based:
```
base_cost = IBM_sector_average
multiplier = f(vulnerability_count, kev_count, revenue_estimate)
range = base_cost * multiplier * (0.8 to 1.2)
```

But requires:
- External IBM report data
- Revenue estimation (how?)
- Multiplier formula (based on what research?)

**RECOMMENDATION:**

Either:
- **REMOVE Layer 4 entirely** - we're a technical scanner, not business analyst
- **Keep but make it generic** - remove industry specific details

Example generic version:
```
Your Data

Critical Business Assets:
• Customer data and personal information
• Business critical applications
• Proprietary systems and intellectual property
• Partner and vendor integrations

Potential Impact:
• Regulatory compliance violations
• Customer trust and reputation damage
• Business disruption costs
• Legal and remediation expenses
```

**NO SPECIFIC COSTS** - too much speculation.

---

## BRIDGE SECTION

### Content Example
```
Attack surface isn't risk surface.
TotalAppSec tells you real risk.

From 343 exposure signals to actionable priorities.
```

### Analysis

| Content | Generatable | Notes |
|---------|-------------|-------|
| First line | ✅ YES | Static tagline |
| Second line | ✅ YES | Static tagline |
| "343 exposure signals" | ✅ YES | `summary.security.total_vulnerabilities` |

**VERDICT: ✅ FULLY GENERATABLE**

---

## SUMMARY: What's Generatable vs Not

### ✅ FULLY GENERATABLE (No Changes Needed)

**Layer 1A (Basic):**
- Application counts by type
- Domain counts
- All numeric metrics

**Layer 3 (Technology):**
- Technology count
- Vulnerability counts and severity
- KEV counts
- Weakness patterns with names and counts

**Bridge:**
- All text (uses vuln count from data)

### ⚠️ PARTIALLY GENERATABLE (Needs Logic/Restructuring)

**Layer 2 (Infrastructure):**
- ✅ Technology instances and counts (have data)
- ⚠️ Category grouping (can use labels/slugs)
- ❌ "Weakness Patterns" count (BROKEN - conflicts with cve_applicable: false)

**Layer 1B (Internal Apps):**
- ⚠️ Industry name (need classification source)
- ❌ Benchmark ranges (need external data)
- ❌ Asset type bullets (need templates)

### ❌ NOT GENERATABLE (Requires Major Changes)

**Layer 1A (Extended - Qualys example):**
- Application category breakdown (Customer Facing, Legacy, etc.)

**Layer 2 (Extended):**
- Specific version details (Nginx 1.18.x)
- EOL detection
- "Outdated" classification

**Layer 3 (Extended):**
- High Risk Technology Inventory
- EOL version detection
- Technology diversity analysis (partial)

**Layer 4 (Data):**
- Business assets list
- Breach cost estimates
- Industry specific context

---

## CRITICAL FINDINGS

### 1. Layer 2 Infrastructure Weakness Count is BROKEN

The example shows:
```
POTENTIAL
└─ 3 Weakness Patterns Identified
   (Infrastructure components show
    no direct CVE applicability)
```

But if infrastructure components have `cve_applicable: false` AND `cwe_applicable: false`, then weakness patterns should be ZERO, not 3.

**This example content is INCONSISTENT with the data model.**

**FIX:** Remove weakness count, or fix data model to allow CWEs even when CVEs don't apply.

### 2. Industry Classification is Missing

Multiple layers assume we know the industry:
- Layer 1B: "AI/Technology companies typically..."
- Layer 4: "Industry: AI-Powered Search & Discovery"

**Where does industry classification come from?**

OPTIONS:
1. Manual input (user provides industry when scanning)
2. Auto detect from domain (lookup database)
3. Auto detect from content (AI analysis - MUST FLAG)
4. Skip industry specific content

### 3. Extended Examples Require Data We Don't Capture

The Qualys example includes:
- Application categorization (customer facing, legacy, internal)
- Technology versions (Nginx 1.18.x)
- EOL detection
- Specific CVE highlighting logic

These require either:
- Enhanced detection during scanning, OR
- External data sources (EOL databases, version databases), OR
- AI classification (MUST FLAG)

---

## RECOMMENDATIONS

### Option A: Minimal (Stick to What We Have)

**Keep:**
- Layer 1A (basic counts only)
- Layer 3 (full - it's perfect)
- Bridge (with vuln count)

**Remove:**
- Layer 1B (too speculative)
- Layer 2 (inconsistent with data model)
- Layer 4 (not technical data)

**Result:** Clean, data driven, no speculation.

### Option B: Enhanced (Add External Data)

**Keep everything but:**

**Add:**
1. Industry classification input
2. Industry benchmark lookup table (hardcoded ranges)
3. Industry template system (hardcoded asset lists)
4. Category grouping logic (use labels)

**Fix:**
- Layer 2 weakness count (remove or fix data model)

**Result:** Full featured but requires infrastructure.

### Option C: AI Assisted (Flag AI Content)

**Allow AI to:**
- Classify applications into categories
- Infer industry from content
- Generate business asset lists
- Estimate breach costs

**BUT:** Mark all AI generated content with clear indicator:
- "✨ AI Generated Insight"
- Different styling
- Disclaimer about accuracy

**Result:** Feature complete but with AI dependency clearly marked.

---

## MY RECOMMENDATION

**Go with Option A (Minimal) initially:**

1. Layer 1A: Basic counts (fully generatable)
2. Layer 3: Full technology analysis (fully generatable)
3. Bridge: Use vulnerability count (fully generatable)

**Skip for now:**
- Layer 1B (needs external data)
- Layer 2 (inconsistent with data model)
- Layer 4 (not technical)

**This gives us:**
- 100% accurate, data backed content
- No speculation or estimates
- No AI required
- Clean, focused message

**Then, incrementally add:**

Phase 2: Layer 2 with category grouping (use labels)
Phase 3: Layer 1B with industry classification system
Phase 4: Layer 4 with industry templates

---

## NEXT STEPS

1. **Clarify data model questions:**
   - Do we capture technology versions?
   - Is there industry classification anywhere?
   - Should infrastructure have CWEs?

2. **Decide on approach:**
   - Minimal (Option A)
   - Enhanced (Option B)
   - AI Assisted (Option C)

3. **Design generation logic:**
   - Template engine
   - Data mapping
   - Grouping/categorization rules

4. **Validate with real data:**
   - Test with perplexity.ai
   - Test with other domains
   - Check edge cases
