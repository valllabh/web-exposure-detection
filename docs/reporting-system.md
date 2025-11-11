# Reporting System Architecture

## Overview

The reporting system provides a complete end-to-end pipeline that transforms raw Nuclei scan results into multiple output formats. It generates JSON, HTML, and PDF reports using a sophisticated template-based processing system with comprehensive analysis of web exposure vulnerabilities and clear API vs Web Application classification.

## Report Output Formats

The system generates reports in three formats:

1. **JSON Report** - Structured data following schema v1
2. **HTML Report** - Interactive web report with assets
3. **PDF Report** - Print-ready document generated from HTML

## Complete End-to-End Flow

### Full Report Generation Pipeline

```
Scan Command Flow:
1. Domain Discovery → Nuclei Scan → Raw Results
2. Hand off to → generateReportsFromNucleiResults()

Report Command Flow:
1. Load existing Nuclei results → generateReportsFromNucleiResults()

generateReportsFromNucleiResults() (Single Entry Point):
1. AggregateResults() → GroupedResults (domain+template mapping)
2. GenerateReport() → ExposureReport (JSON structure)
3. writeJSONToResults() → results/domain/web-exposure-result.json
4. generateHTMLReport() → results/domain/report/index.html + assets/
5. generatePDF() → results/domain/domain-web-exposure-report.pdf
6. cleanup: Remove HTML report directory after successful PDF generation
```

### Directory Structure Output

After complete scan, the system creates:
```
results/example-com/
├── domain-discovery-result.json        # Cached domain discovery results (full AssetDiscoveryResult)
├── nuclei-results/
│   └── results.json                   # Raw Nuclei scan results
├── web-exposure-result.json           # Final JSON report (schema v1)
└── example-com-web-exposure-report.pdf # PDF report

# Note: HTML report directory (report/) is automatically cleaned up after PDF generation
```

**Important:** The HTML report directory is temporary and gets automatically deleted after successful PDF generation to keep only essential files.

## Core Components

### Data Flow Pipeline

```
Scan: Domain Discovery → Nuclei Scan → generateReportsFromNucleiResults()
Report: Load Cached Results → generateReportsFromNucleiResults()

generateReportsFromNucleiResults():
Nuclei Results → AggregateResults() → GenerateReport() → Multi-Format Output + Cleanup
```

**Key Files:**
- `pkg/webexposure/scanner.go` - Scanning logic + report orchestration
- `pkg/webexposure/report.go` - Report structure generation
- `pkg/webexposure/report_html.go` - HTML report generation with embedded templates
- `pkg/webexposure/report_pdf.go` - PDF generation from HTML
- `pkg/webexposure/scanner_types.go` - Data structures and interfaces
- `pkg/webexposure/findings.json` - Finding metadata (display names, icons, classifications)
- `embed.go` - Embedded scan-templates and templates filesystems

### Result Processing Architecture

The system uses a single-pass processing architecture for efficiency:

```go
// Single pass through all domains
func (rp *ResultProcessor) ProcessAllDomains(grouped *GroupedResults) *ExposureReport
```

**Processing Steps:**
1. **Result Aggregation** - Groups results by `domain+template`
2. **Finding Extraction** - Extracts findings from Nuclei results (already populated by templates)
3. **Classification** - Categorizes domains as APIs, Web Apps, AI Assets, or API Specs
4. **Technology Extraction** - Normalizes and deduplicates technologies
5. **Report Generation** - Builds final JSON structure

## Findings System

### How Findings Work

Nuclei templates emit structured findings using `to_value_group()` DSL function:

```yaml
extractors:
  - type: dsl
    dsl:
      - 'len(nginx) > 0 ? to_value_group("gateway.nginx", nginx) : ""'
```

This creates a findings map with hierarchical keys:
```json
{
  "host": "example.com",
  "template-id": "api-gateway-detection",
  "findings": {
    "gateway.nginx": ["nginx/1.21.0"]
  }
}
```

### Finding Metadata

`findings.json` contains all display metadata for each finding slug:

```json
{
  "gateway.nginx": {
    "slug": "gateway.nginx",
    "display_name": "Nginx",
    "icon": "nginx.svg",
    "classification": ["gateway", "webapp", "~api"],
    "show_in_tech": true,
    "display_as": "tag"
  }
}
```

**Fields:**
- `slug` - Hierarchical key matching template output
- `display_name` - Human-readable name for UI
- `icon` - SVG icon filename
- `classification` - Tags for filtering (prefix `~` means display-only, not for classification)
- `show_in_tech` - Show in technologies section
- `display_as` - Rendering style: `tag` or `link`

### Adding New Findings

When adding new findings to `findings.json`, ensure proper classification to avoid misclassification:

**Classification Requirements:**

1. **Authentication Related Findings** - Must have `"classification": ["webapp"]`
   - Traditional login forms (`auth.traditional.*`)
   - Enterprise SSO (`auth.enterprise.*`)
   - Social login (`auth.social.*`)
   - MFA and passwordless auth

2. **Frontend/Backend Technologies** - Must have `"classification": ["webapp"]`
   - Frontend frameworks (React, Angular, Vue, etc.)
   - Backend frameworks (Laravel, Django, Rails, etc.)
   - CMS systems (WordPress, Drupal, etc.)

3. **API Related Findings** - Must have `"classification": ["api"]`
   - API servers and frameworks
   - API domain patterns
   - JSON/XML endpoints

4. **API Specifications** - Must have `"classification": ["api-spec"]`
   - OpenAPI/Swagger
   - Postman collections
   - WADL/WSDL

5. **AI Related Findings** - Must have `"classification": ["ai"]`
   - MCP servers
   - Vector databases
   - AI endpoints

6. **Infrastructure** - Should NOT have classification field
   - Security headers (all `security.*`)
   - Page metadata (`page.title`, `page.description`)
   - Server information

**Impact:** Findings without proper classification cause domains to be categorized as "Other" instead of their correct type (Web App, API, AI Asset, or API Spec).

**Example:**
```json
{
  "auth.traditional.basic_auth": {
    "slug": "auth.traditional.basic_auth",
    "display_name": "Traditional Login",
    "icon": "traditional-login-forms.svg",
    "show_in_tech": false,
    "classification": ["webapp"],  // REQUIRED for proper classification
    "description": "Traditional username and password authentication forms."
  }
}
```

## Classification Logic

### API Classification Rules

APIs are classified into two categories based on detection confidence:

#### Confirmed API Endpoint

A domain is classified as **"Confirmed API Endpoint"** when it serves structured data:

- Detection of `api.server.json` (JSON API detection)
- OR detection of `api.server.xml` (XML API detection)

**Rationale:** Domains actively serving JSON or XML responses demonstrate confirmed API behavior through response content analysis.

**Priority:** If both `api.domain_pattern` and `api.server.json`/`api.server.xml` are present, the domain is still classified as **Confirmed API Endpoint** (server detection takes precedence).

#### Potential API Endpoint

A domain is classified as **"Potential API Endpoint"** when only domain naming patterns suggest API usage:

- Detection of `api.domain_pattern` only (API keyword in domain name)
- WITHOUT `api.server.json` or `api.server.xml`

**Rationale:** Domain naming conventions (e.g., api.example.com, example.com/api) suggest API usage but require response content confirmation.

#### Classification Logic Implementation

```go
func (rp *ResultProcessor) classifyAsAPI(templates map[string]*StoredResult) string {
    hasServerDetection := false
    hasDomainPattern := false

    for _, template := range templates {
        if template.Findings != nil {
            for slug := range template.Findings {
                if slug == "api.server.json" || slug == "api.server.xml" {
                    hasServerDetection = true
                }
                if slug == "api.domain_pattern" {
                    hasDomainPattern = true
                }
            }
        }
    }

    if hasServerDetection {
        return "Confirmed API Endpoint"
    }
    if hasDomainPattern {
        return "Potential API Endpoint"
    }
    return ""
}
```

### Web App Classification

Web applications are identified by:
- **Backend/Frontend frameworks:** Classified as WebApp
- **Web indicators:** `website-host-detection`, `xhr-detection-headless`, etc.

### Classification Priority Order

1. **JSON/XML serving** → Confirmed API Endpoint
2. **API domain pattern only** → Potential API Endpoint
3. **Backend/Frontend tech present** → WebApp
4. **Other web indicators** → WebApp

### Discovery Details Updates

**Blank Root Detection:**
- `blank-root-server-detection` template detects routing servers and blank pages
- Results stored in `server.blank_root_status` finding key
- Filtered from display in final reports

**SPA Framework API Usage:**
- Frontend frameworks (Angular, React, Vue, Next.js, Nuxt, Svelte) indicate API usage
- Frontend technologies classified with "webapp" in findings.json

### UI Status Indicators

**Status Column Removed:**
- HTML report no longer shows separate Status column
- Status now indicated by colored circles before domain names in API Endpoints table:
  - Green circle: "Confirmed API Endpoint"
  - Yellow circle: "Potential API Endpoint"

### Report Sections

**Application Exposure:**
- Renamed from "Asset Inventory"
- Shows 4 summary cards in uniform width grid layout: API Servers, API Specifications, AI Apps, Web Apps
- Cards use gradient background without box shadow for clean appearance
- Label font size: 12px (text-xs) for compact uniform appearance
- Layout: Tailwind CSS grid (grid-cols-4) for equal width distribution

**Technology Exposure:**
- Displays first 4 technologies with icons and counts
- Shows additional count badge (e.g., "9+ Additional") if more than 4 technologies detected
- Matches styling of Application Exposure section (same padding, border radius, colors)

**Legend Positioning:**
- Asset Criticality Score legend appears above each table section
- API Status legend only appears above API Endpoints table
- Compact inline format: "Highest 5 4 3 2 1 Lowest"

**Table Styling:**
- Criticality column values aligned to top
- All inline styles moved to CSS classes for maintainability

**TruRisk Range:**
- Predictive risk scoring (0-1000 scale) displayed as numeric ranges (e.g., "536-820")
- Replaces Headers Grade column in all asset tables
- Color coded using Qualys standards (red for 850-1000, orange for 650-849, etc.)
- Assets sorted by TruRisk Max score descending (highest risk first)
- Calculated based on Asset Criticality Score, technology vulnerabilities, KEV data, and environmental factors
- See [trurisk-range.md](./trurisk-range.md) for complete methodology
- Note: Ranges subject to recalibration based on real-world validation

### Technology Extraction

Technologies are extracted from specific templates and normalized:

**Technology Templates:**
- `website-host-detection` - Web servers, CDNs
- `backend-framework-detection` - Backend frameworks
- `frontend-tech-detection` - Frontend technologies
- `xhr-detection-headless` - API usage patterns

**Normalization Process:**
1. Convert to lowercase
2. Remove version numbers (`v1.2.3`, `1.2.3`)
3. Clean JSON array artifacts
4. Filter out URLs and file paths
5. Map common patterns:
   - `nginx` → `nginx`
   - `react` → `react`
   - `wordpress` → `wordpress`

## Report Schema (v1)

### Final JSON Structure

```json
{
    "schema_version": "v1",
    "report_metadata": {
        "title": "External Application Discovery for example.com",
        "date": "2025-01-15",
        "target_domain": "example.com",
        "timestamp": "2025-01-15T10:30:00Z"
    },
    "summary": {
        "total_domains": 36,
        "live_exposed_domains": 17,
        "total_detections": 13,
        "apis_found": 3,
        "api_specifications_found": 1,
        "web_apps_found": 10,
        "domains_using_api": 2
    },
    "technology_exposure": {
        "count": 7,
        "technologies": ["nginx", "wordpress", "angular"]
    },
    "apis_found": [
        {
            "domain": "api.example.com",
            "discovered": "Potential API Endpoint",
            "findings": ["API Spec Found at https://api.example.com/docs"]
        }
    ],
    "web_applications_found": [
        {
            "domain": "www.example.com",
            "discovered": "Web App",
            "findings": ["Web Server", "Using WordPress"]
        }
    ]
}
```

### Summary Calculations

**Live Exposed Domains** - Domains with any findings
**Total Detections** - Sum of all detection template matches
**API Specifications Found** - Domains with API spec detections
**Domains Using API** - Web apps with API usage indicators or frontend frameworks

## Result Aggregation

### Grouping Logic

Results are grouped by domain and template for efficient processing:

```go
func (s *scanner) AggregateResults(results []*output.ResultEvent) (*GroupedResults, error) {
    grouped := make(map[string]map[string]*output.ResultEvent)
    for _, result := range results {
        grouped[result.Host][result.TemplateID] = result
    }
    return &GroupedResults{Domains: grouped}, nil
}
```

This structure enables:
- Fast template-based classification
- Efficient deduplication
- Single-pass processing

### Finding Cleanup

The system applies cleanup rules to findings:
- Remove "Live Domain" if other findings exist
- Filter "Web Server" from API findings
- Sort all findings alphabetically

## Extension Points

### Adding New Templates

1. Add Nuclei template to `scan-templates/` directory with `to_value_group()` DSL extractors
2. Add finding metadata to `findings.json` with matching slug
3. Update classification logic in `report.go` if new categories required
4. Add SVG icon to `templates/assets/` if needed

## Report Format Details

### JSON Report (`writeJSONToResults`)

**Output:** `results/{domain}/web-exposure-result.json`
- Structured JSON following schema v1
- Primary data source for HTML/PDF generation
- Used for programmatic consumption

### HTML Report (`generateHTMLReport`) - Temporary

**Output:** `results/{domain}/report/index.html` + assets directory (temporary)

**Process:**
1. Extracts embedded `templates/assets/` → `results/{domain}/report/assets/`
2. Processes embedded `templates/report.html` with Go templates
3. Injects ExposureReport data into HTML template
4. Creates self-contained report directory
5. **Automatically deleted after PDF generation**

**Embedded Assets Include:**
- Technology icons (17 SVG files): nginx, react, angular, wordpress, etc.
- Qualys branding logo
- CSS styles optimized for print and web

**HTML Template Features:**
- Responsive design with Montserrat font
- Print-optimized CSS with `@page` and `@media print` rules
- Technology icons for visual identification
- Structured sections matching JSON schema
- Tailwind CSS for styling with utility classes
- Grid based layout for uniform card widths
- Clean design without box shadows on metric cards

### PDF Report (`generatePDF`)

**Output:** `results/{domain}/{domain}-web-exposure-report.pdf`

**Process:**
1. Launches headless Chrome browser using Rod library
2. Loads HTML report via `file://` URL
3. Applies PDF print settings (A4, margins, background colors)
4. Generates PDF with 30-second timeout
5. Saves to results directory

**PDF Settings:**
- Paper: A4 (8.27" x 11.69")
- Margins: 0.39" on all sides
- Scale: 100%
- Print backgrounds: enabled
- Color adjustment: exact

## Embedded Architecture

### No External Dependencies

The system uses Go's `embed` package to include all external files in the binary:

**Embedded in Binary:**
- ✅ `scan-templates/` - Nuclei YAML templates
- ✅ `templates/report.html` - HTML report template
- ✅ `templates/assets/` - SVG technology icons + logo
- ✅ `pkg/webexposure/findings.json` - Finding metadata (display names, icons, classifications)

**Runtime Process:**
1. **Scan Templates:** Extracted to temporary directory for Nuclei
2. **HTML Template:** Loaded from embedded filesystem
3. **Assets:** Copied from embedded filesystem to report directory
4. **Cleanup:** Temporary files removed after PDF generation

**Distribution:** Single standalone binary with zero external file dependencies.

## CLI Integration

Both scan and report commands generate all three formats:

```bash
# Full scan with all formats
web-exposure-detection scan example.com

# Report regeneration from existing results
web-exposure-detection report example.com
```

**Scan Command Flow:**
1. Domain discovery with caching
2. Nuclei vulnerability scanning
3. Result aggregation and processing
4. JSON → HTML → PDF generation

**Report Command Flow:**
1. Load existing Nuclei results from cache
2. Regenerate reports in all formats
3. Useful for template updates or format changes

## Error Handling

The system uses graceful degradation:
- JSON generation failure stops pipeline
- HTML generation failure warns but continues to PDF
- PDF generation failure warns but doesn't affect JSON/HTML
- Missing templates directory prevents HTML/PDF generation

## Testing Helpers

The scanner exposes testing methods:
- `CountIssues()` - Count domains matching template keys
- `NormalizeAndClean()` - Apply bash regex transformations
- `WriteJSONReport()` - Direct JSON report writing for testing