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
1. Domain Discovery → Nuclei Scan → Raw Results
2. AggregateResults() → GroupedResults (domain+template mapping)
3. GenerateReport() → ExposureReport (JSON structure)
4. writeJSONToResults() → results/domain/web-exposure-result.json
5. generateHTMLReport() → results/domain/report/index.html + assets/
6. generatePDF() → results/domain/domain-web-exposure-report.pdf
```

### Directory Structure Output

After complete scan, the system creates:
```
results/example-com/
├── domain-scan.json              # Cached domain discovery results
├── nuclei-results/
│   └── results.json             # Raw Nuclei scan results
├── web-exposure-result.json     # Final JSON report (schema v1)
├── report/                      # HTML report directory
│   ├── index.html              # Main HTML report
│   └── assets/                 # CSS, JS, images, icons
│       ├── angular.svg
│       ├── nginx.svg
│       ├── qualys-logo.svg
│       └── [17 technology icons]
└── example-com-web-exposure-report.pdf  # PDF report
```

## Core Components

### Data Flow Pipeline

```
Nuclei Results → AggregateResults() → GenerateReport() → Multi-Format Output
```

**Key Files:**
- `pkg/webexposure/report.go` - Main report generation logic
- `pkg/webexposure/types.go` - Data structures and interfaces
- `pkg/webexposure/scan-template-meanings.json` - Template configuration with DSL

### Result Processing Architecture

The system uses a single-pass processing architecture for efficiency:

```go
// Single pass through all domains
func (rp *ResultProcessor) ProcessAllDomains(grouped *GroupedResults) *ExposureReport
```

**Processing Steps:**
1. **Result Aggregation** (`scanner.go:518`) - Groups results by `domain+template`
2. **Template Processing** - Applies DSL templates to extract findings
3. **Classification** - Categorizes domains as APIs or Web Apps
4. **Technology Extraction** - Normalizes and deduplicates technologies
5. **Report Generation** - Builds final JSON structure

## Template DSL System

### Template Types

The system uses Go `text/template` with Sprig functions to process Nuclei `ResultEvent` objects:

**Detection Templates** - Categorize findings:
```json
"detection_template": ["Web App", "Web Server"]
```

**Finding Templates** - Generate human-readable descriptions:
```json
"finding_template": [
    "Web Server",
    "{{if .ExtractedResults}}{{range $i, $v := .ExtractedResults}}{{if $i}}, {{end}}{{$v}}{{end}}{{end}}"
]
```

### Template Configuration

Each template in `scan-template-meanings.json` defines:

```json
{
    "template-id": {
        "label": "Human-readable name",
        "detection_template": ["Category", "Specific detection"],
        "finding_template": ["Finding description", "{{DSL expression}}"]
    }
}
```

### DSL Context

Templates receive Nuclei `ResultEvent` objects with access to:
- `.ExtractedResults` - Array of extracted values
- `.Matched` - Matched content/URL
- `.Host` - Target host
- `.TemplateID` - Template identifier

## Classification Logic

### API Classification Rules (Updated)

The classification system enforces **mutual exclusivity** between APIs and Web Apps with strict priority rules:

**Backend/Frontend Technology Override:**
- Any domain with `backend-framework-detection` OR `frontend-tech-detection` is **always classified as WebApp**
- This takes absolute precedence over all API indicators including JSON/XML serving

**API Server Detection:**
- Domains serving JSON/XML (`api-server-detection`) are classified as **"Confirmed API Endpoint"**
- Only applies if no backend/frontend tech is present

**API Specification Detection:**
- API specs (`openapi`, `swagger-api`, `wadl-api`, `wsdl-api`) are classified as **"Potential API Endpoint"** (not "Confirmed")
- Only applies if no backend/frontend tech is present

**API Keyword/Routing Detection:**
- Domains with `api-host-keyword-detection` are classified as **"Potential API Endpoint"**
- **Blank-root exclusion:** Domains with ONLY `blank-root-server-detection` (no other API indicators) are NOT classified as APIs
- This prevents false positives like "client-uat-p.ssga.com"

### Web App Classification

Web applications are identified by:
- **Backend/Frontend frameworks:** Always classified as WebApp regardless of other indicators
- **Web indicators without API server:** `website-host-detection`, `xhr-detection-headless`, etc.
- **JSON/XML exclusion:** Domains serving JSON/XML are APIs unless backend/frontend tech is present

### Classification Priority Order

1. **Backend/Frontend tech present** → WebApp (overrides everything)
2. **JSON/XML serving without backend/frontend** → Confirmed API
3. **API specs without backend/frontend** → Potential API
4. **Other web indicators without JSON/XML** → WebApp
5. **API keywords without backend/frontend** → Potential API (excluding blank-root-only)

### Discovery Details Updates

**"Routing Server" Removal:**
- `blank-root-server-detection` template now has empty `finding_template`
- "Routing Server" no longer appears in discovery details

**SPA Framework API Usage:**
- Frontend frameworks (Angular, React, Vue, Next.js, Nuxt, Svelte) automatically add "Using APIs" to findings
- Updated via DSL expression in `frontend-tech-detection` template:
```json
"{{if .ExtractedResults}}{{range $v := .ExtractedResults}}{{if or (contains (lower $v) \"angular\") (contains (lower $v) \"react\") (contains (lower $v) \"vue\") (contains (lower $v) \"next.js\") (contains (lower $v) \"nuxt\") (contains (lower $v) \"svelte\")}}Using APIs{{end}}{{end}}{{end}}"
```

### UI Status Indicators

**Status Column Removed:**
- HTML report no longer shows separate Status column
- Status now indicated by colored circles before domain names:
  - 🔴 Red circle: "Confirmed API Endpoint"
  - 🟡 Yellow circle: "Potential API Endpoint"

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
    "technologies_detected": {
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

1. Add template to `scan-templates/` directory
2. Define meanings in `scan-template-meanings.json`
3. Add to technology templates list if needed (`report.go:299`)
4. Update classification logic if new categories required

### Custom DSL Functions

The template system supports all Sprig functions plus standard Go template functions for complex processing needs.

## Report Format Details

### JSON Report (`writeJSONToResults`)

**Output:** `results/{domain}/web-exposure-result.json`
- Structured JSON following schema v1
- Primary data source for HTML/PDF generation
- Used for programmatic consumption

### HTML Report (`generateHTMLReport`)

**Output:** `results/{domain}/report/index.html` + assets directory

**Process:**
1. Copies `templates/assets/` → `results/{domain}/report/assets/`
2. Processes `templates/report.html` with Go templates
3. Injects ExposureReport data into HTML template
4. Creates self-contained report directory

**Assets Include:**
- Technology icons (17 SVG files): nginx, react, angular, wordpress, etc.
- Qualys branding logo
- CSS styles optimized for print and web

**HTML Template Features:**
- Responsive design with Montserrat font
- Print-optimized CSS with `@page` and `@media print` rules
- Technology icons for visual identification
- Structured sections matching JSON schema

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
- `ClassifyAsAPI()` / `ClassifyAsWebApp()` - Direct classification testing
- `WriteJSONReport()` - Direct JSON report writing for testing