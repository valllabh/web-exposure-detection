# Development Guide

## Prerequisites

- Go 1.21 or later
- Make (for build automation)

## Development Commands

All development tasks are managed through the Makefile. Reference it for available commands:

- `make build` - Build the binary
- `make test` - Run tests
- `make clean` - Clean build artifacts
- `make deps` - Install/update dependencies
- `make lint` - Run linters

## Running Locally

Use `go run .` to run the entire package (not `go run main.go`):

```bash
# Run help
go run . --help

# Run scan command
go run . scan example.com

# Run with options
go run . scan example.com --domain-keywords additional,keywords --force
```

**Important**: Always run the entire package with `go run .` to ensure all package files are included.

## Project Structure

```
.
├── cmd/                      # CLI commands (Cobra)
│   └── web-exposure-detection/
├── pkg/
│   └── webexposure/          # SDK public API
│       ├── common/           # Common types (scanner, report, pdf)
│       ├── scanner/          # Scanner orchestration and discovery
│       ├── report/           # Report generation (HTML, PDF)
│       ├── nuclei/           # Nuclei integration and DSL
│       ├── findings/         # Findings and criticality types
│       ├── industry/         # Industry classification
│       │   └── prompts/      # Industry classification AI prompts
│       ├── criticality/      # Criticality calculation
│       ├── truinsights/      # TRU threat intelligence
│       │   └── prompts/      # Threat assessment AI prompts
│       ├── ai/               # AI provider adapters
│       └── logger/           # Logger utilities
├── internal/                 # Private implementation
├── scan-templates/           # Nuclei templates (embedded)
├── templates/                # Report templates (embedded)
├── docs/                     # Documentation
├── ref/                      # Reference bash implementation
└── embed.go                  # Embedded file systems
```

### Package Organization Rules

Follow these rules when organizing code:

**1. Package Naming**
- Type files must have descriptive names: `scanner.go`, `report.go`, `pdf.go`
- Never use generic `types.go` - use `{feature}_types.go` instead
- Example: `nuclei_types.go`, not `types.go`

**2. Package Grouping**
- **Discovery** is part of scanner (separate concern within scanner package)
- **PDF and HTML** are both part of report package
- **DSL** is nuclei related (part of nuclei package)
- **Common** package contains shared types across packages

**3. Type Organization**
- All common types go in `common/` package
- Feature-specific types stay with their feature
- Separate files by concern: `scanner.go`, `report.go`, `pdf.go`

**4. Package Dependencies**
```
cmd → pkg/webexposure → scanner → report
                      → common
                      → nuclei
                      → findings
                      → industry
                      → criticality
                      → logger
```

## Testing

```bash
# Run all tests
make test

# Run with coverage
go test -cover ./...

# Run specific package
go test ./pkg/webexposure
```

## Updating CVE Statistics

Update CVE data for findings:

```bash
make update-cve-stats
```

See [how-to-write-nuclei-template.md](./how-to-write-nuclei-template.md#cve-statistics) for details.

## Architecture Overview

### Unified Pipeline

The tool uses a single unified pipeline (`RunCompletePipeline`) that executes all operations with intelligent caching:

**Command Structure:**
- `scan` - Complete pipeline (discovery, scanning, TRU insights, reports)
- `discover` - Domain discovery only (optional, for pre-caching)
- `classify` - Industry classification only (optional, standalone utility)

**Pipeline Flow:**
```
scan command → RunCompletePipeline() → All 7 subflows in sequence
                                        ├─ Discovery Subflow (cached)
                                        ├─ Industry Classification Subflow (cached)
                                        ├─ Nuclei Scan Subflow (cached)
                                        ├─ TRU Insights Subflow (cached)
                                        ├─ Report JSON Subflow (cached)
                                        ├─ HTML Subflow (cached)
                                        └─ PDF Subflow (cached)
```

**Key Principles:**
- Each subflow checks its cache before executing
- Force flag bypasses all caches
- Dependencies automatically resolved (subflows call other subflows)
- Non-blocking steps (industry, TRU insights, HTML, PDF) fail gracefully

**Implementation Location:** `pkg/webexposure/scanner/flow_unified.go`

### Caching Strategy

Each subflow follows this pattern:

```go
func (s *scanner) runXSubflow(domain string, force bool, ...) (*Result, error) {
    cacheFile := filepath.Join("results", domain, "cache-file.json")

    // Step 1: Check cache (unless force=true)
    if !force {
        if cachedData := loadFromCache(cacheFile); cachedData != nil {
            return cachedData, nil
        }
    }

    // Step 2: Call dependency subflows (with same force flag)
    dependency, err := s.runDependencySubflow(domain, force, ...)

    // Step 3: Execute this subflow's work
    result := doWork(dependency)

    // Step 4: Save to cache
    saveToCache(cacheFile, result)

    return result, nil
}
```

This allows running scan command multiple times instantly (uses cache) unless `--force` is specified.

## Adding Features

1. Implement in SDK (`pkg/webexposure`) first
2. Add CLI facade in `cmd/`
3. Update relevant docs in `docs/`
4. Add tests
5. Update CLAUDE.md references if needed

### Adding New Findings

When adding new findings to `pkg/webexposure/findings/findings.json`:

**Critical:** Always add the `classification` field for findings that indicate application type:

```json
{
  "your.new.finding": {
    "slug": "your.new.finding",
    "display_name": "Your Finding Name",
    "icon": "icon.svg",
    "show_in_tech": true,
    "classification": ["webapp"],  // Required for proper classification
    "description": "Description of the finding"
  }
}
```

**Classification Categories:**
- `["webapp"]` - Authentication, frontend/backend frameworks, CMS
- `["api"]` - API servers, API patterns, JSON/XML endpoints
- `["api-spec"]` - OpenAPI, Swagger, Postman collections
- `["ai"]` - MCP servers, vector databases, AI endpoints
- No classification - Security headers, page metadata, infrastructure checks

**Why this matters:** Findings without proper classification cause domains to be categorized as "Other" instead of their correct type.

See [reporting-system.md](./reporting-system.md#adding-new-findings) for complete classification requirements.

## Embedded Resources

When adding/modifying embedded resources:

1. Add files to appropriate directory (`scan-templates/`, `templates/`)
2. Verify `embed.go` includes the path
3. Rebuild to embed new files

## AI Prompts Organization

AI prompts are embedded within their respective packages for maintainability and encapsulation.

### Prompt Locations

```
pkg/webexposure/
├── industry/
│   └── prompts/
│       └── industry-classification.md    # Industry classification prompt
└── truinsights/
    └── prompts/
        └── threat-landscape.md            # Threat assessment prompt
```

### Embedding Strategy

Each package that uses AI prompts embeds its own prompts:

**Industry Package** (`pkg/webexposure/industry/prompts.go`):
```go
//go:embed prompts/*.md
var promptsFS embed.FS
```

**TRU Insights Package** (`pkg/webexposure/truinsights/truinsights.go`):
```go
//go:embed prompts/*.md
var promptsFS embed.FS
```

### Adding/Modifying Prompts

1. **Locate the prompt file** in the appropriate package's `prompts/` directory
2. **Edit the markdown file** with your changes
3. **Rebuild** the binary to embed the updated prompt:
   ```bash
   make build
   ```

### Prompt File Format

All prompts are markdown files with:
- Clear role definition
- Structured input expectations
- Detailed output requirements
- Examples and validation rules

Example structure:
```markdown
# Prompt Title

## Your Role
[Define the AI's role and objectives]

## Input Data
[Describe expected inputs]

## Output Format
[Specify exact output format, usually JSON]

## Examples
[Provide concrete examples]

## Validation
[List validation requirements]
```

### Testing Prompts

After modifying prompts:

1. Rebuild: `make build`
2. Run relevant command (e.g., `./bin/web-exposure-detection scan domain.com`)
3. Verify output quality and format
4. Check for API errors or timeout issues

## Code Style

- Follow standard Go conventions
- Use `make lint` before committing
- Keep SDK and CLI concerns separated
- Document exported functions

## Package Organization Guide

### Core Packages

#### pkg/webexposure/common/
Contains shared types used across multiple packages.

Files:
- `scanner.go` - Scanner interface, ProgressCallback, ScanPreset
- `report.go` - ExposureReport, ReportMetadata, Summary, DomainMetrics
- `pdf.go` - PDFGenerator interface, PDFGeneratorType

Rules:
- Only types that are used by 2+ packages
- No implementation logic
- Types only

#### pkg/webexposure/scanner/
Main scanner orchestration with subflow-based architecture.

Files:
- `scanner.go` - Legacy scan methods, template management
- `scanner_impl.go` - Scanner struct implementation
- `discovery.go` - Domain discovery helpers
- `nuclei.go` - Nuclei scan helpers
- `flow_unified.go` - Unified pipeline (RunCompletePipeline)
- `subflow_discovery.go` - Discovery subflow with caching
- `subflow_industry.go` - Industry classification subflow
- `subflow_nuclei.go` - Nuclei scan subflow with caching
- `subflow_tru_insights.go` - TRU insights generation subflow
- `subflow_report_json.go` - JSON report generation subflow
- `subflow_html.go` - HTML report generation subflow
- `subflow_pdf.go` - PDF report generation subflow

Responsibilities:
- Unified pipeline orchestration (flow_unified.go)
- Subflow execution with intelligent caching
- Domain discovery and protocol handling
- Nuclei scan coordination
- Template validation
- Progress tracking

**Architecture:** Each subflow is self-contained with cache checking, dependency resolution, execution, and cache saving. Subflows call other subflows as dependencies, creating a nested (Russian doll) pattern.

#### pkg/webexposure/report/
All report generation (HTML and PDF).

Files:
- `report.go` - Report generation logic, metrics calculation
- `report_html.go` - HTML report generation, template rendering
- `pdf.go` - PDF generator factory
- `report_pdf_rod.go` - Chrome-based PDF generation
- `report_pdf_playwright*.go` - Playwright-based PDF generation

Responsibilities:
- Generate ExposureReport from scan results
- HTML report generation with embedded assets
- PDF generation from HTML (multiple implementations)
- Domain metrics calculation

#### pkg/webexposure/nuclei/
Nuclei integration and DSL functions.

Files:
- `nuclei_types.go` - Nuclei options and configuration
- `nuclei_results.go` - Result processing and storage
- `nuclei_results_types.go` - Result type definitions
- `dsl.go` - DSL helper functions for templates

Responsibilities:
- Nuclei SDK integration
- Result event processing
- Template DSL functions
- Finding extraction from responses

#### pkg/webexposure/findings/
Finding types and criticality definitions.

Files:
- `findings.go` - Finding item creation and management
- `findings_types.go` - Discovery, APIFinding, WebAppFinding
- `criticality_types.go` - Criticality, CriticalityFactor

#### pkg/webexposure/industry/
Industry classification via LLM API.

Files:
- `industry_api.go` - Industry classification logic
- `industry_types.go` - IndustryClassification types

#### pkg/webexposure/criticality/
Criticality calculation engine.

Files:
- `criticality.go` - Rule-based criticality calculation

#### pkg/webexposure/logger/
Logger utilities wrapper.

Files:
- `logger.go` - GetLogger() wrapper for gologger

### Package Organization Principles

**Separation of Concerns**
- Discovery is scanner concern (stays in scanner/)
- PDF and HTML are report concerns (both in report/)
- DSL is nuclei concern (stays in nuclei/)

**Type Files**
- Never use `types.go` alone
- Use descriptive names: `nuclei_types.go`, `findings_types.go`
- Common types go in `common/` package

**Package Cohesion**
- Group related functionality together
- PDF/HTML both generate reports → same package
- DSL helps with nuclei templates → same package
- Discovery helps with scanning → same package

**Examples**

When adding new functionality:

```go
// ✅ CORRECT: PDF in report package
package report

func (g *RodPDFGenerator) GeneratePDF(htmlPath, pdfPath string) error {
    // PDF generation logic
}

// ✅ CORRECT: Discovery in scanner package
package scanner

func (s *scanner) DiscoverDomains(domains []string, keywords []string) ([]string, error) {
    // Discovery logic
}

// ✅ CORRECT: Common types in common package
package common

type Scanner interface {
    Scan(domains []string, keywords []string) error
}

// ❌ WRONG: Generic types.go file
// types.go  // Don't use this

// ✅ CORRECT: Descriptive type file names
// nuclei_types.go
// findings_types.go
```
