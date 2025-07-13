# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go-based CLI tool for detecting web exposure vulnerabilities using:
- **Cobra** for CLI framework
- **Viper** for configuration management  
- **Nuclei v3 SDK** for vulnerability scanning
- **Domain-scan** for subdomain discovery (placeholder - requires integration)

The tool is designed for defensive security purposes to identify potential web exposure vulnerabilities and misconfigurations.

## Development Commands

### Build and Run
```bash
# Build the application
go build -o bin/web-exposure-detection ./main.go

# Run directly with go
go run main.go

# Run with arguments
go run main.go --help
go run main.go scan example.com
go run main.go scan example.com --keywords "staging,prod"
```

### Testing
```bash
# Run all tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Run tests with coverage
go test -cover ./...

# Run specific package tests
go test ./pkg/webexposure -v
```

### Development Tools
```bash
# Format code
go fmt ./...

# Lint code (requires golangci-lint)
golangci-lint run

# Vet code for common mistakes
go vet ./...

# Download dependencies
go mod download

# Clean up dependencies
go mod tidy

# Update dependencies
go get -u ./...
```

### Makefile Commands
```bash
# Build the application
make build

# Run tests
make test

# Clean build artifacts
make clean

# Install development dependencies
make deps

# Run linters
make lint
```

## Project Architecture

### Directory Structure
- `cmd/web-exposure-detection/` - CLI command definitions using Cobra
- `pkg/webexposure/` - Main SDK package (public API)
- `internal/` - Private application code (currently unused)
- `scan-templates/` - Nuclei templates for vulnerability detection
- `configs/` - Configuration files and examples
- `ref/` - Reference bash scripts for comparison

### SDK-First Design

The project is designed as an SDK with CLI commands as facades:

```go
import "web-exposure-detection/pkg/webexposure"

// Create scanner
scanner, err := webexposure.New()

// Run complete scan pipeline
err = scanner.Scan([]string{"example.com"}, []string{"staging", "prod"})

// Individual steps
domains, err := scanner.DiscoverDomains([]string{"example.com"}, keywords)
results, err := scanner.RunNucleiScan(domains, options)
report, err := scanner.GenerateReport(groupedResults, "example.com")
```

### CLI Framework (Cobra)

#### Main Commands
- `scan [domains...]` - Main scanning command
- `--keywords` flag for SSL certificate domain filtering (optional)
- Auto-generates JSON report in current directory

#### Usage Examples
```bash
# Basic scan
web-exposure-detection scan example.com

# With keywords for domain discovery
web-exposure-detection scan example.com --keywords "staging,prod"

# Multiple domains
web-exposure-detection scan domain1.com domain2.com
```

### Scan Pipeline

The tool implements a complete scan pipeline:

1. **Domain Discovery** - Uses domain-scan (placeholder) with optional keywords
2. **Vulnerability Scanning** - Nuclei v3 SDK with scan-templates
3. **Result Aggregation** - Groups results by domain and template (ports bash logic)
4. **Report Generation** - Creates JSON report following schema v1

### Keywords Parameter

Keywords in this tool are for **SSL certificate domain filtering** (passed to domain-scan):
- Optional parameter (default: empty)
- When empty, domain-scan auto-extracts keywords from domain names
- Used to filter SSL certificate domains by organizational relevance
- NOT for subdomain enumeration patterns

### Nuclei Integration

Uses Nuclei v3 SDK with exact CLI parameters from README:
```go
nuclei.WithTemplateFilters(nuclei.TemplateFilters{
    Tags:        []string{"tech"},
    ExcludeTags: []string{"ssl"},
}),
nuclei.WithGlobalRateLimit(30, time.Second),
nuclei.WithConcurrency(nuclei.Concurrency{TemplateConcurrency: 5}),
```

### Report Generation

Generates JSON reports following schema v1 based on sample-exposure-report.md:

```json
{
  "schema_version": "v1",
  "report_metadata": {
    "title": "TotalAppSec External Application Discovery for example.com",
    "date": "2025-07-12",
    "target_domain": "example.com"
  },
  "summary": {
    "total_domains": 36,
    "live_exposed_domains": 17,
    "total_detections": 13,
    "apis_found": 3,
    "web_apps_found": 10
  },
  "technologies_detected": {
    "count": 7,
    "technologies": ["nginx", "wordpress", "angular"]
  },
  "apis_found": [
    {
      "domain": "api.example.com",
      "discovered": "Potential API Endpoint",
      "findings": "Domain has API keyword, Live Domain, API Spec Found at https://..."
    }
  ],
  "web_applications_found": [
    {
      "domain": "www.example.com", 
      "discovered": "Web App",
      "findings": "Using WordPress, Web Server, Angular",
      "technologies": ["Angular", "WordPress"]
    }
  ]
}
```

### Reference Implementation

The Go implementation ports logic from bash scripts in `ref/`:
- `run-result-aggr.sh` - Result grouping logic
- `generate-report.sh` - Report generation with meanings from `scan-template-meanings.json`
- Exact classification rules for APIs vs Web Apps
- Technology extraction with regex normalization

### Configuration Management (Viper)
- Default config file: `$HOME/.web-exposure-detection.yaml`
- Config can be overridden with `--config` flag
- Environment variables are automatically mapped

### Security Focus
This tool is designed for defensive security purposes:
- Detecting web exposure vulnerabilities
- Identifying misconfigurations  
- Generating security reports
- All functionality should be defensive in nature

### Development Patterns
- SDK-first design with CLI as facade
- Comprehensive test coverage with interface-based testing
- Error handling with context
- Structured logging for debugging
- Follow Go conventions and best practices

### Testing Strategy
- Unit tests for all core SDK functionality
- Interface-based testing to avoid concrete type casting
- Test classification logic, report generation, and aggregation
- Mock external dependencies (Nuclei, domain-scan)
- Validate JSON schema and output formats

### Domain-Scan Integration (TODO)

Currently placeholder implementation. Need to integrate actual domain-scan SDK:
- Repository path issues need resolution
- Should pass keywords parameter through to domain-scan
- Keywords are for SSL cert filtering, not subdomain patterns