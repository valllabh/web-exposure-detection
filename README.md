# Web Exposure Detection

[![Test](https://github.com/valllabh/web-exposure-detection/actions/workflows/test.yml/badge.svg)](https://github.com/valllabh/web-exposure-detection/actions/workflows/test.yml)
[![Security](https://github.com/valllabh/web-exposure-detection/actions/workflows/security.yml/badge.svg)](https://github.com/valllabh/web-exposure-detection/actions/workflows/security.yml)
[![Release](https://github.com/valllabh/web-exposure-detection/actions/workflows/release.yml/badge.svg)](https://github.com/valllabh/web-exposure-detection/actions/workflows/release.yml)
[![SLSA](https://github.com/valllabh/web-exposure-detection/actions/workflows/slsa.yml/badge.svg)](https://github.com/valllabh/web-exposure-detection/actions/workflows/slsa.yml)
[![VEX](https://github.com/valllabh/web-exposure-detection/actions/workflows/vex.yml/badge.svg)](https://github.com/valllabh/web-exposure-detection/actions/workflows/vex.yml)

CLI tool for detecting web exposure vulnerabilities through domain discovery and security scanning.

## Features

- Domain discovery via passive enumeration and certificate transparency
- Web exposure scanning with embedded Nuclei templates
- API vs Web Application classification
- Multi-format reports (JSON, HTML, PDF)
- Zero external dependencies (single binary)
- Results caching for efficient re-scans

## Installation

Download the latest release for your platform:

**Linux:**
```bash
curl -sL https://github.com/valllabh/web-exposure-detection/releases/latest/download/web-exposure-detection_Linux_x86_64.tar.gz | tar xz
sudo mv web-exposure-detection /usr/local/bin/
```

**macOS:**
```bash
curl -sL https://github.com/valllabh/web-exposure-detection/releases/latest/download/web-exposure-detection_Darwin_universal.tar.gz | tar xz
sudo mv web-exposure-detection /usr/local/bin/
```

## Usage

### Scan Command

Complete pipeline with automatic caching: domain discovery, vulnerability scanning, TRU insights, and multi-format report generation (JSON, HTML, PDF).

```bash
# Basic scan (generates full report with all formats)
web-exposure-detection scan example.com

# Subsequent runs use cached results (fast)
web-exposure-detection scan example.com

# Force fresh scan (ignore all caches)
web-exposure-detection scan example.com --force

# Scan multiple domains
web-exposure-detection scan example.com test.com

# Additional keywords for SSL cert filtering
web-exposure-detection scan example.com --domain-keywords "examplecorp,exampleinc"

# Skip domain discovery, scan provided domain only
web-exposure-detection scan example.com --skip-discovery-all

# Scan with specific templates
web-exposure-detection scan example.com --templates "openapi,swagger-api"

# Fast preset (aggressive scanning)
web-exposure-detection scan example.com --preset fast
```

**Automatic Caching:** The scan command intelligently caches all intermediate results. Running scan again on the same domain instantly regenerates reports from cached data unless `--force` is used.

### Discover Command (Optional)

Domain discovery only, no vulnerability scanning. Results are cached for subsequent scan commands.

```bash
# Discover domains
web-exposure-detection discover example.com

# With additional keywords
web-exposure-detection discover example.com --domain-keywords "examplecorp"

# Force fresh discovery
web-exposure-detection discover example.com --force
```

### Classify Command (Optional)

Industry classification for a domain. Used internally by scan command.

```bash
# Classify domain industry
web-exposure-detection classify example.com
```

## Output

Reports are saved to `./results/{domain}/`:

```
results/example-com/
├── domain-discovery-result.json          # Cached domain discovery results
├── industry-classification.json          # Industry classification
├── nuclei-results/
│   └── results.json                     # Raw Nuclei scan results (grouped)
├── tru-insights-TAS.json                # TRU insights analysis
├── web-exposure-result.json             # Final JSON report
├── report/
│   └── index.html                       # HTML report
└── example-com-appex-report.pdf         # PDF report
```

All outputs are cached. Running scan command again uses cached results unless `--force` flag is provided.

## How It Works

### Unified Pipeline with Automatic Caching

The scan command executes a complete pipeline with intelligent caching at each step:

1. **Domain Discovery** (cached)
   - Passive enumeration via certificate transparency
   - SSL certificate SAN extraction
   - Auto-extracts keywords from target domain
   - Filters discovered domains by keywords

2. **Industry Classification** (cached, non-blocking)
   - AI-powered industry detection
   - Compliance requirements identification

3. **Vulnerability Scanning** (cached)
   - Parallel Nuclei scanning with embedded templates
   - Real-time progress tracking per host
   - Live findings display

4. **TRU Insights Generation** (cached, non-blocking)
   - AI-powered risk analysis
   - Actionable security recommendations

5. **Report Generation** (cached)
   - JSON (machine-readable)
   - HTML (human-readable with charts)
   - PDF (export/sharing)

### Caching Strategy

Each pipeline step checks its cache before executing:
- **First run:** Executes all steps, caches results
- **Subsequent runs:** Uses cached results (instant)
- **Force mode:** Bypasses all caches with `--force` flag
- **Smart dependencies:** Steps only re-run if dependencies change

This design allows running the scan command multiple times without penalty, making report regeneration instant.

### Keywords Parameter

Keywords filter domains from SSL certificate SANs to match your organization. The tool auto-extracts keywords from target domains (e.g., `example.com` -> `example`).

Use `--domain-keywords` for alternative business names or brands:

```bash
# Organization with multiple brand names
web-exposure-detection scan apple.com --domain-keywords "iphone,ipad,mac"
```

**NOT for:** Environment names (staging/prod), service types (api/admin), or subdomain prefixes.

## Architecture

### Design Principles

- **SDK-First Design:** CLI commands are facades over `pkg/webexposure` SDK
- **Embedded Files:** All templates/assets embedded in binary (zero dependencies)
- **Domain Discovery:** github.com/valllabh/domain-scan v1.0.0 SDK
- **Vulnerability Scanning:** Nuclei v3 SDK
- **Report Generation:** Single entry point handles all formats

### Package Structure

```
pkg/webexposure/
├── common/           # Common types (scanner, report, pdf)
├── scanner/          # Scanner orchestration and discovery
├── report/           # Report generation (HTML, PDF)
├── nuclei/           # Nuclei integration and DSL
├── findings/         # Findings and criticality types
├── industry/         # Industry classification
├── criticality/      # Criticality calculation
└── logger/           # Logger utilities
```

**Package Organization:**
- Discovery is scanner concern (part of scanner package)
- PDF and HTML are report concerns (both in report package)
- DSL is nuclei related (part of nuclei package)
- Common types in common package (never use generic types.go)

See [docs/development.md](./docs/development.md#package-organization-guide) for detailed package organization rules.

## Development

```bash
make build  # Build binary
make test   # Run tests
make help   # Show all commands
```

See [docs/development.md](docs/development.md) for full development guide.

## Documentation

See [docs/index.md](docs/index.md) for complete documentation index.

Key docs:
- [docs/development.md](docs/development.md) - Development guide
- [docs/reporting-system.md](docs/reporting-system.md) - Report generation pipeline
- [docs/how-to-write-nuclei-template.md](docs/how-to-write-nuclei-template.md) - Template development

## Help

```bash
web-exposure-detection --help
web-exposure-detection scan --help
web-exposure-detection discover --help
web-exposure-detection report --help
```

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.
