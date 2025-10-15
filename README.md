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

Full pipeline: domain discovery + vulnerability scanning + report generation

```bash
# Basic scan
web-exposure-detection scan example.com

# Scan multiple domains
web-exposure-detection scan example.com test.com

# Additional keywords for SSL cert filtering
web-exposure-detection scan example.com --domain-keywords "examplecorp,exampleinc"

# Force fresh domain discovery (ignore cache)
web-exposure-detection scan example.com --force

# Skip domain discovery, scan specific domain only
web-exposure-detection scan example.com --skip-discovery

# Scan with specific templates
web-exposure-detection scan example.com --templates "openapi,swagger-api"

# Fast preset (aggressive scanning)
web-exposure-detection scan example.com --preset fast
```

### Discover Command

Domain discovery only (no vulnerability scanning)

```bash
# Discover domains
web-exposure-detection discover example.com

# With additional keywords
web-exposure-detection discover example.com --domain-keywords "examplecorp"

# Force fresh discovery
web-exposure-detection discover example.com --force
```

### Report Command

Regenerate reports from existing scan results

```bash
# Regenerate report from cached results
web-exposure-detection report example.com
```

## Output

Reports are saved to `./results/{domain}/`:

```
results/example-com/
├── domain-scan.json                      # Cached domain discovery results
├── nuclei-results/
│   └── results.json                     # Raw Nuclei scan results
├── web-exposure-result.json             # Final JSON report
└── example-com-web-exposure-report.pdf  # PDF report
```

## How It Works

### Scan Pipeline

1. **Domain Discovery**
   - Passive enumeration via certificate transparency
   - SSL certificate SAN extraction
   - Auto-extracts keywords from target domain
   - Filters discovered domains by keywords

2. **Vulnerability Scanning**
   - Parallel Nuclei scanning with embedded templates
   - Real-time progress tracking per host
   - Live findings display

3. **Result Aggregation**
   - Classify findings by severity
   - API vs Web Application detection
   - Metadata enrichment

4. **Report Generation**
   - JSON (machine-readable)
   - HTML (human-readable)
   - PDF (export/sharing)

### Caching & Performance

- Results cached in `./results/{domain}/`
- Subsequent scans use cached domain discovery
- Use `--force` to bypass cache and re-scan
- Per-host timing and progress stats

### Keywords Parameter

Keywords filter domains from SSL certificate SANs to match your organization. The tool auto-extracts keywords from target domains (e.g., `example.com` -> `example`).

Use `--domain-keywords` for alternative business names or brands:

```bash
# Organization with multiple brand names
web-exposure-detection scan apple.com --domain-keywords "iphone,ipad,mac"
```

**NOT for:** Environment names (staging/prod), service types (api/admin), or subdomain prefixes.

## Architecture

- **SDK-First Design:** CLI commands are facades over `pkg/webexposure` SDK
- **Embedded Files:** All templates/assets embedded in binary (zero dependencies)
- **Domain Discovery:** github.com/valllabh/domain-scan v1.0.0 SDK
- **Vulnerability Scanning:** Nuclei v3 SDK
- **Report Generation:** Single entry point handles all formats

See [docs/](./docs/) for technical documentation.

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
