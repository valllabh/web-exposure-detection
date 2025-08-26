# Web Exposure Detection

A Go-based CLI tool and SDK for detecting web exposure vulnerabilities using domain discovery and Nuclei exposure scanning with real-time progress tracking.

## Features

- **SDK-First Design**: Use as a Go library or CLI tool
- **Real-time Progress**: Live progress tracking without confusing animations
- **Domain Discovery**: Subdomain enumeration with optional keyword filtering via domain-scan v1.0.0
- **Web Exposure Scanning**: Powered by Nuclei v3 SDK with customizable templates
- **Smart Classification**: Automatically classifies findings as APIs or Web Applications
- **JSON Reports**: Generates structured reports following schema v1
- **Clear CLI UX**: Informative progress messages and per-host timing
- **Defensive Security**: Designed for defensive security use cases only

## Quick Start

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd web-exposure-detection

# Build the application
make build

# Or build manually
go build -o bin/web-exposure-detection ./main.go
```

### Basic Usage

```bash
# Scan a single domain
./bin/web-exposure-detection scan example.com

# Scan multiple domains
./bin/web-exposure-detection scan example.com test.com

# Scan with SSL certificate filtering keywords
./bin/web-exposure-detection scan example.com --keywords "staging,prod"
```

### Example CLI Output

The CLI provides clear, real-time progress tracking:

```
🎯 Starting web exposure scan for: [example.com]
🔍 Starting domain discovery for: [example.com]
📋 Using keywords: [staging, prod]
📡 Running passive subdomain enumeration...
   Found 1 live domains so far...
   Found 5 live domains so far...
   Found 12 live domains so far...
✅ Domain discovery completed
📊 Total: 12 domains (1 original + 11 newly discovered)

🚀 Starting web exposure scan on 12 targets
📝 Loading templates (tech detection, excluding SSL)
🔄 Templates loading and clustering...
✅ Templates loaded successfully
🔍 Beginning exposure detection tests...
   🎯 Testing example.com...
   🚨 Found: Nginx Server Detection on example.com
   ✅ Completed scanning example.com (2.3s)
   🎯 Testing api.example.com...
   🚨 Found: JSON API Endpoint on api.example.com
   ✅ Completed scanning api.example.com (1.8s)
✅ Web exposure scan completed
📊 Tests performed: 3672 | Findings: 15
✅ Report generated: reports/example-com/example-com-web-exposure-report.json
```

### CLI Help

```bash
# View available commands
./bin/web-exposure-detection --help

# View scan command options
./bin/web-exposure-detection scan --help
```

## How It Works

The tool implements a complete vulnerability scanning pipeline:

### Execution Flow
- ResultsDir will be ./results/{first-domain-name-passed}/
- Results dir will contain resutls from doamin scan as domain-scan.json
- - This will be used as cache so we dont have to scan again and again
- - if flag --force is passed cache will be cleared and domain-scan will be done again
- - Scan function will call RunNucleiScan with live targets from ./results/{first-domain-name-passed}/domain-scan.json
- - Scanner will store "nuclie-results" back to ./results/{first-domain-name-passed}/
- - Then Reporting will use the "nuclie-results"
- - Reporting will store  "web-exposure-result.json" back to ./results/{first-domain-name-passed}/

Execution Flow Ends


1. **Domain Discovery**: Discovers subdomains and related live domains
   - Uses domain-scan v1.0.0 SDK with real-time progress tracking
   - Optional SSL certificate filtering keywords
   - Keywords help filter domains by organizational relevance

2. **Web Exposure Scanning**: Scans discovered domains using Nuclei
   - Uses Nuclei v3 SDK with templates from `scan-templates/` directory
   - Configured with: `--include-tags tech --exclude-tags ssl`
   - Rate limiting: 30 requests/second, concurrency: 5, bulk-size: 10
   - Live progress updates showing per-host scanning and timing

3. **Result Processing**: Aggregates and classifies findings
   - Groups results by domain and template
   - Classifies domains as APIs or Web Applications
   - Extracts technologies and generates meaningful descriptions

4. **Report Generation**: Creates structured JSON reports
   - Schema v1 format with metadata, summary, and detailed findings
   - Includes technology detection and security classifications
   - Uses `scan-template-meanings.json` for human-readable descriptions

## CLI Progress Features

The CLI provides excellent user experience with:

- **No Confusing Animations**: Replaced spinner animations with clear status messages
- **Real-time Domain Discovery**: Shows actual count of live domains as they're found
- **Per-Host Scan Progress**: Displays which target is being tested and completion time
- **Live Finding Reports**: Shows exposures immediately when discovered
- **Clear Stage Progression**: Indicates exactly what's happening at each step
- **Informative Summaries**: Provides totals for tests performed and findings

## SDK Usage

Use the tool as a Go library in your own projects:

```go
package main

import (
    "log"
    "web-exposure-detection/pkg/webexposure"
)

func main() {
    // Create scanner instance
    scanner, err := webexposure.New()
    if err != nil {
        log.Fatal(err)
    }
    
    // Run complete scan pipeline
    domains := []string{"example.com"}
    keywords := []string{"staging", "prod"} // Optional SSL cert filtering
    
    err = scanner.Scan(domains, keywords)
    if err != nil {
        log.Fatal(err)
    }
    
    // JSON report automatically generated in current directory
}
```

### Advanced SDK Usage

```go
// Individual pipeline steps
domains := []string{"example.com"}
keywords := []string{"staging", "prod"}

// 1. Domain discovery
discovered, err := scanner.DiscoverDomains(domains, keywords)

// 2. Vulnerability scanning
results, err := scanner.RunNucleiScan(discovered, &webexposure.NucleiOptions{
    TemplatesPath: "./scan-templates",
    IncludeTags:   []string{"tech"},
    ExcludeTags:   []string{"ssl"},
    RateLimit:     30,
    Concurrency:   5,
})

// 3. Generate report
grouped, err := scanner.AggregateResults(results)
report, err := scanner.GenerateReport(grouped, "example.com")
```

## Report Format

The tool generates JSON reports following schema v1:

```json
{
  "schema_version": "v1",
  "report_metadata": {
    "title": "External Application Discovery for example.com",
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

## Development

### Requirements

- Go 1.24+
- Nuclei templates (included in `scan-templates/`)

### Development Commands

```bash
# Run tests
make test

# Build application
make build

# Format code
go fmt ./...

# Run linter
make lint

# Clean build artifacts
make clean
```

### Project Structure

```
├── cmd/web-exposure-detection/  # CLI commands
├── pkg/webexposure/            # Main SDK package
├── scan-templates/             # Nuclei vulnerability templates
├── configs/                    # Configuration files
├── ref/                        # Reference bash scripts
├── Makefile                    # Development tasks
└── CLAUDE.md                   # Development documentation
```

## Keywords Parameter

The `--keywords` parameter is used for **SSL certificate domain filtering**:

- **Optional**: Defaults to empty (auto-extraction from domain names)
- **Purpose**: Filters SSL certificate domains by organizational relevance
- **Example**: `--keywords "staging,prod"` focuses on domains containing these terms
- **Not for**: Subdomain enumeration patterns (this is handled by domain-scan internally)

## Security Notice

This tool is designed exclusively for **defensive security purposes**:

- Vulnerability assessment of your own systems
- Security posture evaluation
- Misconfiguration detection
- Authorized security testing only

## Dependencies

- [Nuclei v3](https://github.com/projectdiscovery/nuclei) - Web exposure scanner
- [Domain-scan v1.0.0](https://github.com/valllabh/domain-scan) - Subdomain discovery with real-time progress
- [Cobra](https://github.com/spf13/cobra) - CLI framework
- [Viper](https://github.com/spf13/viper) - Configuration management

## License

This project is intended for defensive security use cases only. Ensure you have proper authorization before scanning any systems.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass: `make test`
5. Submit a pull request

For detailed development guidance, see [CLAUDE.md](./CLAUDE.md).