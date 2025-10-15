# Web Exposure Detection

CLI tool for detecting web exposure vulnerabilities through domain discovery and security scanning.

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

**Basic scan:**
```bash
web-exposure-detection scan example.com
```

**Scan multiple domains:**
```bash
web-exposure-detection scan example.com test.com
```

**Scan with additional business name keywords:**
```bash
web-exposure-detection scan example.com --keywords "examplecorp,exampleinc"
```

**Force fresh domain discovery (ignore cache):**
```bash
web-exposure-detection scan example.com --force
```

## What it does

1. **Discovers domains** - Finds subdomains related to your target
2. **Scans for exposures** - Tests for web vulnerabilities and misconfigurations
3. **Generates reports** - Creates JSON and PDF reports with findings

## Output

Reports are saved to `./results/{domain}/`:
- `web-exposure-result.json` - Structured findings data
- `{domain}-web-exposure-report.pdf` - Formatted report

## Help

```bash
web-exposure-detection --help
web-exposure-detection scan --help
```

For detailed documentation see [docs/](./docs/).

## Development

### Build from source

```bash
make build
make test
```

### Update CVE statistics

Update CVE data for all findings:
```bash
make update-cve-stats
```

See [CVE Statistics](docs/how-to-write-nuclei-template.md#cve-statistics) for details.

### Commands

```bash
make help  # Show all available commands
```