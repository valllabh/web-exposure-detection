# Security Analysis

This document describes the static security analysis tools and processes for this repository.

## Overview

We use multiple security scanning tools to ensure code quality and identify vulnerabilities:

1. **gosec** - Go security checker for common security issues
2. **Trivy** - Vulnerability scanner for dependencies and configurations
3. **Nancy** - Dependency vulnerability checker using Sonatype OSS Index
4. **CodeQL** - GitHub's semantic code analysis engine
5. **golangci-lint** - Meta-linter with security-focused linters enabled

## Running Security Scans Locally

### Quick Start

Run all security scans:
```bash
make security
```

### Individual Scanners

Run specific security tools:

```bash
# gosec - Go security scanner
make sec-gosec

# Trivy - Vulnerability scanner (requires installation)
make sec-trivy

# Nancy - Dependency scanner
make sec-nancy
```

### Installing Tools

#### gosec
Auto-installed on first run, or manually:
```bash
go install github.com/securego/gosec/v2/cmd/gosec@latest
```

#### Trivy
```bash
# macOS
brew install trivy

# Linux
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy
```

#### Nancy
Auto-installed on first run, or manually:
```bash
go install github.com/sonatype-nexus-community/nancy@latest
```

## CI/CD Integration

Security scans run automatically on:
- Every push to main branch
- Every pull request
- Weekly schedule (Sundays at midnight)

### GitHub Actions Workflow

The `.github/workflows/security.yml` workflow includes:

1. **gosec** - Scans for security issues, uploads SARIF results
2. **Trivy** - Scans for vulnerabilities (CRITICAL, HIGH, MEDIUM)
3. **Nancy** - Checks dependencies for known vulnerabilities
4. **Staticcheck** - Advanced static analysis
5. **CodeQL** - Semantic code analysis

Results are available in:
- GitHub Security tab → Code scanning alerts
- Pull request checks
- Workflow run logs

## Configuration

### golangci-lint

Security linters enabled in `.golangci.yml`:
- `gosec` - Security issues
- `bodyclose` - HTTP body closure
- `sqlclosecheck` - SQL row closure
- `rowserrcheck` - SQL rows.Err() checks
- `noctx` - HTTP request context checks

Excluded checks:
- `G204` - Subprocess with variable (needed for CLI)
- `G304` - File path as taint input (needed for file ops)

### gosec

Configured in `.golangci.yml` with:
- Severity: medium
- Confidence: medium
- Excludes: G204, G304

## Security Best Practices

### Code Level
1. Always validate user input
2. Use context for HTTP requests
3. Close resources (files, HTTP bodies, DB connections)
4. Avoid hardcoded credentials
5. Use crypto/rand for random values
6. Sanitize file paths

### Dependencies
1. Keep dependencies up to date
2. Review dependency changes in PRs
3. Use go.mod replace only when necessary
4. Run `make sec-nancy` before releases

### CI/CD
1. Review security scan results before merging
2. Fix CRITICAL and HIGH vulnerabilities immediately
3. Address MEDIUM vulnerabilities in next release
4. Document accepted risks for false positives

## Interpreting Results

### gosec

Common findings:
- **G104**: Unhandled errors - Add error handling
- **G304**: File inclusion via variable - Validate paths
- **G401**: Weak crypto - Use SHA256+ or bcrypt
- **G402**: TLS InsecureSkipVerify - Only for testing

### Trivy

Severity levels:
- **CRITICAL**: Fix immediately, block deployment
- **HIGH**: Fix before next release
- **MEDIUM**: Fix in upcoming releases
- **LOW**: Fix when convenient

### Nancy

Reports CVE numbers with:
- CVSS score
- Description
- Affected versions
- Fixed version (if available)

## Suppressing False Positives

### gosec

Add comment to suppress:
```go
// #nosec G304 -- Path validated via allowlist
file, err := os.Open(filepath.Clean(userPath))
```

### golangci-lint

Add to `.golangci.yml`:
```yaml
issues:
  exclude-rules:
    - path: pkg/specific/file.go
      linters:
        - gosec
      text: "G304"
```

## Reporting Security Issues

For security vulnerabilities:
1. Do NOT open public issues
2. Email: [Security contact to be added]
3. Include: Description, impact, reproduction steps
4. Expected response: Within 48 hours

## Resources

- [gosec Documentation](https://github.com/securego/gosec)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Nancy Documentation](https://github.com/sonatype-nexus-community/nancy)
- [CodeQL Documentation](https://codeql.github.com/)
- [OWASP Go Security](https://owasp.org/www-project-go-secure-coding-practices-guide/)
