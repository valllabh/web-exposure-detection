# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via one of the following methods:

1. **GitHub Security Advisories** (Preferred)
   - Go to: https://github.com/valllabh/web-exposure-detection/security/advisories
   - Click "Report a vulnerability"
   - Fill in the details

2. **Email**
   - Send to: [Security contact to be configured]
   - Include: Description, impact, reproduction steps, affected versions

## What to Include

Please include as much of the following information as possible:

- Type of vulnerability
- Full paths of source file(s) related to the vulnerability
- Location of affected source code (tag/branch/commit/URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

## Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: Within 7 days
  - High: Within 14 days
  - Medium: Within 30 days
  - Low: Best effort

## Disclosure Policy

- Report received and acknowledged
- Issue validated and severity assessed
- Fix developed and tested
- Security advisory published
- CVE assigned (if applicable)
- Fix released and announced

## Security Features

This project implements multiple security measures:

### Static Analysis
- gosec security scanner
- Trivy vulnerability scanner
- Nancy dependency checker
- CodeQL semantic analysis
- golangci-lint with security focus

### Supply Chain Security (SLSA Level 3)
- Build provenance generation
- Artifact signing with cosign
- SBOM generation (SPDX format)
- OpenSSF Scorecard monitoring
- Dependabot security updates

### Best Practices
- Minimal dependencies
- No hardcoded credentials
- Input validation
- Secure defaults
- Regular updates

## Security Documentation

- [docs/SECURITY.md](./docs/SECURITY.md) - Detailed security analysis guide
- [docs/SLSA.md](./docs/SLSA.md) - Supply chain security documentation

## Security Scanning

All code changes are automatically scanned for:
- Common security vulnerabilities (gosec)
- Dependency vulnerabilities (Nancy, Trivy)
- Code quality issues (golangci-lint)
- Supply chain risks (OpenSSF Scorecard)

## Acknowledgments

We appreciate the security research community's efforts in responsibly disclosing vulnerabilities. Contributors will be acknowledged in release notes (unless they prefer to remain anonymous).
