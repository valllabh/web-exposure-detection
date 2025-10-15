# Documentation

Technical documentation for web-exposure-detection.

## For Users

- [User Guide](../README.md) - Installation, usage, how it works

## For Contributors

- [Development Guide](./development.md) - Setup, build, test, project structure

## Technical Documentation

### Reporting System
[reporting-system.md](./reporting-system.md) - JSON/HTML/PDF generation, classification logic, findings system, report schema

### Nuclei Templates
[how-to-write-nuclei-template.md](./how-to-write-nuclei-template.md) - DSL patterns, hierarchical keys, findings.json integration, CVE statistics

### Logging System
[logging.md](./logging.md) - Logging strategy, levels, gologger usage, migration guide, best practices

### Security & Supply Chain

- [SECURITY.md](./SECURITY.md) - Security scanning tools (gosec, Trivy, Nancy, CodeQL, golangci-lint)
- [SLSA.md](./SLSA.md) - SLSA Level 3 compliance, build provenance, artifact signing
- [RELEASE.md](../RELEASE.md) - Release process with GoReleaser and GitHub Actions

## SDK Documentation

See [pkg/webexposure/](../pkg/webexposure/) for SDK public API and Go documentation.
