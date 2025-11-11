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

### Styling Guide
[styling-guide.md](./styling-guide.md) - HTML report styling patterns, Tailwind CSS conventions, component patterns, consistency rules

### Caching Architecture
[caching.md](./caching.md) - Caching principles, cached operations, API design patterns, force flag behavior

### Flow Architecture
[flow-architecture.md](./flow-architecture.md) - Russian doll pattern for flow orchestration, caching strategy, dependency management, adding new flows

### Industry Classification
[industry-classification.md](./industry-classification.md) - Automatic industry vertical detection with AI providers, compliance framework mapping

### TruRisk Range
[trurisk-range.md](./trurisk-range.md) - Predictive risk scoring system, calculation methodology, implementation details, range calibration

### AI Providers
[ai-providers.md](./ai-providers.md) - Multi provider AI/LLM integration system (OpenRouter, Perplexity), adapter pattern, configuration

### Security & Supply Chain

- [SECURITY.md](./SECURITY.md) - Security scanning tools (gosec, Trivy, Nancy, CodeQL, golangci-lint)
- [SLSA.md](./SLSA.md) - SLSA Level 3 compliance, build provenance, artifact signing
- [RELEASE.md](../RELEASE.md) - Release process with GoReleaser and GitHub Actions

## Research

- [Exploitability Scoring](./research/exploitability-scoring.md) - Research on EPSS, KEV, CVSS, and composite scoring approaches for vulnerability prioritization
- [Industry Classification](./research/industry-detection-api.md) - API integration for automatic industry vertical detection with compliance framework mapping

## SDK Documentation

See [pkg/webexposure/](../pkg/webexposure/) for SDK public API and Go documentation.
