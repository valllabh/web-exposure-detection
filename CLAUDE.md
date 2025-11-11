# CLAUDE.md

Guidance for Claude Code when working with this repository.

## Project Overview

Go-based CLI tool for detecting web exposure vulnerabilities. Designed for defensive security purposes.

**Key Technologies**: Cobra, Viper, Nuclei v3 SDK, Domain-scan v2.2.0 SDK (local), Go embed

## Quick Reference

- **Documentation index**: [docs/index.md](./docs/index.md)
- **How it works**: [README.md](./README.md#how-it-works) - scan pipeline, caching, keywords
- **Development**: [docs/development.md](./docs/development.md) - build, test, project structure
- **Architecture**: [README.md](./README.md#architecture) - SDK-first design, embedded files
- **Reporting**: [docs/reporting-system.md](./docs/reporting-system.md) - report generation details
- **Templates**: [docs/how-to-write-nuclei-template.md](./docs/how-to-write-nuclei-template.md)
- **Logging**: [docs/logging.md](./docs/logging.md) - gologger strategy, levels, migration guide
- **Reference impl**: [ref/](./ref/) directory - original bash scripts

## Important Notes

- **CRITICAL**: NEVER run scans (./web-exposure-detection scan) without explicit user permission. User will test themselves.
- Use `go run .` not `go run main.go` (entire package required)
- Reference Makefile for build, test, clean, deps, lint commands
- SDK-first design: CLI commands are facades over pkg/webexposure SDK
- All templates/assets embedded in binary via embed.go
- Results cached in ./results/{domain}/ - never use --force unless explicitly told
- Entry point for reports: generateReportsFromNucleiResults()
- **Logging**: Follow [docs/logging.md](./docs/logging.md) - ALWAYS use gologger (never fmt.Printf): Info for user messages, Debug for traces, Warning for non-fatal, Error for fatal
- **Findings**: When adding new findings to findings.json, ALWAYS add `classification` field for application type indicators (webapp, api, api-spec, ai). See [docs/development.md](./docs/development.md#adding-new-findings)

## Package Organization

**Critical Rules:**
- Never use generic `types.go` - use descriptive names like `nuclei_types.go`, `findings_types.go`
- Discovery is part of scanner package (separate concern)
- PDF and HTML are both part of report package
- DSL is nuclei related (part of nuclei package)
- AI providers are adapter pattern implementations (part of ai package)
- Common types go in common package

**Package Structure:**
```
pkg/webexposure/
├── common/           # Common types (scanner, report, pdf)
├── scanner/          # Scanner orchestration and discovery
├── report/           # Report generation (HTML, PDF)
├── nuclei/           # Nuclei integration and DSL
├── findings/         # Findings and criticality types
├── industry/         # Industry classification
├── criticality/      # Criticality calculation
├── ai/               # AI provider adapters (OpenRouter, Perplexity)
└── logger/           # Logger utilities
```

See [docs/development.md](./docs/development.md#package-organization-guide) for complete package organization guide.