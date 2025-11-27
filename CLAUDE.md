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

## Temporary Scripts Policy

**NEVER commit temporary scripts to repository root.** Follow these rules:

1. **One-time migrations/refactoring**: Do NOT create shell scripts. Apply changes directly using Claude Code tools (Edit, Bash) and commit the results only.

2. **Utility scripts for data processing**: Place in `scripts/` directory with clear naming.

3. **Experimental/rejected scripts**: Move to `scripts/archive-rejected/` with explanation in README.

4. **Test scripts**: Keep in `scripts/` only if reusable. One-time test scripts should be deleted after use.

**Allowed in root:**
- Makefile (build commands)
- Go files (main.go, embed.go)
- Config files (.goreleaser.yaml, .vex.yaml, etc.)

**Never in root:**
- *.sh files (except through Makefile targets)
- *.py migration scripts
- Temporary fix scripts