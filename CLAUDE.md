# CLAUDE.md

Guidance for Claude Code when working with this repository.

## Project Overview

Go-based CLI tool for detecting web exposure vulnerabilities. Designed for defensive security purposes.

**Key Technologies**: Cobra, Viper, Nuclei v3 SDK, Domain-scan v1.0.0 SDK, Go embed

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

- Use `go run .` not `go run main.go` (entire package required)
- Reference Makefile for build, test, clean, deps, lint commands
- SDK-first design: CLI commands are facades over pkg/webexposure SDK
- All templates/assets embedded in binary via embed.go
- Results cached in ./results/{domain}/ - never use --force unless explicitly told
- Entry point for reports: generateReportsFromNucleiResults()
- **Logging**: Follow [docs/logging.md](./docs/logging.md) - ALWAYS use gologger (never fmt.Printf): Info for user messages, Debug for traces, Warning for non-fatal, Error for fatal