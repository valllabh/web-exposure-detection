# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Go-based CLI tool for detecting web exposure vulnerabilities using Cobra, Viper, Nuclei v3 SDK, Domain-scan v1.0.0 SDK, and Go embed for zero-dependency distribution. Designed for defensive security purposes.

## Development Commands

Reference Makefile for build, test, clean, deps, lint commands.
Use `go run .` (entire package, not main.go).

## Embedded Architecture

Uses Go embed package for zero-dependency distribution. All scan-templates, templates, and meanings.json embedded in binary. See embed.go for implementation.

## Architecture

### SDK-First Design
CLI commands are facades over pkg/webexposure SDK. See pkg/webexposure for public API.

### Scan Pipeline
1. Domain Discovery (domain-scan v1.0.0)
2. Nuclei Scanning (embedded templates)
3. Result Aggregation
4. Report Generation (JSON, HTML, PDF)
5. HTML Cleanup

### Keywords Parameter
For SSL certificate domain filtering (not subdomain enumeration).

### Report Generation
Single entry point generateReportsFromNucleiResults() handles all formats. See docs/reporting-system.md for details.

### Reference Implementation
Ports logic from ref/ bash scripts. See ref/ directory for original implementation.

### CLI User Experience
Real-time progress tracking with clear status messages, per-host timing, and live findings display.

### Execution Flow
Results stored in ./results/{domain}/ with caching. --force flag clears cache.

### Domain-Scan Integration
Uses github.com/valllabh/domain-scan v1.0.0 SDK with real-time progress adapter.