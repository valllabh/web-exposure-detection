# Documentation Overview

This directory contains comprehensive documentation for the web-exposure-detection tool.

## Current Architecture (Updated 2025)

### Core Features
- **Defensive Security Tool** - Scan for web exposure vulnerabilities and misconfigurations
- **Single Binary Distribution** - All dependencies embedded for zero external file requirements
- **Multi-Format Reports** - JSON, HTML, PDF with automatic cleanup
- **Cross-Platform Releases** - Linux and macOS with automated builds

### Key Features
- **Embedded Dependencies** - No external files required for distribution
- **Separation of Concerns** - Clean separation between scanning and reporting
- **Automated Releases** - GitHub Actions for cross-platform builds
- **Enhanced Classification** - Improved API vs WebApp classification logic
- **Report Cleanup** - Automatic HTML cleanup after PDF generation

## Documentation Files

### Core Documentation
- **[reporting-system.md](./reporting-system.md)** - Complete reporting pipeline architecture
- **[scan-templates-analysis.md](./scan-templates-analysis.md)** - Scan template classification analysis
- **[prd.md](./prd.md)** - Product Requirements Document

### Release Documentation
- **[../RELEASE.md](../RELEASE.md)** - Release process with GoReleaser and GitHub Actions

## Quick Start

See root README.md for installation and usage instructions.

## Architecture Overview

The tool implements a complete scan pipeline with embedded dependencies:

### Scan Pipeline
1. **Domain Discovery** - Subdomain enumeration with real-time progress
2. **Nuclei Scanning** - Web exposure detection using embedded templates
3. **Result Processing** - Aggregation and classification
4. **Report Generation** - Multi-format output (JSON, HTML, PDF)
5. **Cleanup** - Automatic removal of temporary files

### Key Features
- **Embedded Files** - All templates and assets embedded in binary
- **Report Generation** - Single entry point for all report formats
- **Classification Logic** - Enhanced API vs WebApp detection
- **Release Process** - Automated cross-platform builds

## Status: Production Ready ✅

The tool is currently production-ready with:
- ✅ Embedded dependencies for zero-dependency distribution
- ✅ Comprehensive test coverage
- ✅ Automated release pipeline
- ✅ Multi-format report generation
- ✅ Cross-platform compatibility