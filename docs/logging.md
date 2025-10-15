# Logging Strategy

Comprehensive logging approach for web-exposure-detection using ProjectDiscovery's gologger.

## Table of Contents

- [Overview](#overview)
- [Logging Levels](#logging-levels)
- [Architecture](#architecture)
- [Usage Guidelines](#usage-guidelines)
- [Migration Examples](#migration-examples)
- [Configuration](#configuration)

## Overview

**Logger**: ProjectDiscovery's `gologger` (from Nuclei v3 SDK dependency)

**Why gologger:**
- Already in dependencies (no new deps)
- Supports structured logging with levels
- Battle-tested in security tools
- Supports Debug, Info, Warning, Error, Fatal levels
- Integrates seamlessly with Nuclei SDK

**Key Principle**: All output uses gologger - no fmt.Printf except in exceptional cases

**Consistent Experience**: Logging flags control both web-exposure-detection and Nuclei output for unified behavior

### Unified Logging Behavior

| Flag | gologger Level | Nuclei Output | Use Case |
|------|----------------|---------------|----------|
| (default) | Info + Warning + Error | Normal findings | Normal user experience, interactive scans |
| `--debug` | Debug + Info + Warning + Error | Debug requests/responses | Full troubleshooting, development |
| `--silent` | Warning + Error only | Findings only | Automation, CI/CD pipelines |

## Logging Levels

### Debug (--debug flag)
**Use for**: Internal flow, technical details, troubleshooting

Examples:
- XML parsing details
- Cache hits/misses
- Template validation steps
- Nuclei result processing
- Internal state changes
- Function entry/exit traces

```go
logger.Debug().Msgf("Parsed %d findings for %s (template: %s)", len(findingsMap), event.Host, event.TemplateID)
logger.Debug().Msgf("Cache hit: loaded %d domains from %s", len(cachedDomains), cacheFile)
logger.Debug().Msgf("Template validation: checking %d templates", len(templates))
```

### Info
**Use for**: Major milestones, operational events, user-facing messages

Examples:
- Scan phase transitions
- Discovery completion
- Report generation
- File operations (saved, loaded)
- Progress updates
- Command start/completion
- Real-time findings

```go
logger.Info().Msgf("Starting web exposure scan for: %v", domains)
logger.Info().Msgf("Domain discovery completed: %d domains found", len(domains))
logger.Info().Msgf("Found %d live domains", found)
logger.Info().Msgf("Found: %s on %s", event.Info.Name, event.Host)
logger.Info().Msgf("Scanning %s (%d tests)", host, testsCompleted)
logger.Info().Msgf("Nuclei scan complete: %d tests, %d findings", testsPerformed, findings)
logger.Info().Msgf("Report generated: %s", filepath)
logger.Info().Msgf("Scan completed successfully")
```

### Warning
**Use for**: Non-fatal issues, degraded functionality

Examples:
- Cache save failures
- Template skipped
- PDF/HTML generation failures
- Partial results
- Malformed data (skipped)

```go
logger.Warning().Msgf("Failed to save domain cache: %v", err)
logger.Warning().Msgf("Skipping malformed JSONL line %d: %v", lineNum, err)
logger.Warning().Msgf("Failed to generate PDF report: %v", err)
```

### Error
**Use for**: Fatal errors that will be returned to caller

Examples:
- Engine initialization failures
- File read/write errors (fatal)
- Network errors
- Invalid configuration

```go
logger.Error().Msgf("Failed to create nuclei engine: %v", err)
return nil, fmt.Errorf("failed to create nuclei engine: %w", err)
```

### Silent (--silent flag)
**Use for**: Minimal output for automation

Only warnings and errors displayed. Suppresses info messages (progress, milestones).

## Architecture

### Logger Initialization

**Location**: `pkg/webexposure/logger.go`

```go
package webexposure

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

// InitLogger configures the global logger based on flags
func InitLogger(debug bool, silent bool) {
	if debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	} else if silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelWarning)
	} else {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo) // Default
	}
}

// GetLogger returns the configured logger instance
func GetLogger() *gologger.Logger {
	return gologger.DefaultLogger
}
```

### Scanner Integration

**Location**: `pkg/webexposure/scanner.go`

```go
// New creates scanner and initializes logger (default: Info level)
func New() (Scanner, error) {
	InitLogger(false, false) // Default to Info level
	return &scanner{}, nil
}

// SetDebug sets debug mode and reconfigures logger
func (s *scanner) SetDebug(debug bool) {
	s.debug = debug
	InitLogger(debug, s.silent)
}

// SetSilent sets silent mode and reconfigures logger
func (s *scanner) SetSilent(silent bool) {
	s.silent = silent
	InitLogger(s.debug, silent)
}
```

### Command Integration

**Location**: `cmd/web-exposure-detection/*.go`

```go
import (
	"web-exposure-detection/pkg/webexposure"
)

// Get logger instance in commands
var logger = webexposure.GetLogger()

// Use throughout command
logger.Info().Msgf("Starting web exposure scan for: %v", domains)
```

### Nuclei Integration

**Location**: `pkg/webexposure/nuclei.go`

Logging flags are passed through to Nuclei SDK for consistent experience:

```go
nuclei.WithVerbosity(nuclei.VerbosityOptions{
	Silent: opts.Silent, // Suppress Nuclei info output (--silent)
	Debug:  opts.Debug,  // Enable debug Nuclei output (--debug)
})
```

**NucleiOptions struct** (pkg/webexposure/nuclei_results_types.go):
```go
type NucleiOptions struct {
	// ... other fields
	Debug  bool // Passed to Nuclei SDK
	Silent bool // Passed to Nuclei SDK
}
```

**Scanner struct** (pkg/webexposure/scanner_types.go):
```go
type scanner struct {
	progress ProgressCallback
	debug    bool // --debug flag
	silent   bool // --silent flag
	verbose  bool // --verbose flag (deprecated, use !silent)
}
```

**Scanner setup** (pkg/webexposure/scanner.go):
```go
nucleiOptions := &NucleiOptions{
	// ... other options
	Debug:  s.debug,  // From --debug flag
	Silent: s.silent, // From --silent flag
}
```

## Usage Guidelines

### When to Log

**DO Log:**
- State changes (discovery started, scan completed)
- Resource operations (file saved, cache loaded)
- Errors and warnings
- Debug traces when --debug enabled

**DO NOT Log:**
- Every loop iteration (too verbose, use sampled logging)
- Sensitive data (credentials, tokens)
- Redundant information
- Internal variables dumps without context

### Log Message Format

**Good:**
```go
logger.Debug().Msgf("Loaded %d templates from %s", count, path)
logger.Warning().Msgf("Failed to convert JSONL to JSON: %v", err)
logger.Info().Msgf("Scan completed: %d findings in %v", findings, duration)
```

**Bad:**
```go
logger.Debug().Msgf("Debug: %v", someComplexStruct) // Too vague
logger.Info().Msgf("Processing...") // No context
logger.Warning().Msgf("Error") // No details
```

### Error Handling Pattern

**Standard pattern:**
```go
// Log the error with context, then return wrapped error
if err != nil {
	logger.Error().Msgf("Failed to create temp directory: %v", err)
	return "", fmt.Errorf("failed to create temp directory: %w", err)
}
```

**Warning pattern (non-fatal):**
```go
// Log warning but continue execution
if err := s.saveDomainsToCache(domains, cacheFile); err != nil {
	logger.Warning().Msgf("Failed to save domain cache: %v", err)
	// Continue - cache save is non-critical
}
```

## Migration Examples

### Example 1: Warning Messages

**Before:**
```go
fmt.Printf("⚠️  Warning: Failed to save domain cache: %v\n", err)
```

**After:**
```go
logger.Warning().Msgf("Failed to save domain cache: %v", err)
```

### Example 2: Debug Messages

**Before:**
```go
if s.debug {
	fmt.Printf("Debug mode: HTML report preserved at %s\n", reportPath)
}
```

**After:**
```go
logger.Debug().Msgf("HTML report preserved at %s", reportPath)
```

### Example 3: Existing gologger Calls

**Before:**
```go
gologger.Debug().Msgf("NewStoredResult: Host=%s, TemplateID=%s", event.Host, event.TemplateID)
gologger.Warning().Msgf("Failed to unmarshal FindingXML: %v", err)
gologger.Info().Msgf("Parsed %d findings for %s", len(findingsMap), event.Host)
```

**After:**
```go
logger := GetLogger()
logger.Debug().Msgf("NewStoredResult: Host=%s, TemplateID=%s", event.Host, event.TemplateID)
logger.Warning().Msgf("Failed to unmarshal FindingXML: %v", err)
logger.Info().Msgf("Parsed %d findings for %s", len(findingsMap), event.Host)
```

### Example 4: User-Facing Messages

**Before:**
```go
// internal/cli/progress.go
fmt.Printf("Found %d live domains\n", found)
fmt.Printf("Scanning %s (%d tests)\n", host, testsCompleted)

// cmd/scan.go
fmt.Printf("Starting web exposure scan for: %v\n", domains)
fmt.Printf("Scan completed successfully\n")
```

**After:**
```go
// internal/cli/progress.go
logger.Info().Msgf("Found %d live domains", found)
logger.Info().Msgf("Scanning %s (%d tests)", host, testsCompleted)

// cmd/scan.go
logger.Info().Msgf("Starting web exposure scan for: %v", domains)
logger.Info().Msgf("Scan completed successfully")
```

## Configuration

### Command Flags

**Default (no flags)**: Info level logging (normal user experience)
- gologger: Info, Warning, Error messages
- Nuclei: Normal findings output
```bash
./bin/web-exposure-detection scan example.com
```

**--debug**: Debug logging (full troubleshooting)
- gologger: Debug, Info, Warning, Error (all messages)
- Nuclei: Debug output (show requests/responses)
```bash
./bin/web-exposure-detection scan example.com --debug
```

**--silent**: Silent mode (automation, CI/CD)
- gologger: Warning, Error only
- Nuclei: Findings only (suppress progress)
```bash
./bin/web-exposure-detection scan example.com --silent
```

**Flag Inheritance**: Both `--debug` and `--silent` are passed through to:
1. gologger (via InitLogger)
2. Nuclei SDK (via nuclei.WithVerbosity)
3. Progress handlers (via scanner.silent flag)

### Environment Variables (Future)

Reserved for future implementation:
- `WED_LOG_LEVEL`: Override log level (debug, info, warning, error)
- `WED_LOG_FILE`: Write logs to file
- `WED_LOG_FORMAT`: Log format (text, json)

## File-by-File Migration Plan

### Priority 1: Core Logging Infrastructure
1. **pkg/webexposure/logger.go** (NEW) - Create logger utilities with InitLogger(debug, silent)
2. **pkg/webexposure/scanner_types.go** - Add `silent bool` field to scanner struct
3. **pkg/webexposure/scanner.go** - Add SetSilent() method and update SetDebug()
4. **pkg/webexposure/nuclei_results_types.go** - Add Debug, Silent bool to NucleiOptions
5. **pkg/webexposure/nuclei.go** - Pass Debug, Silent to nuclei.WithVerbosity
6. **pkg/webexposure/scanner.go** - Set Debug, Silent in NucleiOptions
7. **cmd/scan.go, cmd/discover.go** - Add --silent flag and call scanner.SetSilent()

### Priority 2: High-Volume Logging
8. **pkg/webexposure/nuclei_results.go** - Standardize gologger calls
9. **pkg/webexposure/scanner.go** - Replace warning messages

### Priority 3: User-Facing Output
10. **internal/cli/progress.go** - Convert all fmt.Printf to logger.Info()
11. **cmd/scan.go** - Convert all fmt.Printf to logger.Info()
12. **cmd/discover.go** - Convert all fmt.Printf to logger.Info()
13. **cmd/report.go** - Convert all fmt.Printf to logger.Info()

### Priority 4: Supporting Files
14. **pkg/webexposure/discovery.go** - Update warnings, convert fmt.Printf
15. **pkg/webexposure/report_pdf.go** - Update warnings
16. **pkg/webexposure/report_html.go** - Update warnings
17. **pkg/webexposure/nuclei.go** - Update error logging (not verbosity - already handled)

## Testing

### Verify Debug Output
```bash
./bin/web-exposure-detection scan example.com --debug 2>&1 | grep -i debug
```

### Verify Warning Output
```bash
./bin/web-exposure-detection scan example.com 2>&1 | grep -i warning
```

### Verify Info Output
```bash
./bin/web-exposure-detection scan example.com 2>&1 | grep -i "completed\|generated"
```

## Future Enhancements

- Structured logging with fields (key-value pairs)
- Log file output (in addition to stderr)
- JSON log format for parsing
- Log rotation for long-running scans
- Per-module log levels
- Correlation IDs for multi-domain scans
