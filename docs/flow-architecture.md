# Flow Architecture

## Overview

This codebase uses a **Flow and Subflow Pattern** for orchestration:
- **Flows** are high-level user-facing operations (map to CLI commands)
- **Subflows** are internal building blocks (cacheable operations)

## Core Principles

### 1. Flow vs Subflow

**Flows** (High-level orchestration):
- Map to CLI commands (scan, report, tru-insights)
- Call multiple subflows in sequence
- Handle high-level logic and error handling
- Not directly cacheable (orchestrate cacheable subflows)

**Subflows** (Building blocks):
- Single responsibility operations
- Accept `(domain, force, ...params)` parameters
- Check cache first (unless `force=true`)
- Call dependent subflows with same `force` flag
- Execute logic and save to cache
- Return result

### 2. Caching Rules

- Every **subflow** output MUST be cached
- Cache location: `results/{domain}/{subflow-name}.json`
- Cache check happens before execution (unless `force=true`)
- Force flag propagates to ALL dependent subflows

### 3. Subflow Dependencies

Subflows call dependent subflows automatically. Never duplicate logic.

**Example**: TRU Insights Subflow needs Discovery, Industry, and Nuclei results.
- ❌ Bad: Load each from cache manually
- ✅ Good: Call each subflow function (they handle their own caching)

## Architecture Structure

### Subflows (Building Blocks)

Subflows are cacheable operations with dependencies:

```
Level 0 (Base Subflows - No Dependencies):
├─ DiscoverySubflow
│  Cache: domain-discovery-result.json
│  Dependencies: None
│
└─ IndustryClassificationSubflow
   Cache: industry-classification.json
   Dependencies: None

Level 1 (Depends on Level 0):
└─ NucleiScanSubflow
   Cache: nuclei-results/results.json
   Calls: DiscoverySubflow
   Dependencies: Discovery results

Level 2 (Depends on Level 0 + 1):
└─ TRUInsightsSubflow
   Cache: tru-insights-TAS.json
   Calls: DiscoverySubflow, IndustryClassificationSubflow, NucleiScanSubflow
   Dependencies: All above

Level 3 (Depends on Level 2):
└─ ReportJSONSubflow
   Cache: web-exposure-result.json
   Calls: TRUInsightsSubflow
   Dependencies: TRU Insights (+ all its deps)

Level 4 (Depends on Level 3):
└─ HTMLSubflow
   Cache: report/index.html
   Calls: ReportJSONSubflow
   Dependencies: Report JSON

Level 5 (Depends on Level 4):
└─ PDFSubflow
   Cache: {domain}-appex-report.pdf
   Calls: HTMLSubflow
   Dependencies: HTML report
```

### Flows (High-Level Orchestration)

Flows orchestrate subflows for user-facing operations:

```
SCAN FLOW (Complete scan from scratch)
├─ DiscoverySubflow
├─ IndustryClassificationSubflow
├─ NucleiScanSubflow
└─ ReportFlow (nested)
   ├─ TRUInsightsSubflow
   ├─ ReportJSONSubflow
   ├─ HTMLSubflow
   └─ PDFSubflow

REPORT FLOW (Generate reports from existing scan)
├─ TRUInsightsSubflow (ensures all deps exist)
├─ ReportJSONSubflow
├─ HTMLSubflow
└─ PDFSubflow

TRU INSIGHTS FLOW (Standalone TRU insights generation)
├─ DiscoverySubflow (if not exists)
├─ IndustryClassificationSubflow (if not exists)
├─ NucleiScanSubflow (if not exists)
└─ TRUInsightsSubflow
```

## Function Templates

### Subflow Function Template

```go
// runXYZSubflow executes XYZ subflow with caching and dependency orchestration
// Cache: results/{domain}/xyz-result.json
// Dependencies: Dep1Subflow, Dep2Subflow
func (s *scanner) runXYZSubflow(domain string, force bool, params XYZParams) (*XYZResult, error) {
    logger := logger.GetLogger()
    resultsDir := filepath.Join("results", domain)
    cacheFile := filepath.Join(resultsDir, "xyz-result.json")

    // Step 1: Check cache (unless force=true)
    if !force {
        if cached, err := s.loadXYZCache(cacheFile); err == nil {
            logger.Info().Msg("Using cached XYZ result")
            return cached, nil
        }
        logger.Debug().Msg("Cache miss for XYZ, executing subflow")
    } else {
        logger.Info().Msg("Force flag set, regenerating XYZ")
    }

    // Step 2: Call dependent subflows (with same force flag)
    dep1, err := s.runDep1Subflow(domain, force, dep1Params)
    if err != nil {
        return nil, fmt.Errorf("dependency Dep1 failed: %w", err)
    }

    dep2, err := s.runDep2Subflow(domain, force, dep2Params)
    if err != nil {
        return nil, fmt.Errorf("dependency Dep2 failed: %w", err)
    }

    // Step 3: Execute own logic
    logger.Info().Msg("Executing XYZ subflow")
    result, err := s.executeXYZ(dep1, dep2, params)
    if err != nil {
        return nil, fmt.Errorf("XYZ execution failed: %w", err)
    }

    // Step 4: Save to cache
    if err := s.saveXYZCache(cacheFile, result); err != nil {
        logger.Warning().Msgf("Failed to save XYZ cache: %v", err)
        // Continue even if cache save fails
    }

    // Step 5: Return result
    return result, nil
}
```

### Flow Function Template

```go
// RunXYZFlow orchestrates XYZ flow by calling subflows in sequence
// This is a high-level operation that maps to a CLI command
func (s *scanner) RunXYZFlow(domain string, force bool, params XYZParams) error {
    logger := logger.GetLogger()
    logger.Info().Msgf("Starting XYZ flow for domain: %s", domain)

    // Step 1: Call first subflow
    result1, err := s.runSubflow1(domain, force, params.Subflow1Params)
    if err != nil {
        return fmt.Errorf("subflow1 failed: %w", err)
    }

    // Step 2: Call second subflow
    result2, err := s.runSubflow2(domain, force, params.Subflow2Params)
    if err != nil {
        return fmt.Errorf("subflow2 failed: %w", err)
    }

    // Step 3: Call nested flow (if applicable)
    if err := s.RunNestedFlow(domain, force, params.NestedParams); err != nil {
        return fmt.Errorf("nested flow failed: %w", err)
    }

    logger.Info().Msgf("XYZ flow completed successfully for domain: %s", domain)
    return nil
}
```

## Command to Flow Mapping

### Scan Command

Entry point: **RunScanFlow**

```go
// cmd/web-exposure-detection/scan.go
func scanCmd.RunE() error {
    scanner := webexposure.NewScanner()

    // Call scan flow with all parameters
    return scanner.RunScanFlow(domain, force, ScanParams{
        Templates:  templates,
        Keywords:   keywords,
        SkipFlags:  skipFlags,
        // ... other params
    })
}
```

**Scan Flow Implementation**:
```go
// pkg/webexposure/scanner/flow_scan.go
func (s *scanner) RunScanFlow(domain string, force bool, params ScanParams) error {
    logger.Info().Msg("Starting Scan Flow")

    // Step 1: Discovery
    _, err := s.runDiscoverySubflow(domain, force, params.Keywords, params.SkipFlags)
    if err != nil {
        return fmt.Errorf("discovery subflow failed: %w", err)
    }

    // Step 2: Industry Classification
    _, err = s.runIndustryClassificationSubflow(domain, force)
    if err != nil {
        logger.Warning().Msgf("Industry classification failed: %v", err)
        // Non-blocking, continue
    }

    // Step 3: Nuclei Scan
    _, err = s.runNucleiScanSubflow(domain, force, params.Templates)
    if err != nil {
        return fmt.Errorf("nuclei scan subflow failed: %w", err)
    }

    // Step 4: Report Flow (nested)
    return s.RunReportFlow(domain, force)
}
```

### Report Command

Entry point: **RunReportFlow**

```go
// cmd/web-exposure-detection/report.go
func reportCmd.RunE() error {
    scanner := webexposure.NewScanner()

    // Generate reports from existing scan results
    // force=false means reuse all cached subflow results
    return scanner.RunReportFlow(domain, false)
}
```

**Report Flow Implementation**:
```go
// pkg/webexposure/scanner/flow_report.go
func (s *scanner) RunReportFlow(domain string, force bool) error {
    logger.Info().Msg("Starting Report Flow")

    // Step 1: TRU Insights (with dependency resolution)
    _, err := s.runTRUInsightsSubflow(domain, force)
    if err != nil {
        logger.Warning().Msgf("TRU insights generation failed: %v", err)
        // Non-blocking, continue
    }

    // Step 2: Report JSON generation
    report, err := s.runReportJSONSubflow(domain, force)
    if err != nil {
        return fmt.Errorf("report JSON generation failed: %w", err)
    }

    // Step 3: HTML generation
    _, err = s.runHTMLSubflow(domain, force, report)
    if err != nil {
        logger.Warning().Msgf("HTML generation failed: %v", err)
        // Non-blocking, continue
    }

    // Step 4: PDF generation
    _, err = s.runPDFSubflow(domain, force)
    if err != nil {
        logger.Warning().Msgf("PDF generation failed: %v", err)
        // Non-blocking, continue
    }

    logger.Info().Msg("Report Flow completed")
    return nil
}
```

### TRU Insights Command

Entry point: **RunTRUInsightsFlow**

```go
// cmd/web-exposure-detection/tru-insights.go
func truInsightsCmd.RunE() error {
    scanner := webexposure.NewScanner()

    // Generate TRU insights standalone
    return scanner.RunTRUInsightsFlow(domain, force)
}
```

**TRU Insights Flow Implementation**:
```go
// pkg/webexposure/scanner/flow_tru_insights.go
func (s *scanner) RunTRUInsightsFlow(domain string, force bool) error {
    logger.Info().Msg("Starting TRU Insights Flow")

    // Just call the subflow - it handles dependency resolution
    _, err := s.runTRUInsightsSubflow(domain, force)
    if err != nil {
        return fmt.Errorf("TRU insights subflow failed: %w", err)
    }

    logger.Info().Msg("TRU Insights Flow completed")
    return nil
}
```

## Adding New Subflows

### Step 1: Identify Dependencies

Determine what data your subflow needs:
- What files must exist?
- What subflows generate those files?

### Step 2: Define Cache Location

```go
// Cache location
const cacheFile = "results/{domain}/my-new-subflow.json"
```

### Step 3: Create Subflow Function

Use subflow template above. Key points:
- Accept `force` parameter
- Check cache unless `force=true`
- Call dependent subflows with same `force`
- Execute logic
- Save to cache
- Return result

### Step 4: Add to Hierarchy

Update this document with:
- Subflow level (depends on dependencies)
- Cache file location
- Dependencies list

### Step 5: Integrate into Flow

Add subflow call to existing flow function:
```go
func (s *scanner) RunExistingFlow(domain string, force bool) error {
    // ... existing subflows

    // Call new subflow
    _, err := s.runMyNewSubflow(domain, force, params)
    if err != nil {
        return fmt.Errorf("my new subflow failed: %w", err)
    }

    // ... continue
}
```

## Adding New Flows

### Step 1: Define Flow Purpose

Determine if this should be a user-facing command:
- What sequence of subflows does it orchestrate?
- Is this a new CLI command or part of existing flow?

### Step 2: Create Flow Function

Use flow template above. Key points:
- No caching (flows orchestrate cached subflows)
- Call subflows in sequence
- Handle errors appropriately
- Can call nested flows

### Step 3: Map to CLI Command

If new command, create command handler:
```go
// cmd/web-exposure-detection/my-command.go
func myCmd.RunE() error {
    scanner := webexposure.NewScanner()
    return scanner.RunMyNewFlow(domain, force, params)
}
```

### Step 4: Update Documentation

Add flow to hierarchy and command mapping sections in this document.

## Common Pitfalls

### ❌ Don't Mix Flow and Subflow Responsibilities

```go
// BAD: Flow with caching logic (flows should not cache)
func (s *scanner) RunXYZFlow(domain string, force bool) error {
    cacheFile := "..."
    if !force {
        if cached, _ := loadCache(cacheFile); cached != nil {
            return nil
        }
    }
    // ... execute logic
}
```

```go
// GOOD: Flow orchestrates subflows (subflows handle caching)
func (s *scanner) RunXYZFlow(domain string, force bool) error {
    _, err := s.runSubflow1(domain, force)
    _, err = s.runSubflow2(domain, force)
    return nil
}
```

### ❌ Don't Load Cache Manually in Subflows

```go
// BAD: Loading dependency cache manually in subflow
discoveryData, _ := loadFile("results/{domain}/domain-discovery.json")
industryData, _ := loadFile("results/{domain}/industry.json")
// Use both...
```

```go
// GOOD: Call dependent subflows (they handle their own caching)
discovery, err := s.runDiscoverySubflow(domain, force)
industry, err := s.runIndustryClassificationSubflow(domain, force)
// Use both...
```

### ❌ Don't Skip Cache Checks in Subflows

```go
// BAD: Subflow always executing without checking cache
func (s *scanner) runXYZSubflow(domain string, force bool) (*Result, error) {
    result := s.executeExpensiveOperation()
    return result, nil
}
```

```go
// GOOD: Subflow checks cache first, respects force flag
func (s *scanner) runXYZSubflow(domain string, force bool) (*Result, error) {
    if !force {
        if cached, err := loadCache(); err == nil {
            return cached, nil
        }
    }
    result := s.executeExpensiveOperation()
    saveCache(result)
    return result, nil
}
```

### ❌ Don't Propagate Force Incorrectly

```go
// BAD: Not passing force to dependency subflows
dep, err := s.runDepSubflow(domain, false) // Always uses cache!
```

```go
// GOOD: Force applies to entire dependency tree
dep, err := s.runDepSubflow(domain, force)
```

### ❌ Don't Duplicate Subflow Logic in Flows

```go
// BAD: Flow duplicating subflow logic
func (s *scanner) RunReportFlow(domain string, force bool) error {
    // Inline TRU insights generation (duplicates subflow logic)
    generator := truinsights.NewGenerator()
    insights, _ := generator.Generate(domain)
    // ...
}
```

```go
// GOOD: Flow calls subflow
func (s *scanner) RunReportFlow(domain string, force bool) error {
    // Call TRU insights subflow
    _, err := s.runTRUInsightsSubflow(domain, force)
    // ...
}
```

## Testing

### Unit Testing Subflows

Test each subflow in isolation with mocked dependencies:

```go
func TestRunXYZSubflow(t *testing.T) {
    scanner := NewScanner()

    // Test cache hit
    t.Run("cache hit", func(t *testing.T) {
        // Setup cache file
        result, err := scanner.runXYZSubflow("example.com", false, params)
        // Assert loaded from cache
        assert.NoError(t, err)
        assert.NotNil(t, result)
    })

    // Test cache miss
    t.Run("cache miss", func(t *testing.T) {
        // No cache file
        result, err := scanner.runXYZSubflow("example.com", false, params)
        // Assert executed and cached
        assert.NoError(t, err)
        assertFileExists(t, "results/example.com/xyz-result.json")
    })

    // Test force flag
    t.Run("force regenerate", func(t *testing.T) {
        // Cache exists but force=true
        result, err := scanner.runXYZSubflow("example.com", true, params)
        // Assert executed despite cache
        assert.NoError(t, err)
    })
}
```

### Integration Testing Flows

Test complete flows orchestrating subflows:

```go
func TestScanFlow(t *testing.T) {
    scanner := NewScanner()

    // Full scan with force
    err := scanner.RunScanFlow("example.com", true, params)
    assert.NoError(t, err)

    // Verify all subflow cache files created
    assertFileExists(t, "results/example.com/domain-discovery-result.json")
    assertFileExists(t, "results/example.com/industry-classification.json")
    assertFileExists(t, "results/example.com/nuclei-results/results.json")
    assertFileExists(t, "results/example.com/tru-insights-TAS.json")
    assertFileExists(t, "results/example.com/web-exposure-result.json")
    assertFileExists(t, "results/example.com/report/index.html")
    assertFileExists(t, "results/example.com/example.com-appex-report.pdf")
}

func TestReportFlow(t *testing.T) {
    scanner := NewScanner()

    // Setup: Run scan first to create dependencies
    scanner.RunScanFlow("example.com", true, params)

    // Test report flow with cache (force=false)
    err := scanner.RunReportFlow("example.com", false)
    assert.NoError(t, err)

    // Should reuse cached discovery, industry, nuclei
    // Should regenerate TRU insights, report, HTML, PDF
}
```

## Debugging

Enable debug logging to see flow and subflow execution:

```bash
./web-exposure-detection scan example.com --debug
```

**Example Output**:
```
[INFO] Starting Scan Flow
[INFO] Executing Discovery Subflow
[DEBUG] Checking cache: results/example.com/domain-discovery-result.json
[DEBUG] Cache miss, executing subflow
[INFO] Discovered 15 domains
[DEBUG] Saved cache: results/example.com/domain-discovery-result.json

[INFO] Executing Industry Classification Subflow
[DEBUG] Checking cache: results/example.com/industry-classification.json
[INFO] Using cached industry classification
[INFO] Industry: Financial Services

[INFO] Executing Nuclei Scan Subflow
[DEBUG] Checking cache: results/example.com/nuclei-results/results.json
[DEBUG] Cache miss, executing subflow
[INFO] Running Nuclei scan on 15 targets
[INFO] Nuclei scan complete: 23 findings

[INFO] Starting Report Flow
[INFO] Executing TRU Insights Subflow
[DEBUG] Checking cache: results/example.com/tru-insights-TAS.json
[DEBUG] Cache miss, executing subflow
[INFO] Generating TRU insights via Perplexity
[INFO] TRU insights generated

[INFO] Executing Report JSON Subflow
[INFO] Generating report structure
[INFO] Report JSON complete

[INFO] Executing HTML Subflow
[INFO] Generating HTML report
[INFO] HTML complete

[INFO] Executing PDF Subflow
[INFO] Generating PDF from HTML
[INFO] PDF complete: results/example.com/example.com-appex-report.pdf

[INFO] Report Flow completed
[INFO] Scan Flow completed
```

**Trace Subflow Dependencies**:

```bash
# See which subflows call which
./web-exposure-detection scan example.com --debug 2>&1 | grep "Executing\|Calling"
```

## Migration Guide

### Current State Issues

Current implementation (scanner.go) has:
- **Inline execution**: All logic in ScanWithPreset() and GenerateReportFromExistingResults()
- **Incomplete caching**: Nuclei, Report JSON, HTML, PDF not cached
- **Code duplication**: TRU Insights generation in 2 places
- **No subflow functions**: Everything inline
- **Force flag inconsistency**: Not propagated to all operations
- **Missing TRU Insights in scan**: Only generated in report command

### Migration Strategy

Refactor into separate files for clarity:

```
pkg/webexposure/scanner/
├── scanner.go              # Scanner type, constructor, utilities
├── flow_scan.go            # Scan Flow
├── flow_report.go          # Report Flow
├── flow_tru_insights.go    # TRU Insights Flow
├── subflow_discovery.go    # Discovery Subflow
├── subflow_industry.go     # Industry Classification Subflow
├── subflow_nuclei.go       # Nuclei Scan Subflow
├── subflow_tru_insights.go # TRU Insights Subflow
├── subflow_report_json.go  # Report JSON Subflow
├── subflow_html.go         # HTML Subflow
└── subflow_pdf.go          # PDF Subflow
```

### Migration Steps

#### Phase 1: Extract Base Subflows

1. **Extract Discovery Subflow** (subflow_discovery.go)
   - Move discoverDomainsWithProtocolCached logic
   - Already has caching, just extract to function
   - Function: `runDiscoverySubflow(domain, force, keywords, skipFlags)`

2. **Extract Industry Classification Subflow** (subflow_industry.go)
   - Move industry.ClassifyDomainIndustryWithCache logic
   - Already has caching, just extract to function
   - Function: `runIndustryClassificationSubflow(domain, force)`

#### Phase 2: Create Nuclei Subflow

3. **Create Nuclei Scan Subflow** (subflow_nuclei.go)
   - Extract Nuclei scanning logic
   - ADD caching (currently missing)
   - Function: `runNucleiScanSubflow(domain, force, templates)`
   - Cache: `nuclei-results/results.json`

#### Phase 3: Create TRU Insights Subflow

4. **Create TRU Insights Subflow** (subflow_tru_insights.go)
   - Consolidate duplicate code from:
     - cmd/web-exposure-detection/tru-insights.go
     - scanner.go:GenerateReportFromExistingResults (lines 518-527)
   - Ensure dependency resolution (calls Discovery, Industry, Nuclei subflows)
   - Function: `runTRUInsightsSubflow(domain, force)`
   - Cache: `tru-insights-TAS.json`

#### Phase 4: Create Report Subflows

5. **Create Report JSON Subflow** (subflow_report_json.go)
   - Extract report.GenerateReport logic
   - ADD caching (currently missing)
   - Function: `runReportJSONSubflow(domain, force)`
   - Cache: `web-exposure-result.json`

6. **Create HTML Subflow** (subflow_html.go)
   - Extract report.GenerateHTMLReport logic
   - ADD caching (currently missing)
   - Function: `runHTMLSubflow(domain, force)`
   - Cache: `report/index.html`

7. **Create PDF Subflow** (subflow_pdf.go)
   - Extract generatePDF logic
   - ADD caching (currently missing)
   - Function: `runPDFSubflow(domain, force)`
   - Cache: `{domain}-appex-report.pdf`

#### Phase 5: Create Flow Functions

8. **Create Scan Flow** (flow_scan.go)
   - Orchestrates: Discovery, Industry, Nuclei, Report Flow
   - Function: `RunScanFlow(domain, force, params)`
   - No caching (orchestrates cached subflows)

9. **Create Report Flow** (flow_report.go)
   - Orchestrates: TRU Insights, Report JSON, HTML, PDF
   - Function: `RunReportFlow(domain, force)`
   - No caching (orchestrates cached subflows)

10. **Create TRU Insights Flow** (flow_tru_insights.go)
    - Calls: TRU Insights Subflow (which resolves dependencies)
    - Function: `RunTRUInsightsFlow(domain, force)`
    - No caching (orchestrates cached subflows)

#### Phase 6: Update Command Handlers

11. **Update scan.go**
    - Replace ScanWithPreset call
    - Call: `scanner.RunScanFlow(domain, force, params)`

12. **Update report.go**
    - Replace GenerateReportFromExistingResults call
    - Call: `scanner.RunReportFlow(domain, force)`

13. **Update tru-insights.go**
    - Replace webexposure.GenerateTRUInsightsWithDebug call
    - Call: `scanner.RunTRUInsightsFlow(domain, force)`

#### Phase 7: Testing

14. **Test each subflow independently**
    - Cache hit/miss scenarios
    - Force flag behavior
    - Dependency resolution

15. **Test each flow**
    - Full scan flow
    - Report regeneration flow
    - TRU insights standalone flow

16. **Integration testing**
    - Scan → generates everything including TRU insights
    - Report → reuses cached scan, regenerates reports
    - TRU Insights → reuses cached scan, regenerates only TRU insights

### Validation Checklist

After migration, verify:

- ✅ Scan command generates TRU insights automatically
- ✅ All subflows check cache before execution
- ✅ Force flag propagates through entire dependency tree
- ✅ No code duplication (DRY principle)
- ✅ Report command reuses cached scan results
- ✅ TRU Insights command works standalone
- ✅ Each subflow has single responsibility
- ✅ Flows orchestrate subflows (no business logic in flows)
- ✅ All cache files created in correct locations
- ✅ Debug logging shows flow/subflow execution clearly

## File Organization Summary

### Current Files (Before Migration)
```
pkg/webexposure/scanner/
├── scanner.go              # All logic inline (2000+ lines)
└── ... other utilities

cmd/web-exposure-detection/
├── scan.go                 # Calls ScanWithPreset
├── report.go               # Calls GenerateReportFromExistingResults
└── tru-insights.go         # Duplicates TRU insights logic
```

### Target Files (After Migration)
```
pkg/webexposure/scanner/
├── scanner.go              # Scanner type, constructor, utilities
├── flow_scan.go            # RunScanFlow
├── flow_report.go          # RunReportFlow
├── flow_tru_insights.go    # RunTRUInsightsFlow
├── subflow_discovery.go    # runDiscoverySubflow
├── subflow_industry.go     # runIndustryClassificationSubflow
├── subflow_nuclei.go       # runNucleiScanSubflow
├── subflow_tru_insights.go # runTRUInsightsSubflow
├── subflow_report_json.go  # runReportJSONSubflow
├── subflow_html.go         # runHTMLSubflow
└── subflow_pdf.go          # runPDFSubflow

cmd/web-exposure-detection/
├── scan.go                 # Calls RunScanFlow
├── report.go               # Calls RunReportFlow
└── tru-insights.go         # Calls RunTRUInsightsFlow
```

## References

- **Current Implementation**: `pkg/webexposure/scanner/scanner.go`
- **Command Handlers**: `cmd/web-exposure-detection/*.go`
- **Common Types**: `pkg/webexposure/common/*.go`
- **Caching Architecture**: [caching.md](./caching.md)
- **Logging System**: [logging.md](./logging.md)
