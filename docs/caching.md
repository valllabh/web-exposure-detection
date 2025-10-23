# Caching Architecture

This document describes the caching architecture used throughout the codebase.

## Principles

1. **Cache by default**: All expensive operations use caching automatically
2. **Force flag to override**: Users can use `--force` to bypass cache
3. **Private non-cached methods**: Only cached versions are exposed publicly
4. **Consistent behavior**: All cacheable operations follow the same pattern

## Cached Operations

### 1. Domain Discovery

**Location**: `pkg/webexposure/scanner/discovery.go`

**Cached Method**: `discoverDomainsWithProtocolCached()`
- Private method (lowercase) used internally by scanner
- Checks cache first unless force flag is set
- Stores results in `results/{domain}/domain-discovery-result.json`

**Non-cached Methods**:
- `DiscoverDomainsWithProtocol()` - used internally by cached method
- Not exposed in public API

**Usage**:
```go
// Internal scanner usage
discoveredDomains, err := s.discoverDomainsWithProtocolCached(
    domains, keywords, skipPassive, skipCertificate, resultsDir, force
)
```

### 2. Industry Classification

**Location**: `pkg/webexposure/industry/industry_api.go`

**Cached Method**: `ClassifyDomainIndustryWithCache()`
- Public method exposed in package API
- Checks cache first unless force flag is set
- Stores results in `results/{domain}/industry-classification.json`

**Non-cached Methods**:
- `getIndustryClassifier()` - private helper
- `ClassifyDomain()` - method on interface (required to be public)

**Public API** (`pkg/webexposure/api.go`):
```go
// Only cached version exposed
ClassifyDomainIndustryWithCache = industry.ClassifyDomainIndustryWithCache
```

**Usage**:
```go
classification, err := industry.ClassifyDomainIndustryWithCache(
    domain, cacheFile, force
)
```

### 3. Nuclei Scan Results

**Location**: `pkg/webexposure/scanner/scanner.go`

**Storage**: Progressive JSONL writer
- Results written to `results/{domain}/nuclei-results/results.jsonl`
- Converted to JSON for backward compatibility
- Reloaded when generating reports

**Methods**:
- `runNucleiScanWithStorage()` - runs scan and stores results
- `loadExistingNucleiResults()` - loads cached results
- `GenerateReportFromExistingResults()` - regenerates from cache

## Cache File Locations

All cache files are stored under `results/{domain}/`:

```
results/
└── example.com/
    ├── domain-discovery-result.json    # Domain discovery cache
    ├── industry-classification.json    # Industry classification cache
    ├── nuclei-results/
    │   ├── results.jsonl              # Progressive Nuclei results
    │   └── results.json               # Converted format
    └── web-exposure-result.json       # Final report
```

## API Design Pattern

### Public API (pkg/webexposure/api.go)

Only cached versions are exposed:

```go
// Industry functions (only cached version exposed)
var (
    ClassifyDomainIndustryWithCache = industry.ClassifyDomainIndustryWithCache
)
```

### Scanner Interface (pkg/webexposure/common/scanner.go)

High-level methods that use caching internally:

```go
type Scanner interface {
    // Complete scan pipeline (uses caching internally)
    Scan(domains []string, keywords []string) error
    ScanWithOptions(domains []string, keywords []string, templates []string, force bool) error
    ScanWithPreset(...) error

    // Individual steps (no raw discovery methods exposed)
    RunNucleiScan(targets []string, opts *NucleiOptions) ([]*output.ResultEvent, error)
    AggregateResults(results []*output.ResultEvent) (*GroupedResults, error)
}
```

### Package-level Functions

Non-cached methods are private (lowercase):

```go
// Public (cached)
func ClassifyDomainIndustryWithCache(domain, cacheFile string, force bool) (*IndustryClassification, error)

// Private (non-cached, used internally)
func getIndustryClassifier() IndustryClassifier
```

## Force Flag Behavior

The `--force` or `-f` flag clears cache and forces fresh operations:

```bash
# Use cache if available
web-exposure-detection scan example.com

# Force fresh scan (clear all caches)
web-exposure-detection scan example.com --force

# Force fresh industry classification
web-exposure-detection classify example.com --force
```

**Implementation**:
1. Check if force flag is set
2. If force, remove cache files
3. Perform fresh operation
4. Save new results to cache

## Adding New Cached Operations

To add caching to a new operation:

1. Create private non-cached method
2. Create public cached wrapper:
   ```go
   func DoSomethingWithCache(params, cacheFile string, force bool) error {
       // Clear cache if force
       if force {
           os.Remove(cacheFile)
       }

       // Check cache
       if !force {
           if result, err := loadFromCache(cacheFile); err == nil {
               return result, nil
           }
       }

       // Perform operation
       result := doSomething(params)

       // Save to cache
       saveToCache(result, cacheFile)

       return result, nil
   }
   ```

3. Expose only cached version in public API
4. Update Scanner to use cached version

## Cache Invalidation

Cache files are invalidated when:

1. User runs with `--force` flag
2. Cache file format changes (manual deletion required)
3. Results directory is deleted

There is no automatic cache expiration.
