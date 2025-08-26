# Testing Architecture for Web Exposure Detection Tool

## Overview

This document defines the comprehensive testing strategy for the web exposure detection CLI tool, providing multiple test layers to ensure accuracy, reliability, and performance of vulnerability scanning.

## Current State vs Target

### Current State ✅
- Basic unit tests for SDK core functions (`pkg/webexposure/scanner_test.go`)
- Makefile with basic `test` and `test-coverage` targets
- Test coverage for result aggregation, classification, and report generation

### Target Architecture 🎯
- **Multi-layer testing** with unit, integration, e2e, and validation tests
- **Live website testing** against controlled targets  
- **Golden dataset validation** for result accuracy
- **Performance benchmarking** and regression testing
- **Automated test infrastructure** setup and management

## Testing Layers

### 1. Unit Tests (`make test-unit`)
**Purpose:** Test individual SDK functions in isolation
**Location:** `pkg/webexposure/*_test.go`
**Coverage:** Core business logic, data processing, classification rules

**Current Status:** ✅ Implemented
- Result aggregation logic
- API/WebApp classification 
- Report generation
- Domain discovery fallbacks

### 2. Integration Tests (`make test-integration`)
**Purpose:** Test complete scan pipeline against live targets
**Location:** `tests/integration/`  
**Dependencies:** `test-targets/targets.yaml`

**Key Test Scenarios:**
```yaml
# Example test target configuration
test_targets:
  - name: "httpbin-basic"
    domain: "httpbin.org"
    keywords: []
    expected_findings: ["live-domain"]
    timeout: "60s"
  
  - name: "nginx-tech-detection" 
    domain: "nginx.org"
    keywords: ["docs", "api"]
    expected_findings: ["live-domain", "nginx-detect"]
    timeout: "120s"
    
  - name: "jsonplaceholder-api"
    domain: "jsonplaceholder.typicode.com"
    keywords: ["api"]
    expected_findings: ["live-domain", "api-server-detection"]
    timeout: "90s"
```

**Test Coverage:**
- Domain discovery with real DNS lookups
- Nuclei scanning against live targets
- Template matching accuracy
- Result aggregation with real data
- Report generation end-to-end

### 3. End-to-End CLI Tests (`make test-e2e`)
**Purpose:** Test complete CLI workflows as end users would
**Location:** `tests/e2e/`
**Dependencies:** Built binary

**Test Scenarios:**
```bash
# CLI command variations
./bin/web-exposure-detection scan httpbin.org
./bin/web-exposure-detection scan nginx.org --keywords "docs,api"
./bin/web-exposure-detection scan multiple.com another.com
```

**Validation Points:**
- CLI argument parsing  
- Progress output formatting
- Report file generation
- Exit codes and error handling
- Cache functionality (`--force` flag)

### 4. Validation Tests (`make test-validation`)
**Purpose:** Verify scan result accuracy against known datasets
**Location:** `tests/validation/`
**Dependencies:** `test-data/golden/`

**Golden Dataset Structure:**
```
test-data/golden/
├── httpbin-org/
│   ├── expected-domains.json
│   ├── expected-nuclei-results.json  
│   └── expected-report.json
├── nginx-org/
│   └── ...
└── validation-rules.yaml
```

**Validation Checks:**
- Domain discovery completeness
- Template detection accuracy
- Classification correctness (API vs WebApp)
- Technology extraction precision
- Report schema compliance

### 5. Performance Tests (`make test-performance`)
**Purpose:** Benchmark scan performance and detect regressions
**Location:** `tests/performance/`

**Benchmark Metrics:**
```go
func BenchmarkDomainDiscovery(b *testing.B) {
  // Measure domain-scan performance
}

func BenchmarkNucleiScan(b *testing.B) {
  // Measure nuclei scanning speed
}

func BenchmarkReportGeneration(b *testing.B) {
  // Measure report processing time
}
```

**Performance Targets:**
- Domain discovery: < 5 minutes for 50 domains
- Nuclei scanning: < 30 seconds per domain
- Report generation: < 5 seconds
- Memory usage: < 500MB peak

## Test Infrastructure

### Test Target Management
**Configuration:** `test-targets/targets.yaml`
**Purpose:** Controlled, predictable test domains

**Selection Criteria:**
- Stable, publicly accessible domains
- Known technology stacks for validation
- Different response characteristics (APIs, static sites, etc.)
- Reliable uptime for CI/CD environments

### Golden Dataset Management  
**Location:** `test-data/golden/`
**Purpose:** Expected results for validation testing

**Update Process:**
1. Run scans against test targets manually
2. Verify results are accurate
3. Store as golden dataset files
4. Version control golden data changes

### Test Environment Setup
**Command:** `make test-setup`
**Creates:**
```
test-targets/
├── targets.yaml
tests/
├── integration/
├── e2e/
├── validation/
└── performance/  
test-data/
├── golden/
├── inputs/
└── outputs/
```

## Testing Workflow

### Development Workflow
```bash
# 1. Setup testing infrastructure (one-time)
make test-setup

# 2. Run tests during development
make test-unit          # Fast feedback loop
make test-integration   # Verify against live targets  
make test-e2e          # Full CLI validation

# 3. Before commit/PR
make test-all          # Complete test suite
make lint              # Code quality checks
```

### CI/CD Integration
```yaml
# Example GitHub Actions workflow
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup Go
        uses: actions/setup-go@v3
      - name: Setup test infrastructure
        run: make test-setup
      - name: Run unit tests
        run: make test-unit
      - name: Run integration tests  
        run: make test-integration
      - name: Run validation tests
        run: make test-validation
```

### Test Maintenance
- **Golden dataset updates:** Monthly or after template changes
- **Test target validation:** Weekly uptime checks  
- **Performance baseline updates:** After major releases
- **Test cleanup:** `make test-clean` removes artifacts

## Implementation Priority

### Phase 1: Foundation (Week 1) 🔴
- [ ] Setup test infrastructure (`make test-setup`)
- [ ] Create initial test targets configuration
- [ ] Implement basic integration tests

### Phase 2: Validation (Week 2) 🟡  
- [ ] Create golden dataset for 3-5 test targets
- [ ] Implement validation test framework
- [ ] Add E2E CLI testing

### Phase 3: Performance & CI (Week 3) 🟢
- [ ] Add performance benchmarks
- [ ] Setup CI/CD integration
- [ ] Documentation and training

## Test Execution Examples

```bash
# Setup (one-time)
make test-setup

# Development cycle
make test-unit                    # 30 seconds
make test-integration            # 5-10 minutes  
make test-validation             # 2-3 minutes

# Full validation
make test-all                    # 10-15 minutes

# Performance tracking  
make test-performance            # 15-20 minutes

# Cleanup
make test-clean
```

## Success Metrics

### Test Coverage
- Unit test coverage: >85%
- Integration test coverage: All major workflows
- E2E test coverage: All CLI commands and flags
- Validation accuracy: >95% against golden dataset

### Performance Targets
- Test execution time: <15 minutes for full suite
- CI/CD integration: <20 minutes including setup
- Flaky test rate: <2%

### Quality Gates
- All tests must pass before merge
- Performance regression threshold: 20% slower
- New features require corresponding tests
- Golden dataset updated with template changes

---

This architecture provides comprehensive testing for the web exposure detection tool, ensuring both accuracy and reliability of vulnerability scanning results through multiple validation layers.