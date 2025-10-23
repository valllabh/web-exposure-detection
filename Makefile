.PHONY: build test test-unit test-integration test-e2e test-validation test-all test-targets clean deps lint run help list-templates update-cve-stats update-cwe-stats security sec-gosec sec-trivy sec-nancy sec-all criticality criticality-analyze

# Binary name
BINARY_NAME=web-exposure-detection
BUILD_DIR=bin

# Build the application
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) .

# Run the application
run:
	@echo "Running $(BINARY_NAME)..."
	go run .

# Run all tests
test: test-unit

# Run unit tests
test-unit:
	@echo "Running unit tests..."
	go test -v ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -cover ./...

# Run integration tests with live targets
test-integration:
	@echo "Running integration tests with live targets..."
	@if [ ! -f "test-targets/targets.yaml" ]; then \
		echo "❌ Test targets not found. Run 'make test-targets-setup' first"; \
		exit 1; \
	fi
	go test -v ./tests/integration -tags=integration -timeout=30m

# Run end-to-end CLI tests  
test-e2e:
	@echo "Running end-to-end CLI tests..."
	@make build
	go test -v ./tests/e2e -tags=e2e -timeout=20m

# Run validation tests against golden dataset
test-validation:
	@echo "Running validation tests..."
	@if [ ! -d "test-data/golden" ]; then \
		echo "❌ Golden dataset not found. Run 'make test-data-setup' first"; \
		exit 1; \
	fi
	go test -v ./tests/validation -tags=validation -timeout=15m

# Template-specific testing (signature validation)
test-templates:
	@echo "Running template validation tests..."
	@if [ ! -f "$(BUILD_DIR)/$(BINARY_NAME)" ]; then \
		echo "❌ Binary not found. Run 'make build' first"; \
		exit 1; \
	fi
	@if [ ! -f "test-targets/template-targets.yaml" ]; then \
		echo "❌ Template test targets not found. Run 'make test-template-setup' first"; \
		exit 1; \
	fi
	go test -v ./tests/templates -tags=templates -timeout=45m

# Test specific template against known targets
test-template:
	@if [ -z "$(TEMPLATE)" ]; then \
		echo "❌ Usage: make test-template TEMPLATE=template-name"; \
		echo "📝 Available templates in scan-templates/"; \
		ls scan-templates/*.yaml 2>/dev/null | xargs -I {} basename {} .yaml || echo "No templates found"; \
		exit 1; \
	fi
	@echo "Testing template: $(TEMPLATE)"
	@if [ ! -f "$(BUILD_DIR)/$(BINARY_NAME)" ]; then \
		echo "❌ Binary not found. Run 'make build' first"; \
		exit 1; \
	fi
	go test -v ./tests/templates -tags=templates -run="TestSpecificTemplate" -timeout=10m -args -template="$(TEMPLATE)"

# Quick template validation (syntax and meanings check)
test-template-syntax:
	@echo "Validating template syntax and meanings..."
	@if [ ! -f "$(BUILD_DIR)/$(BINARY_NAME)" ]; then \
		echo "❌ Binary not found. Run 'make build' first"; \
		exit 1; \
	fi
	$(BUILD_DIR)/$(BINARY_NAME) scan --validate-templates-only

# Run performance benchmarks
test-performance:
	@echo "Running performance benchmarks..."
	go test -v ./tests/performance -bench=. -benchmem -timeout=45m

# Run all test suites
test-all: test-unit test-integration test-e2e test-validation
	@echo "✅ All test suites completed"

# Setup test targets configuration  
test-targets-setup:
	@echo "Setting up test targets..."
	@mkdir -p test-targets
	@if [ ! -f "test-targets/targets.yaml" ]; then \
		echo "✅ Test targets already exist at test-targets/targets.yaml"; \
	else \
		echo "✅ Test targets found at test-targets/targets.yaml"; \
	fi

# Setup template-specific test targets  
test-template-setup:
	@echo "Setting up template test targets..."
	@mkdir -p test-targets
	@if [ -f "test-targets/template-targets.yaml" ]; then \
		echo "✅ Template test targets found at test-targets/template-targets.yaml"; \
	else \
		echo "❌ Template test targets not found. Please create test-targets/template-targets.yaml"; \
	fi

# Setup test data and golden datasets
test-data-setup:
	@echo "Setting up test data..."
	@mkdir -p test-data/golden test-data/inputs test-data/outputs
	@echo "✅ Test data directories created"
	@echo "📝 Add golden dataset files to test-data/golden/"

# Setup complete testing infrastructure
test-setup: test-targets-setup test-template-setup test-data-setup
	@echo "Setting up complete testing infrastructure..."
	@mkdir -p tests/integration tests/e2e tests/validation tests/performance tests/templates
	@echo "✅ Testing infrastructure setup complete"

# Clean test artifacts
test-clean:
	@echo "Cleaning test artifacts..."
	@rm -rf test-data/outputs/* results/test-* reports/test-*
	@echo "✅ Test artifacts cleaned"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	go clean

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

# Lint code
lint:
	@echo "Running linters..."
	go fmt ./...
	go vet ./...
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed. Run: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

# Install the binary
install: build
	@echo "Installing $(BINARY_NAME)..."
	@cp $(BUILD_DIR)/$(BINARY_NAME) $(GOPATH)/bin/

# List all available templates
list-templates:
	@echo "📝 Available Templates:"
	@echo ""
	@echo "Root Templates:"
	@find scan-templates -maxdepth 1 -name "*.yaml" -exec basename {} .yaml \; | sort | sed 's/^/  /'
	@echo ""
	@echo "API Templates:"
	@find scan-templates/api -name "*.yaml" -exec basename {} .yaml \; 2>/dev/null | sort | sed 's/^/  /' || true
	@echo ""
	@echo "Headless Technology Templates:"
	@find scan-templates/headless -name "*.yaml" -exec basename {} .yaml \; 2>/dev/null | sort | sed 's/^/  /' || true
	@echo ""
	@echo "Usage: make test-template TEMPLATE=<template-name>"
	@echo "Example: make test-template TEMPLATE=api-host-detection"

# Update CVE statistics for findings.json using vulnx
update-cve-stats:
	@if ! command -v vulnx >/dev/null 2>&1; then \
		echo "❌ vulnx not installed. Install with: go install github.com/projectdiscovery/cvemap/cmd/vulnx@latest"; \
		exit 1; \
	fi
	@python3 scripts/update-findings-cve/update-cve-stats.py

# Update CWE statistics for findings.json using vulnx
update-cwe-stats:
	@if ! command -v vulnx >/dev/null 2>&1; then \
		echo "❌ vulnx not installed. Install with: go install github.com/projectdiscovery/cvemap/cmd/vulnx@latest"; \
		exit 1; \
	fi
	@python3 scripts/update-findings-cve/update-cwe-stats.py

# Calculate criticality scores for scan results
criticality:
	@if [ -z "$(DOMAIN)" ]; then \
		echo "❌ Usage: make criticality DOMAIN=example.com"; \
		echo "Example: make criticality DOMAIN=qualys.com"; \
		exit 1; \
	fi
	@if [ ! -f "results/$(DOMAIN)/nuclei-results/results.jsonl" ]; then \
		echo "❌ Scan results not found for $(DOMAIN)"; \
		echo "Run scan first: ./bin/web-exposure-detection scan $(DOMAIN)"; \
		exit 1; \
	fi
	@echo "Calculating criticality scores for $(DOMAIN)..."
	@python3 scripts/calculate-criticality-from-jsonl.py results/$(DOMAIN)/nuclei-results/results.jsonl

# Analyze specific domain criticality
criticality-analyze:
	@if [ -z "$(DOMAIN)" ] || [ -z "$(TARGET)" ]; then \
		echo "❌ Usage: make criticality-analyze DOMAIN=example.com TARGET=subdomain.example.com"; \
		echo "Example: make criticality-analyze DOMAIN=qualys.com TARGET=portal.qg2.apps.qualys.com"; \
		exit 1; \
	fi
	@if [ ! -f "results/$(DOMAIN)/nuclei-results/results.jsonl" ]; then \
		echo "❌ Scan results not found for $(DOMAIN)"; \
		exit 1; \
	fi
	@python3 scripts/analyze-single-domain.py results/$(DOMAIN)/nuclei-results/results.jsonl $(TARGET)

# Security scanning
security: sec-all

# Run gosec security scanner
sec-gosec:
	@echo "Running gosec security scanner..."
	@if ! command -v gosec >/dev/null 2>&1; then \
		echo "Installing gosec..."; \
		go install github.com/securego/gosec/v2/cmd/gosec@latest; \
	fi
	@gosec -fmt=json -out=gosec-report.json ./...
	@gosec ./...

# Run Trivy vulnerability scanner
sec-trivy:
	@echo "Running Trivy vulnerability scanner..."
	@if ! command -v trivy >/dev/null 2>&1; then \
		echo "❌ trivy not installed. Install from: https://github.com/aquasecurity/trivy"; \
		exit 1; \
	fi
	@trivy fs --security-checks vuln,config --severity HIGH,CRITICAL .

# Run Nancy dependency scanner
sec-nancy:
	@echo "Running Nancy dependency scanner..."
	@if ! command -v nancy >/dev/null 2>&1; then \
		echo "Installing nancy..."; \
		go install github.com/sonatype-nexus-community/nancy@latest; \
	fi
	@go list -json -deps ./... | nancy sleuth

# Run all security scans
sec-all: sec-gosec sec-nancy
	@echo "✅ All security scans completed"
	@echo "Note: Install trivy to run vulnerability scanning (sec-trivy)"

# Show help
help:
	@echo "Available targets:"
	@echo ""
	@echo "Build & Run:"
	@echo "  build              - Build the application"
	@echo "  run                - Run the application"
	@echo "  install            - Install binary to GOPATH/bin"
	@echo ""
	@echo "Application Testing:"
	@echo "  test               - Run unit tests (default)"
	@echo "  test-unit          - Run unit tests only"
	@echo "  test-integration   - Run integration tests with live targets"
	@echo "  test-e2e           - Run end-to-end CLI tests"
	@echo "  test-validation    - Run validation tests against golden dataset"
	@echo "  test-performance   - Run performance benchmarks"
	@echo "  test-all           - Run all application test suites"
	@echo "  test-coverage      - Run tests with coverage report"
	@echo ""
	@echo "Template Testing (Signature Validation):"
	@echo "  test-templates     - Run all template validation tests"
	@echo "  test-template      - Test specific template (TEMPLATE=name)"
	@echo "  test-template-syntax - Quick syntax validation of templates"
	@echo "  list-templates     - List all available templates"
	@echo ""
	@echo "Test Setup:"
	@echo "  test-setup         - Setup complete testing infrastructure"
	@echo "  test-targets-setup - Setup test targets configuration"
	@echo "  test-template-setup - Setup template-specific test targets"
	@echo "  test-data-setup    - Setup test data directories"
	@echo "  test-clean         - Clean test artifacts"
	@echo ""
	@echo "Development:"
	@echo "  deps               - Download and tidy dependencies"
	@echo "  lint               - Run code formatters and linters"
	@echo "  clean              - Clean build artifacts"
	@echo "  update-cve-stats   - Update CVE statistics for findings.json"
	@echo "  update-cwe-stats   - Update CWE statistics for findings.json"
	@echo ""
	@echo "Criticality Scoring:"
	@echo "  criticality        - Calculate criticality for all domains (DOMAIN=name)"
	@echo "  criticality-analyze - Analyze specific domain (DOMAIN=name TARGET=subdomain)"
	@echo ""
	@echo "Security Analysis:"
	@echo "  security           - Run all security scans (alias for sec-all)"
	@echo "  sec-gosec          - Run gosec security scanner"
	@echo "  sec-trivy          - Run Trivy vulnerability scanner"
	@echo "  sec-nancy          - Run Nancy dependency scanner"
	@echo "  sec-all            - Run all security scans"
	@echo ""
	@echo "Help:"
	@echo "  help               - Show this help message"