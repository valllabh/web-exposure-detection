# Web Exposure Detection Tool Product Requirements Document (PRD)

## Goals and Background Context

### Goals
- Provide security teams with automated web exposure vulnerability detection capabilities
- Enable comprehensive subdomain discovery and vulnerability scanning in a single CLI tool
- Generate actionable security reports for external application discovery and risk assessment
- Deliver defensive security tooling that integrates Nuclei v3 and domain-scan capabilities
- Support enterprise security workflows with structured JSON reporting

### Background Context
The web-exposure-detection tool addresses the critical need for automated external attack surface discovery and vulnerability assessment. Security teams currently lack integrated tooling that combines subdomain discovery with comprehensive vulnerability scanning, often requiring multiple tools and manual correlation of results. This tool provides a unified CLI solution that leverages proven security frameworks (Nuclei v3, domain-scan) to deliver automated web exposure detection with structured reporting, enabling security teams to quickly identify and assess external-facing applications and their associated risks.

### Change Log
| Date | Version | Description | Author |
|------|---------|-------------|---------|
| 2025-08-26 | v1.0 | Initial PRD creation | John (PM Agent) |

## Requirements

### Functional Requirements

**FR1:** The system shall accept one or more domain names as input parameters for vulnerability scanning

**FR2:** The system shall perform automated subdomain discovery using the domain-scan v1.0.0 SDK with real-time progress tracking

**FR3:** The system shall support optional SSL certificate domain filtering through keywords parameter

**FR4:** The system shall execute web exposure vulnerability scanning using Nuclei v3 SDK with predefined templates

**FR5:** The system shall filter scan templates to include "tech" detection and exclude "ssl" templates

**FR6:** The system shall provide real-time progress updates during both domain discovery and vulnerability scanning phases

**FR7:** The system shall cache domain scan results in `./results/{first-domain}/domain-scan.json` format

**FR8:** The system shall support `--force` flag to bypass cache and perform fresh domain scans

**FR9:** The system shall aggregate scan results by domain and template following established bash script logic

**FR10:** The system shall generate structured JSON reports following schema v1 specification

**FR11:** The system shall classify discovered services as either "APIs" or "Web Applications" based on detection patterns

**FR12:** The system shall extract and normalize technology stack information from scan results

**FR13:** The system shall store final reports in `./results/{first-domain}/web-exposure-result.json`

### Non-Functional Requirements

**NFR1:** The system shall maintain scan rate limits of 30 requests per second to avoid overwhelming target infrastructure

**NFR2:** The system shall support concurrent template execution with maximum 5 concurrent templates

**NFR3:** The system shall complete domain discovery within 5-minute timeout with 6-minute context timeout

**NFR4:** The system shall provide clear, non-animated progress indicators suitable for CLI environments

**NFR5:** The system shall follow Go language conventions and best practices for maintainable code

**NFR6:** The system shall implement comprehensive error handling with contextual logging

**NFR7:** The system shall support cross-platform execution (Linux, macOS, Windows)

**NFR8:** The system shall maintain SDK-first architecture enabling programmatic integration

## User Interface Design Goals

### Overall UX Vision

The web-exposure-detection tool prioritizes clarity and professionalism in its command-line interface. The UX emphasizes real-time feedback without distracting animations, providing security professionals with clear status updates and actionable results. The interface follows Unix philosophy of doing one thing well while maintaining transparency about scan progress and findings.

### Key Interaction Paradigms

- **Progressive Disclosure:** Information is revealed in logical stages (domain discovery → vulnerability scanning → reporting)
- **Real-time Status Updates:** Live progress indicators show actual counts and findings as they occur
- **Structured Output:** JSON reports enable programmatic consumption while CLI output remains human-readable
- **Error Transparency:** Clear error messages with actionable guidance for resolution
- **Caching Awareness:** Users understand when cached results are used vs fresh scans

### Core Screens and Views

- **Command Help Interface:** Comprehensive usage documentation and flag descriptions
- **Domain Discovery Progress View:** Real-time subdomain enumeration with running counts
- **Vulnerability Scan Progress View:** Per-target scan status with timing and findings
- **Results Summary View:** High-level statistics before detailed report generation
- **Error and Warning Display:** Clear problem identification with resolution guidance

### Accessibility: None
*CLI tools inherently provide screen reader compatibility through text-based output*

### Branding

Minimal security-focused aesthetic using standard CLI conventions. Output uses appropriate Unicode characters (🔍, 📋, 🚨) for visual hierarchy while maintaining professional tone. No custom branding requirements - follows standard security tooling conventions.

### Target Device and Platforms: Cross-Platform
*Supports Linux, macOS, and Windows environments where Go applications can execute*

## Technical Assumptions

### Repository Structure: Monorepo
*Single repository containing CLI tool, SDK packages, templates, and documentation*

### Service Architecture
**Monolith with SDK-First Design:** The application follows a monolithic CLI architecture with a well-defined SDK layer (`pkg/webexposure/`) that can be consumed programmatically. The CLI commands in `cmd/web-exposure-detection/` serve as facades over the SDK functionality, enabling both standalone tool usage and library integration.

### Testing Requirements
**Full Testing Pyramid:** Comprehensive testing approach including unit tests for SDK functions, integration tests for external service interactions (Nuclei, domain-scan), and end-to-end CLI testing. Mock external dependencies to enable reliable testing without network calls.

### Additional Technical Assumptions and Requests

- **Language:** Go 1.21+ for cross-platform compatibility and security tooling ecosystem alignment
- **CLI Framework:** Cobra for command-line interface with Viper for configuration management
- **External Dependencies:** 
  - Nuclei v3 SDK for vulnerability scanning
  - domain-scan v1.0.0 SDK for subdomain discovery
- **Build System:** Standard Go toolchain with Makefile for common development tasks
- **Configuration:** YAML-based configuration files with environment variable overrides
- **Logging:** Structured logging for debugging and audit trails
- **Output Formats:** JSON for programmatic consumption, human-readable CLI output
- **Error Handling:** Comprehensive error handling with context preservation
- **Performance:** Rate limiting and concurrency controls to prevent infrastructure impact
- **Security:** No credential storage, defensive-only scanning capabilities
- **Deployment:** Single binary distribution with no external runtime dependencies

## Epic List

**Epic 1: Foundation & Core Infrastructure**
Establish project infrastructure, CLI framework, SDK architecture, and basic configuration management with a simple health-check capability.

**Epic 2: Domain Discovery Integration** 
Implement subdomain discovery using domain-scan v1.0.0 SDK with real-time progress tracking and result caching.

**Epic 3: Vulnerability Scanning Engine**
Integrate Nuclei v3 SDK for web exposure detection with template filtering and concurrent scanning capabilities.

**Epic 4: Results Processing & Reporting**
Implement result aggregation, classification logic, and structured JSON report generation following schema v1.

## Epic 1: Foundation & Core Infrastructure

**Epic Goal:** Establish the foundational project infrastructure with CLI framework, SDK architecture, configuration management, and basic operational capabilities. This epic delivers a working CLI tool with health-check functionality that can be deployed and extended, providing the technical foundation for all subsequent development while demonstrating the tool's basic operational readiness.

### Story 1.1: Project Setup and CLI Framework
As a developer,
I want a properly structured Go project with CLI framework,
so that I can build and execute the web-exposure-detection tool with proper command structure.

#### Acceptance Criteria
1. Go module initialized with proper naming and dependency management
2. Cobra CLI framework integrated with root command and help system
3. Viper configuration management configured for YAML and environment variables
4. Project structure follows Go conventions with cmd/, pkg/, and internal/ directories
5. Makefile provides build, test, clean, and lint targets
6. Basic CI/CD pipeline configured for automated testing and building
7. README updated with build and usage instructions

### Story 1.2: SDK Architecture Foundation
As a developer integrating the tool,
I want a clean SDK interface in pkg/webexposure,
so that I can programmatically use scanning capabilities without CLI dependencies.

#### Acceptance Criteria
1. pkg/webexposure package created with public API interfaces
2. Scanner struct with New() constructor function implemented
3. Basic configuration struct with validation methods
4. Error handling patterns established with wrapped errors and context
5. Logging framework integrated with structured logging capabilities
6. SDK interface documented with Go doc comments
7. Unit tests demonstrate interface usage without CLI dependencies

### Story 1.3: Configuration Management System
As a security operator,
I want flexible configuration options,
so that I can customize tool behavior for different environments and use cases.

#### Acceptance Criteria
1. Default configuration file created at $HOME/.web-exposure-detection.yaml
2. Configuration struct supports all CLI flags and options
3. Environment variable overrides work for all configuration options
4. --config flag allows custom configuration file path
5. Configuration validation prevents invalid settings
6. Configuration examples provided in configs/ directory
7. Viper properly loads and merges configuration from all sources

### Story 1.4: Health Check and Basic CLI Operations
As a security operator,
I want basic operational commands,
so that I can verify tool installation and configuration before running scans.

#### Acceptance Criteria
1. Health check command validates tool installation and dependencies
2. Version command displays tool version and build information
3. Config command shows current configuration values (sanitized)
4. Basic scan command structure exists (returns "not implemented" message)
5. Help system provides comprehensive usage documentation
6. Error messages are clear and provide actionable guidance
7. Tool builds to single binary with no external runtime dependencies

## Epic 2: Domain Discovery Integration

**Epic Goal:** Integrate domain-scan v1.0.0 SDK to provide comprehensive subdomain discovery with real-time progress tracking and intelligent caching. This epic delivers the first major scanning capability, enabling security teams to discover external-facing subdomains with optional SSL certificate filtering, establishing the foundation for vulnerability assessment workflows.

### Story 2.1: Domain-Scan SDK Integration
As a developer,
I want domain-scan v1.0.0 SDK integrated into the web-exposure-detection tool,
so that subdomain discovery functionality is available through both CLI and SDK interfaces.

#### Acceptance Criteria
1. domain-scan v1.0.0 SDK added as Go module dependency
2. DomainScanner interface created in pkg/webexposure with DiscoverDomains method
3. domain-scan SDK configuration mapped to tool's configuration system
4. Error handling wraps domain-scan errors with additional context
5. Unit tests mock domain-scan SDK to verify integration without network calls
6. SDK interface supports timeout configuration and cancellation
7. Documentation explains domain-scan integration and configuration options

### Story 2.2: Real-Time Progress Tracking System
As a security operator,
I want to see real-time progress during subdomain discovery,
so that I understand scan status and can estimate completion time.

#### Acceptance Criteria
1. Progress adapter bridges domain-scan SDK callbacks to CLI progress interface
2. Live domain count updates display as "Found X live domains so far..."
3. Clear stage progression messages indicate discovery phases
4. Per-target timing information shows scan duration
5. Progress updates work through both CLI and SDK interfaces
6. No spinner animations - uses clear status messages only
7. Progress system handles cancellation and error states gracefully

### Story 2.3: Keywords-Based SSL Certificate Filtering
As a security operator,
I want to filter discovered domains using SSL certificate keywords,
so that I can focus on organizationally relevant subdomains.

#### Acceptance Criteria
1. --keywords CLI flag accepts comma-separated list of filter terms
2. Keywords parameter passed correctly to domain-scan SDK configuration
3. Empty keywords default to auto-extraction from target domain names
4. Keywords filtering affects SSL certificate domain matching in domain-scan
5. CLI help documentation explains keywords usage and examples
6. SDK interface exposes keywords parameter for programmatic use
7. Configuration system supports keywords in YAML and environment variables

### Story 2.4: Domain Discovery Caching and Results Storage
As a security operator,
I want domain discovery results cached locally,
so that I can skip expensive subdomain enumeration on subsequent scans.

#### Acceptance Criteria
1. Domain scan results stored in ./results/{first-domain}/domain-scan.json
2. Cache validity check prevents stale results usage
3. --force flag bypasses cache and performs fresh domain scan
4. Cached results properly loaded and validated before use
5. Results directory structure created automatically
6. Cache file format supports both original and discovered domains
7. Error handling covers cache corruption and disk space issues

### Story 2.5: Domain Discovery CLI Command Implementation
As a security operator,
I want to execute subdomain discovery via scan command,
so that I can discover external-facing domains for my organization.

#### Acceptance Criteria
1. scan command accepts multiple domain arguments
2. Domain discovery executes with real-time progress display
3. Results summary shows total domains found (original + discovered)
4. Live domain extraction from domain-scan results works correctly
5. Command handles timeout scenarios gracefully
6. Error messages provide actionable guidance for common failures
7. Successful completion prepares for vulnerability scanning phase

## Epic 3: Vulnerability Scanning Engine

**Epic Goal:** Integrate Nuclei v3 SDK to provide comprehensive web exposure vulnerability scanning with template filtering, concurrent execution, and live progress tracking. This epic delivers the core security scanning capability, enabling security teams to identify vulnerabilities and technology stacks across discovered domains with professional progress reporting and result storage.

### Story 3.1: Nuclei v3 SDK Integration
As a developer,
I want Nuclei v3 SDK integrated with proper configuration,
so that vulnerability scanning capabilities are available through both CLI and SDK interfaces.

#### Acceptance Criteria
1. Nuclei v3 SDK added as Go module dependency with version pinning
2. VulnerabilityScanner interface created in pkg/webexposure with RunScan method
3. Nuclei SDK configured with tech tag inclusion and ssl tag exclusion
4. Global rate limiting set to 30 requests per second
5. Template concurrency limited to 5 concurrent templates
6. Error handling wraps Nuclei errors with scan context
7. Unit tests mock Nuclei SDK to verify configuration without network calls

### Story 3.2: Template Management and Filtering
As a security operator,
I want vulnerability scanning to use appropriate templates,
so that I get relevant security findings without unnecessary noise.

#### Acceptance Criteria
1. Template filtering includes "tech" tags for technology detection
2. Template filtering excludes "ssl" tags to avoid SSL-specific tests
3. scan-templates/ directory integration with Nuclei template loading
4. Template validation ensures required templates are available
5. Template loading progress displayed during scan initialization
6. Custom template directory support through configuration
7. Template clustering optimization handled by Nuclei SDK

### Story 3.3: Concurrent Scanning with Progress Tracking
As a security operator,
I want real-time visibility into vulnerability scanning progress,
so that I can monitor scan status and understand findings as they occur.

#### Acceptance Criteria
1. Per-target scanning displays "Testing {domain}..." messages
2. Live findings reported as "Found: {detection} on {domain}"
3. Scan completion timing displayed per target
4. Overall progress shows tests performed and findings count
5. Concurrent scanning respects rate limits and template concurrency
6. Progress system handles scan errors and timeouts gracefully
7. No spinner animations - uses clear status messages only

### Story 3.4: Results Processing and Storage
As a developer,
I want Nuclei scan results properly captured and stored,
so that subsequent processing and reporting can access structured findings.

#### Acceptance Criteria
1. Nuclei results stored in ./results/{first-domain}/nuclei-results directory
2. Results format preserves all Nuclei output fields and metadata
3. Result processing extracts domains, templates, and finding details
4. Error handling covers result storage failures and disk space issues
5. Results validation ensures data integrity before storage
6. Result file naming convention supports multiple scan sessions
7. SDK interface provides access to stored results for programmatic use

### Story 3.5: Vulnerability Scanning CLI Command Implementation
As a security operator,
I want to execute vulnerability scanning against discovered domains,
So that I can identify security exposures and technology stacks.

#### Acceptance Criteria
1. Scan command continues from domain discovery to vulnerability scanning
2. Vulnerability scanning accepts domains from previous discovery phase
3. Real-time progress displays per-target scanning status
4. Scan results summary shows total tests performed and findings
5. Command handles scanning errors and timeouts gracefully
6. Successful completion prepares results for aggregation and reporting
7. Error messages provide actionable guidance for scan failures

## Epic 4: Results Processing & Reporting

**Epic Goal:** Implement comprehensive result aggregation, classification, and structured JSON report generation following schema v1 specification. This epic completes the scanning pipeline by transforming raw vulnerability data into actionable security reports, enabling security teams to understand their external attack surface through professional documentation and programmatic integration capabilities.

### Story 4.1: Result Aggregation and Grouping Logic
As a developer,
I want Nuclei scan results aggregated by domain and template,
so that findings are properly organized for classification and reporting.

#### Acceptance Criteria
1. Result aggregation groups findings by target domain and template ID
2. Grouping logic follows bash script patterns from ref/run-result-aggr.sh
3. Duplicate finding elimination based on domain-template combinations
4. Result metadata preserved including timestamps and scan context
5. Aggregation handles partial scan results and error conditions
6. Unit tests verify grouping logic with various result scenarios
7. SDK interface exposes aggregated results for programmatic access

### Story 4.2: API vs Web Application Classification
As a security operator,
I want discovered services classified as APIs or Web Applications,
so that I can prioritize security assessment based on service types.

#### Acceptance Criteria
1. Classification logic distinguishes APIs from Web Applications using detection patterns
2. API classification uses keyword matching and endpoint pattern recognition
3. Web Application classification identifies CMS, frameworks, and web servers
4. Classification rules follow reference implementation from bash scripts
5. Technology extraction normalizes framework and server names
6. Classification handles ambiguous cases with appropriate defaults
7. Results include confidence indicators for classification decisions

### Story 4.3: Technology Stack Extraction and Normalization
As a security operator,
I want technology information extracted and normalized,
so that I can understand the technical landscape of discovered services.

#### Acceptance Criteria
1. Technology extraction uses findings.json for display metadata mapping
2. Framework detection identifies specific versions where available
3. Web server identification includes nginx, Apache, IIS variants
4. Technology normalization handles case variations and aliases
5. Technology counting provides accurate statistics for report summary
6. Regex patterns normalize technology names to standard formats
7. Unknown technologies logged for future template enhancement

### Story 4.4: JSON Report Generation (Schema v1)
As a security operator,
I want structured JSON reports following schema v1,
so that I can integrate findings with other security tools and workflows.

#### Acceptance Criteria
1. JSON report follows schema v1 specification from sample-exposure-report.md
2. Report metadata includes title, date, and target domain information
3. Summary section provides accurate counts and statistics
4. APIs found section lists discovered API endpoints with findings
5. Web applications section details discovered web apps with technologies
6. Technologies detected section provides comprehensive technology inventory
7. Report generation handles edge cases like zero findings gracefully

### Story 4.5: Report Output and Storage Management
As a security operator,
I want reports generated and stored in predictable locations,
so that I can easily access and share security assessment results.

#### Acceptance Criteria
1. Final reports stored in ./results/{first-domain}/web-exposure-result.json
2. Report generation message displayed with file location
3. Report file permissions set appropriately for security content
4. Report naming convention supports multiple scan sessions
5. Storage error handling provides clear guidance for disk issues
6. SDK interface allows custom report output locations
7. Report validation ensures JSON schema compliance before writing