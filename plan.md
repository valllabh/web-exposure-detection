Web Exposure Detection SDK - Complete Implementation Plan                                                                                                                      │
     │                                                                                                                                                                                │
     │ Project Architecture: SDK-First with Report Builder                                                                                                                            │
     │                                                                                                                                                                                │
     │ Data Flow Architecture                                                                                                                                                         │
     │                                                                                                                                                                                │
     │ Domains Input → Domain-Scan (with optional keywords) → Live Domains List → Nuclei Scanner → Raw Results → Report Builder → Formatted JSON Report                               │
     │                                                                                                                                                                                │
     │ SDK Architecture                                                                                                                                                               │
     │                                                                                                                                                                                │
     │ 1. Core SDK Interface                                                                                                                                                          │
     │                                                                                                                                                                                │
     │ pkg/webexposure/ - Main SDK                                                                                                                                                    │
     │                                                                                                                                                                                │
     │ type Scanner interface {                                                                                                                                                       │
     │     // Complete scan pipeline                                                                                                                                                  │
     │     Scan(domains []string, opts *ScanOptions) (*Report, error)                                                                                                                 │
     │                                                                                                                                                                                │
     │     // Individual pipeline steps                                                                                                                                               │
     │     DiscoverDomains(domains []string, keywords []string) ([]string, error)                                                                                                     │
     │     ScanVulnerabilities(targets []string, opts *NucleiOptions) (*NucleiResults, error)                                                                                         │
     │     GenerateReport(nucleiResults *NucleiResults, opts *ReportOptions) (*Report, error)                                                                                         │
     │ }                                                                                                                                                                              │
     │                                                                                                                                                                                │
     │ type ScanOptions struct {                                                                                                                                                      │
     │     Keywords []string           // Optional: SSL cert filtering (default: empty)                                                                                               │
     │     Nuclei   *NucleiOptions     // Nuclei scanning configuration                                                                                                               │
     │     Report   *ReportOptions     // Report generation configuration                                                                                                             │
     │ }                                                                                                                                                                              │
     │                                                                                                                                                                                │
     │ 2. Report Builder Module                                                                                                                                                       │
     │                                                                                                                                                                                │
     │ pkg/report/ - Report Generation                                                                                                                                                │
     │                                                                                                                                                                                │
     │ type ReportBuilder interface {                                                                                                                                                 │
     │     // Generate formatted JSON report from Nuclei results                                                                                                                      │
     │     GenerateReport(nucleiResults *NucleiResults, opts *ReportOptions) (*Report, error)                                                                                         │
     │                                                                                                                                                                                │
     │     // Add meaning mappings using scan-template-meanings.json                                                                                                                  │
     │     AddMeanings(report *Report) error                                                                                                                                          │
     │                                                                                                                                                                                │
     │     // Export to different formats                                                                                                                                             │
     │     ExportJSON(report *Report, outputPath string) error                                                                                                                        │
     │ }                                                                                                                                                                              │
     │                                                                                                                                                                                │
     │ type ReportOptions struct {                                                                                                                                                    │
     │     OutputFormat    string            // "json", "html", "csv"                                                                                                                 │
     │     IncludeMeanings bool              // Use scan-template-meanings.json                                                                                                       │
     │     GroupBy         string            // "domain", "severity", "template"                                                                                                      │
     │     CustomFields    map[string]string // Additional metadata                                                                                                                   │
     │ }                                                                                                                                                                              │
     │                                                                                                                                                                                │
     │ type Report struct {                                                                                                                                                           │
     │     Metadata    *ReportMetadata    `json:"metadata"`                                                                                                                           │
     │     Domains     []string           `json:"domains_scanned"`                                                                                                                    │
     │     Findings    []*Finding         `json:"findings"`                                                                                                                           │
     │     Summary     *Summary           `json:"summary"`                                                                                                                            │
     │     Meanings    map[string]string  `json:"template_meanings,omitempty"`                                                                                                        │
     │ }                                                                                                                                                                              │
     │                                                                                                                                                                                │
     │ type Finding struct {                                                                                                                                                          │
     │     Domain       string            `json:"domain"`                                                                                                                             │
     │     TemplateID   string            `json:"template_id"`                                                                                                                        │
     │     TemplateName string            `json:"template_name"`                                                                                                                      │
     │     Severity     string            `json:"severity"`                                                                                                                           │
     │     Description  string            `json:"description"`                                                                                                                        │
     │     Meaning      string            `json:"meaning,omitempty"` // From scan-template-meanings.json                                                                              │
     │     MatchedAt    string            `json:"matched_at"`                                                                                                                         │
     │     RawNuclei    interface{}       `json:"raw_nuclei_result"`                                                                                                                  │
     │ }                                                                                                                                                                              │
     │                                                                                                                                                                                │
     │ 3. Pipeline Implementation                                                                                                                                                     │
     │                                                                                                                                                                                │
     │ Complete Scan Pipeline                                                                                                                                                         │
     │                                                                                                                                                                                │
     │ func (s *Scanner) Scan(domains []string, opts *ScanOptions) (*Report, error) {                                                                                                 │
     │     // Step 1: Domain Discovery                                                                                                                                                │
     │     discoveredDomains, err := s.DiscoverDomains(domains, opts.Keywords)                                                                                                        │
     │     if err != nil {                                                                                                                                                            │
     │         return nil, fmt.Errorf("domain discovery failed: %w", err)                                                                                                             │
     │     }                                                                                                                                                                          │
     │                                                                                                                                                                                │
     │     // Step 2: Vulnerability Scanning                                                                                                                                          │
     │     nucleiResults, err := s.ScanVulnerabilities(discoveredDomains, opts.Nuclei)                                                                                                │
     │     if err != nil {                                                                                                                                                            │
     │         return nil, fmt.Errorf("nuclei scanning failed: %w", err)                                                                                                              │
     │     }                                                                                                                                                                          │
     │                                                                                                                                                                                │
     │     // Step 3: Report Generation                                                                                                                                               │
     │     report, err := s.GenerateReport(nucleiResults, opts.Report)                                                                                                                │
     │     if err != nil {                                                                                                                                                            │
     │         return nil, fmt.Errorf("report generation failed: %w", err)                                                                                                            │
     │     }                                                                                                                                                                          │
     │                                                                                                                                                                                │
     │     return report, nil                                                                                                                                                         │
     │ }                                                                                                                                                                              │
     │                                                                                                                                                                                │
     │ 4. CLI as SDK Facade                                                                                                                                                           │
     │                                                                                                                                                                                │
     │ CLI Implementation                                                                                                                                                             │
     │                                                                                                                                                                                │
     │ func scanCmd() *cobra.Command {                                                                                                                                                │
     │     var (                                                                                                                                                                      │
     │         keywords     []string                                                                                                                                                  │
     │         outputFile   string                                                                                                                                                    │
     │         outputFormat string                                                                                                                                                    │
     │         groupBy      string                                                                                                                                                    │
     │     )                                                                                                                                                                          │
     │                                                                                                                                                                                │
     │     cmd := &cobra.Command{                                                                                                                                                     │
     │         Use: "scan [domains...]",                                                                                                                                              │
     │         RunE: func(cmd *cobra.Command, args []string) error {                                                                                                                  │
     │             scanner, err := webexposure.New()                                                                                                                                  │
     │             if err != nil {                                                                                                                                                    │
     │                 return err                                                                                                                                                     │
     │             }                                                                                                                                                                  │
     │                                                                                                                                                                                │
     │             // Generate complete report using SDK                                                                                                                              │
     │             report, err := scanner.Scan(args, &webexposure.ScanOptions{                                                                                                        │
     │                 Keywords: keywords,                                                                                                                                            │
     │                 Nuclei: &webexposure.NucleiOptions{                                                                                                                            │
     │                     TemplatesPath: "./scan-templates",                                                                                                                         │
     │                     IncludeTags:   []string{"tech"},                                                                                                                           │
     │                     ExcludeTags:   []string{"ssl"},                                                                                                                            │
     │                     RateLimit:     30,                                                                                                                                         │
     │                     BulkSize:      10,                                                                                                                                         │
     │                     Concurrency:   5,                                                                                                                                          │
     │                 },                                                                                                                                                             │
     │                 Report: &webexposure.ReportOptions{                                                                                                                            │
     │                     OutputFormat:    outputFormat,                                                                                                                             │
     │                     IncludeMeanings: true,                                                                                                                                     │
     │                     GroupBy:         groupBy,                                                                                                                                  │
     │                 },                                                                                                                                                             │
     │             })                                                                                                                                                                 │
     │             if err != nil {                                                                                                                                                    │
     │                 return err                                                                                                                                                     │
     │             }                                                                                                                                                                  │
     │                                                                                                                                                                                │
     │             // Export report                                                                                                                                                   │
     │             if outputFile != "" {                                                                                                                                              │
     │                 return report.ExportJSON(outputFile)                                                                                                                           │
     │             }                                                                                                                                                                  │
     │                                                                                                                                                                                │
     │             // Print to stdout                                                                                                                                                 │
     │             return report.PrintJSON()                                                                                                                                          │
     │         },                                                                                                                                                                     │
     │     }                                                                                                                                                                          │
     │                                                                                                                                                                                │
     │     cmd.Flags().StringSliceVar(&keywords, "keywords", []string{},                                                                                                              │
     │         "Optional keywords for SSL certificate domain filtering")                                                                                                              │
     │     cmd.Flags().StringVar(&outputFile, "output", "",                                                                                                                           │
     │         "Output file path for JSON report")                                                                                                                                    │
     │     cmd.Flags().StringVar(&outputFormat, "format", "json",                                                                                                                     │
     │         "Output format: json, html, csv")                                                                                                                                      │
     │     cmd.Flags().StringVar(&groupBy, "group-by", "domain",                                                                                                                      │
     │         "Group results by: domain, severity, template")                                                                                                                        │
     │                                                                                                                                                                                │
     │     return cmd                                                                                                                                                                 │
     │ }                                                                                                                                                                              │
     │                                                                                                                                                                                │
     │ 5. Report Builder Implementation                                                                                                                                               │
     │                                                                                                                                                                                │
     │ Using scan-template-meanings.json                                                                                                                                              │
     │                                                                                                                                                                                │
     │ type ReportBuilder struct {                                                                                                                                                    │
     │     meanings map[string]string // Loaded from scan-template-meanings.json                                                                                                      │
     │ }                                                                                                                                                                              │
     │                                                                                                                                                                                │
     │ func (rb *ReportBuilder) GenerateReport(nucleiResults *NucleiResults, opts *ReportOptions) (*Report, error) {                                                                  │
     │     report := &Report{                                                                                                                                                         │
     │         Metadata: &ReportMetadata{                                                                                                                                             │
     │             Timestamp:     time.Now(),                                                                                                                                         │
     │             Version:       "1.0.0",                                                                                                                                            │
     │             TotalDomains:  len(nucleiResults.Domains),                                                                                                                         │
     │             TotalFindings: len(nucleiResults.Results),                                                                                                                         │
     │         },                                                                                                                                                                     │
     │         Domains:  nucleiResults.Domains,                                                                                                                                       │
     │         Findings: []*Finding{},                                                                                                                                                │
     │     }                                                                                                                                                                          │
     │                                                                                                                                                                                │
     │     // Process each Nuclei result                                                                                                                                              │
     │     for _, result := range nucleiResults.Results {                                                                                                                             │
     │         finding := &Finding{                                                                                                                                                   │
     │             Domain:       result.Host,                                                                                                                                         │
     │             TemplateID:   result.TemplateID,                                                                                                                                   │
     │             TemplateName: result.Info.Name,                                                                                                                                    │
     │             Severity:     result.Info.Severity,                                                                                                                                │
     │             Description:  result.Info.Description,                                                                                                                             │
     │             MatchedAt:    result.Timestamp,                                                                                                                                    │
     │             RawNuclei:    result, // Include raw Nuclei data                                                                                                                   │
     │         }                                                                                                                                                                      │
     │                                                                                                                                                                                │
     │         // Add meaning from scan-template-meanings.json                                                                                                                        │
     │         if opts.IncludeMeanings {                                                                                                                                              │
     │             if meaning, exists := rb.meanings[result.TemplateID]; exists {                                                                                                     │
     │                 finding.Meaning = meaning                                                                                                                                      │
     │             }                                                                                                                                                                  │
     │         }                                                                                                                                                                      │
     │                                                                                                                                                                                │
     │         report.Findings = append(report.Findings, finding)                                                                                                                     │
     │     }                                                                                                                                                                          │
     │                                                                                                                                                                                │
     │     // Generate summary                                                                                                                                                        │
     │     report.Summary = rb.generateSummary(report.Findings)                                                                                                                       │
     │                                                                                                                                                                                │
     │     return report, nil                                                                                                                                                         │
     │ }                                                                                                                                                                              │
     │                                                                                                                                                                                │
     │ 6. Configuration with Report Options                                                                                                                                           │
     │                                                                                                                                                                                │
     │ YAML Configuration                                                                                                                                                             │
     │                                                                                                                                                                                │
     │ discovery:                                                                                                                                                                     │
     │   keywords: []              # Optional SSL cert filtering                                                                                                                      │
     │   ports: [80, 443, 8080]                                                                                                                                                       │
     │   profile: "comprehensive"                                                                                                                                                     │
     │                                                                                                                                                                                │
     │ nuclei:                                                                                                                                                                        │
     │   templates_path: "./scan-templates"                                                                                                                                           │
     │   include_tags: ["tech"]                                                                                                                                                       │
     │   exclude_tags: ["ssl"]                                                                                                                                                        │
     │   rate_limit: 30                                                                                                                                                               │
     │   bulk_size: 10                                                                                                                                                                │
     │   concurrency: 5                                                                                                                                                               │
     │                                                                                                                                                                                │
     │ report:                                                                                                                                                                        │
     │   output_format: "json"                                                                                                                                                        │
     │   include_meanings: true                                                                                                                                                       │
     │   group_by: "domain"                                                                                                                                                           │
     │   custom_fields:                                                                                                                                                               │
     │     scanner_version: "1.0.0"                                                                                                                                                   │
     │     environment: "production"                                                                                                                                                  │
     │                                                                                                                                                                                │
     │ 7. Updated CLAUDE.md Structure                                                                                                                                                 │
     │                                                                                                                                                                                │
     │ SDK Usage Documentation                                                                                                                                                        │
     │                                                                                                                                                                                │
     │ ## Complete Scan Pipeline                                                                                                                                                      │
     │                                                                                                                                                                                │
     │ ```go                                                                                                                                                                          │
     │ // Full pipeline with report generation                                                                                                                                        │
     │ scanner := webexposure.New()                                                                                                                                                   │
     │ report, err := scanner.Scan(domains, &webexposure.ScanOptions{                                                                                                                 │
     │     Keywords: []string{"staging", "prod"}, // Optional                                                                                                                         │
     │     Report: &webexposure.ReportOptions{                                                                                                                                        │
     │         OutputFormat:    "json",                                                                                                                                               │
     │         IncludeMeanings: true,                                                                                                                                                 │
     │         GroupBy:         "domain",                                                                                                                                             │
     │     },                                                                                                                                                                         │
     │ })                                                                                                                                                                             │
     │                                                                                                                                                                                │
     │ // Export structured JSON report                                                                                                                                               │
     │ err = report.ExportJSON("./results.json")                                                                                                                                      │
     │                                                                                                                                                                                │
     │ Report Format                                                                                                                                                                  │
     │                                                                                                                                                                                │
     │ The generated JSON report includes:                                                                                                                                            │
     │ - Metadata (timestamp, version, counts)                                                                                                                                        │
     │ - Scanned domains list                                                                                                                                                         │
     │ - Detailed findings with meanings from scan-template-meanings.json                                                                                                             │
     │ - Summary statistics                                                                                                                                                           │
     │ - Raw Nuclei results for programmatic access                                                                                                                                   │
     │                                                                                                                                                                                │
     │ ### 8. Implementation Priority                                                                                                                                                 │
     │                                                                                                                                                                                │
     │ #### Phase 1: Core Pipeline                                                                                                                                                    │
     │ 1. **Domain Discovery**: Integrate domain-scan with keywords pass-through                                                                                                      │
     │ 2. **Nuclei Integration**: Nuclei v3 SDK with existing templates                                                                                                               │
     │ 3. **Report Builder**: JSON report generation using scan-template-meanings.json                                                                                                │
     │                                                                                                                                                                                │
     │ #### Phase 2: Enhanced Features                                                                                                                                                │
     │ 1. **Multiple Output Formats**: HTML, CSV export options                                                                                                                       │
     │ 2. **Report Grouping**: Group by domain, severity, template                                                                                                                    │
     │ 3. **CLI Facade**: Complete CLI wrapper over SDK                                                                                                                               │
     │                                                                                                                                                                                │
     │ #### Phase 3: Documentation & Testing                                                                                                                                          │
     │ 1. **SDK Documentation**: Complete API docs with report examples                                                                                                               │
     │ 2. **Report Schema**: Document JSON output format                                                                                                                              │
     │ 3. **Integration Examples**: How external projects consume reports                                                                                                             │
     │                                                                                                                                                                                │
     │ This architecture ensures a clean pipeline from domain input to structured JSON reports, with the report builder module handling all output formatting and meaning enrichment.