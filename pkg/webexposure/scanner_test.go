package webexposure

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

func TestNew(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	if scanner == nil {
		t.Fatal("Scanner is nil")
	}
}

func TestAggregateResults(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	// Test data using native Nuclei output.ResultEvent
	results := []*output.ResultEvent{
		{
			Host:       "example.com",
			TemplateID: "apache-detect",
			Matched:    "https://example.com",
			Timestamp:  time.Now(),
			Info: model.Info{
				Name: "Apache Detection",
			},
		},
		{
			Host:       "example.com",
			TemplateID: "nginx-detect",
			Matched:    "https://example.com",
			Timestamp:  time.Now(),
			Info: model.Info{
				Name: "Nginx Detection",
			},
		},
		{
			Host:       "api.example.com",
			TemplateID: "api-detect",
			Matched:    "https://api.example.com",
			Timestamp:  time.Now(),
			Info: model.Info{
				Name: "API Detection",
			},
		},
	}

	grouped, err := scanner.AggregateResults(results)
	if err != nil {
		t.Fatalf("AggregateResults failed: %v", err)
	}

	// Verify grouping
	if len(grouped.Domains) != 2 {
		t.Errorf("Expected 2 domains, got %d", len(grouped.Domains))
	}

	if len(grouped.Domains["example.com"]) != 2 {
		t.Errorf("Expected 2 templates for example.com, got %d", len(grouped.Domains["example.com"]))
	}

	if len(grouped.Domains["api.example.com"]) != 1 {
		t.Errorf("Expected 1 template for api.example.com, got %d", len(grouped.Domains["api.example.com"]))
	}
}

func TestCountIssues(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	// Create test grouped results
	grouped := &GroupedResults{
		Domains: map[string]map[string]*output.ResultEvent{
			"example.com": {
				"live-domain":   {Host: "example.com", TemplateID: "live-domain"},
				"apache-detect": {Host: "example.com", TemplateID: "apache-detect"},
			},
			"api.example.com": {
				"api-server-detection": {Host: "api.example.com", TemplateID: "api-server-detection"},
			},
			"test.example.com": {
				"live-domain": {Host: "test.example.com", TemplateID: "live-domain"},
			},
		},
	}

	// Test counting
	liveCount := scanner.CountIssues(grouped, []string{"live-domain"})
	if liveCount != 2 {
		t.Errorf("Expected 2 live domains, got %d", liveCount)
	}

	apiCount := scanner.CountIssues(grouped, []string{"api-server-detection"})
	if apiCount != 1 {
		t.Errorf("Expected 1 API server, got %d", apiCount)
	}
}

func TestNormalizeAndClean(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	tests := []struct {
		input    string
		expected []string
	}{
		{
			input:    "WordPress 5.8",
			expected: []string{"wordpress", "5.8"},
		},
		{
			input:    "generator: Jekyll v4.2.0",
			expected: []string{"jekyll", "v4.2.0"},
		},
		{
			input:    "Angular; React",
			expected: []string{"angular"},
		},
		{
			input:    "<title>Test</title>",
			expected: []string{"titletest", "title"},
		},
	}

	for _, test := range tests {
		result := scanner.NormalizeAndClean(test.input)
		if len(result) != len(test.expected) {
			t.Errorf("Input %q: expected %v, got %v", test.input, test.expected, result)
		}
	}
}

func TestClassifyAsAPI(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	// Test API classification
	tests := []struct {
		name         string
		templates    map[string]*output.ResultEvent
		expectedType string
	}{
		{
			name: "Confirmed API Endpoint",
			templates: map[string]*output.ResultEvent{
				"api-server-detection": {Host: "api.example.com", TemplateID: "api-server-detection"},
			},
			expectedType: "Confirmed API Endpoint",
		},
		{
			name: "Potential API Endpoint - keyword",
			templates: map[string]*output.ResultEvent{
				"api-host-keyword-detection": {Host: "api.example.com", TemplateID: "api-host-keyword-detection"},
			},
			expectedType: "Potential API Endpoint",
		},
		{
			name: "Potential API Endpoint - swagger",
			templates: map[string]*output.ResultEvent{
				"swagger-api": {Host: "example.com", TemplateID: "swagger-api", Matched: "https://example.com/swagger"},
			},
			expectedType: "Potential API Endpoint",
		},
		{
			name: "Not an API",
			templates: map[string]*output.ResultEvent{
				"website-host-detection": {Host: "example.com", TemplateID: "website-host-detection"},
			},
			expectedType: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			discovered, _ := scanner.ClassifyAsAPI(test.templates)
			if discovered != test.expectedType {
				t.Errorf("Expected %q, got %q", test.expectedType, discovered)
			}
		})
	}
}

func TestClassifyAsWebApp(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	// Test Web App classification
	tests := []struct {
		name         string
		templates    map[string]*output.ResultEvent
		expectedType string
	}{
		{
			name: "Web App",
			templates: map[string]*output.ResultEvent{
				"website-host-detection": {Host: "example.com", TemplateID: "website-host-detection"},
			},
			expectedType: "Web App",
		},
		{
			name: "Frontend Tech Web App",
			templates: map[string]*output.ResultEvent{
				"frontend-tech-detection": {Host: "example.com", TemplateID: "frontend-tech-detection"},
			},
			expectedType: "Web App",
		},
		{
			name: "Not a Web App - API keyword",
			templates: map[string]*output.ResultEvent{
				"api-host-keyword-detection": {Host: "api.example.com", TemplateID: "api-host-keyword-detection"},
			},
			expectedType: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			discovered, _, _ := scanner.ClassifyAsWebApp(test.templates)
			if discovered != test.expectedType {
				t.Errorf("Expected %q, got %q", test.expectedType, discovered)
			}
		})
	}
}

func TestGenerateReport(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	// Create test grouped results
	grouped := &GroupedResults{
		Domains: map[string]map[string]*output.ResultEvent{
			"example.com": {
				"website-host-detection": {Host: "example.com", TemplateID: "website-host-detection"},
				"live-domain":            {Host: "example.com", TemplateID: "live-domain"},
			},
			"api.example.com": {
				"api-server-detection": {Host: "api.example.com", TemplateID: "api-server-detection"},
				"live-domain":          {Host: "api.example.com", TemplateID: "live-domain"},
			},
		},
	}

	report, err := scanner.GenerateReport(grouped, "example.com")
	if err != nil {
		t.Fatalf("GenerateReport failed: %v", err)
	}

	// Verify report structure
	if report.SchemaVersion != "v1" {
		t.Errorf("Expected schema version v1, got %s", report.SchemaVersion)
	}

	if report.ReportMetadata.TargetDomain != "example.com" {
		t.Errorf("Expected target domain example.com, got %s", report.ReportMetadata.TargetDomain)
	}

	if report.Summary.LiveExposedDomains != 2 {
		t.Errorf("Expected 2 live domains, got %d", report.Summary.LiveExposedDomains)
	}

	// Should have 1 API and 1 Web App
	if len(report.APIsFound) != 1 {
		t.Errorf("Expected 1 API, got %d", len(report.APIsFound))
	}

	if len(report.WebAppsFound) != 1 {
		t.Errorf("Expected 1 Web App, got %d", len(report.WebAppsFound))
	}
}

func TestDiscoverDomains(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	// Test domain discovery implementation
	domains := []string{"example.com"}
	keywords := []string{"staging", "prod"}

	discovered, err := scanner.DiscoverDomains(domains, keywords)
	if err != nil {
		t.Fatalf("DiscoverDomains failed: %v", err)
	}

	// Should return at least the input domains
	if len(discovered) < len(domains) {
		t.Errorf("Expected at least %d domains, got %d", len(domains), len(discovered))
	}

	// Original domain should be included
	found := false
	for _, domain := range discovered {
		if domain == "example.com" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Original domain example.com not found in discovered domains")
	}
}

func TestJSONReportGeneration(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	// Create a test report
	report := &ExposureReport{
		SchemaVersion: "v1",
		ReportMetadata: &ReportMetadata{
			Title:        "Test Report",
			Date:         "2025-07-12",
			TargetDomain: "example.com",
			Timestamp:    time.Now(),
		},
		Summary: &Summary{
			TotalDomains:       5,
			LiveExposedDomains: 3,
			TotalDetections:    2,
		},
		Technologies: &TechnologiesDetected{
			Count:        2,
			Technologies: []string{"nginx", "wordpress"},
		},
		APIsFound: []*APIFinding{
			{
				Domain:     "api.example.com",
				Discovered: "Potential API Endpoint",
				Findings:   "Domain has API keyword, Live Domain",
			},
		},
		WebAppsFound: []*WebAppFinding{
			{
				Domain:     "www.example.com",
				Discovered: "Web App",
				Findings:   "Using WordPress, Web Server",
			},
		},
	}

	// Test JSON marshaling
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal report: %v", err)
	}

	// Test that we can unmarshal it back
	var unmarshaled ExposureReport
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal report: %v", err)
	}

	if unmarshaled.SchemaVersion != report.SchemaVersion {
		t.Errorf("Schema version mismatch: expected %s, got %s", report.SchemaVersion, unmarshaled.SchemaVersion)
	}

	// Test writing to file
	targetDomain := "test-example.com"
	err = scanner.WriteJSONReport(report, targetDomain)
	if err != nil {
		t.Fatalf("Failed to write JSON report: %v", err)
	}

	// The writeJSONReport function creates: ./reports/{domain}/{domain}-web-exposure-report.json
	expectedFilename := "reports/test-example-com/test-example-com-web-exposure-report.json"

	// Clean up
	defer os.RemoveAll("reports")

	// Verify file exists and contains valid JSON
	_, err = os.Stat(expectedFilename)
	if err != nil {
		t.Fatalf("Report file not created: %v", err)
	}
}
