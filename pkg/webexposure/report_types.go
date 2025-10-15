package webexposure

import (
	"time"
)

// ExposureReport represents the final JSON report schema V1
type ExposureReport struct {
	SchemaVersion  string                `json:"schema_version"`
	ReportMetadata *ReportMetadata       `json:"report_metadata"`
	Summary        *Summary              `json:"summary"`
	Technologies   *TechnologiesDetected `json:"technologies_detected"`
	APIsFound      []*APIFinding         `json:"apis_found"`
	APISpecsFound  []*Discovery          `json:"api_specs_found"`
	AIAssetsFound  []*Discovery          `json:"ai_assets_found"`
	WebAppsFound   []*WebAppFinding      `json:"web_applications_found"`
}

// ReportMetadata contains report information
type ReportMetadata struct {
	Title        string    `json:"title"`
	Date         string    `json:"date"`
	TargetDomain string    `json:"target_domain"`
	Timestamp    time.Time `json:"timestamp"`
}

// Summary contains aggregated statistics
type Summary struct {
	TotalDomains           int `json:"total_domains"`
	LiveExposedDomains     int `json:"live_exposed_domains"`
	TotalDetections        int `json:"total_detections"`
	APIsFound              int `json:"apis_found"`
	APISpecificationsFound int `json:"api_specifications_found"`
	AIAssetsFound          int `json:"ai_assets_found"`
	WebAppsFound           int `json:"web_apps_found"`
	DomainsUsingAPI        int `json:"domains_using_api"`
	TotalApps              int `json:"total_apps"`
}

// TechnologiesDetected contains detected technologies
type TechnologiesDetected struct {
	Count           int            `json:"count"`
	Technologies    []*FindingItem `json:"technologies"`     // Top 5 for first page
	AllTechnologies []*FindingItem `json:"all_technologies"` // All technologies for detailed section
}

// ResultProcessor centralizes all report generation logic
type ResultProcessor struct {
	summary      *Summary
	apis         []*Discovery
	apiSpecs     []*Discovery
	aiAssets     []*Discovery
	webApps      []*Discovery
	technologies map[string]bool // set for deduplication
	techCounts   map[string]int  // count of domains using each technology
	grouped      *GroupedResults // stored for populating technology values
}

// DomainResult holds processed results for a single domain
type DomainResult struct {
	Domain       string
	Title        string          // Page title
	Description  string          // Page meta description
	Findings     map[string]bool // set for deduplication
	Technologies map[string]bool // set for deduplication
	Discovered   string          // classification result
}
