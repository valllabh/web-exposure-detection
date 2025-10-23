package common

import (
	"time"

	"web-exposure-detection/pkg/webexposure/findings"
)

// ExposureReport represents the final JSON report schema V1
type ExposureReport struct {
	SchemaVersion  string                `json:"schema_version"`
	ReportMetadata *ReportMetadata       `json:"report_metadata"`
	Summary        *Summary              `json:"summary"`
	Technologies   *TechnologiesDetected `json:"technology_exposure"`
	APIsFound      []*findings.APIFinding         `json:"apis_found"`
	APISpecsFound  []*findings.Discovery          `json:"api_specs_found"`
	AIAssetsFound  []*findings.Discovery          `json:"ai_assets_found"`
	WebAppsFound   []*findings.WebAppFinding      `json:"web_applications_found"`
	OtherDomains   []*findings.Discovery          `json:"other_domains_found"`
}

// ReportMetadata contains report information
type ReportMetadata struct {
	Title        string         `json:"title"`
	Date         string         `json:"date"`
	TargetDomain string         `json:"target_domain"`
	Timestamp    time.Time      `json:"timestamp"`
	Industry     *IndustryInfo  `json:"industry,omitempty"`
}

// IndustryInfo contains industry classification metadata
type IndustryInfo struct {
	Industry    string   `json:"industry"`
	SubIndustry string   `json:"sub_industry,omitempty"`
	Compliances []string `json:"compliances,omitempty"`
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
	UnclassifiedFound      int `json:"unclassified_found"`
	DomainsUsingAPI        int `json:"domains_using_api"`
	TotalApps              int `json:"total_apps"`
	APICriticality         *findings.CriticalityDistribution `json:"api_criticality,omitempty"`
	APISpecCriticality     *findings.CriticalityDistribution `json:"api_spec_criticality,omitempty"`
	AIAssetCriticality     *findings.CriticalityDistribution `json:"ai_asset_criticality,omitempty"`
	WebAppCriticality      *findings.CriticalityDistribution `json:"web_app_criticality,omitempty"`
	DomainMetrics          *DomainMetrics           `json:"domain_metrics,omitempty"`
}

// DomainMetrics contains domain categorization metrics
type DomainMetrics struct {
	TotalDiscovered    int `json:"total_discovered"`     // All domains found
	InternetExposed    int `json:"internet_exposed"`     // Reachable domains (Status != 0 or IsLive = true)
	NotReachable       int `json:"not_reachable"`        // Discovered but not responding (Status = 0 and IsLive = false)
	PassiveOnly        int `json:"passive_only"`         // Found via passive scan only, not HTTP accessible
	WithRedirects      int `json:"with_redirects"`       // Domains that redirect to another location
	WithCertificates   int `json:"with_certificates"`    // Domains with TLS certificate information
	ExpiredCerts       int `json:"expired_certs"`        // Domains with expired certificates
	ExpiringSoonCerts  int `json:"expiring_soon_certs"`  // Certificates expiring within 30 days
}

// TechnologiesDetected contains detected technologies
type TechnologiesDetected struct {
	Count           int            `json:"count"`
	Technologies    []*findings.FindingItem `json:"technologies"`     // Top 5 for first page
	AllTechnologies []*findings.FindingItem `json:"all_technologies"` // All technologies for detailed section
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
