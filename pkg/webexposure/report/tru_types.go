package report

// TRUInsightsData represents the complete threat landscape assessment report
type TRUInsightsData struct {
	Organization         OrganizationInfo     `json:"organization"`
	AttackSurfaceSummary AttackSurfaceSummary `json:"attack_surface_summary"`
	ThreatAssessment     ThreatAssessment     `json:"threat_assessment"`
}

// OrganizationInfo represents organization details
type OrganizationInfo struct {
	Name        string   `json:"name"`
	Domain      string   `json:"domain"`
	Industry    string   `json:"industry"`
	SubIndustry string   `json:"sub_industry"`
	Region      string   `json:"region"`
	Compliance  []string `json:"compliance"`
}

// AttackSurfaceSummary represents attack surface overview
type AttackSurfaceSummary struct {
	TotalDomains          int      `json:"total_domains"`
	TotalApplications     int      `json:"total_applications"`
	KeyTechnologies       []string `json:"key_technologies"`
	AuthenticationMethods []string `json:"authentication_methods"`
}

// ThreatAssessment represents the contextual threat assessment section
type ThreatAssessment struct {
	LandscapeOverview string   `json:"landscape_overview,omitempty"`
	TopInsights       []string `json:"top_insights"` // Top 10 insights with markdown bold formatting
}
