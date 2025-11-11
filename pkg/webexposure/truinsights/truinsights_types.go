package truinsights

// DomainDiscoveryStatistics represents extracted statistics from domain discovery
type DomainDiscoveryStatistics struct {
	TotalDomains        int      `json:"total_domains"`
	TotalSubdomains     int      `json:"total_subdomains"`
	ActiveServices      int      `json:"active_services"`
	DomainList          []string `json:"domain_list"`
	PrimaryDomain       string   `json:"primary_domain"`
}

// TRUInsightsInput represents the input data for TRU insights generation
type TRUInsightsInput struct {
	DomainStats             *DomainDiscoveryStatistics `json:"domain_statistics"`
	WebExposureResult       interface{}                `json:"web_exposure_result"`
	IndustryClassification  interface{}                `json:"industry_classification"`
}

// TRUInsightsResult represents the output from TRU insights generation
type TRUInsightsResult struct {
	Content      string `json:"content"`       // Raw markdown response
	Provider     string `json:"provider"`
	Model        string `json:"model"`
	GeneratedAt  string `json:"generated_at"`
	PromptLength int    `json:"prompt_length,omitempty"`
}
