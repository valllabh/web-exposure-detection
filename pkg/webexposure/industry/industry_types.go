package industry

// Compliance represents a compliance framework and the reason it applies
type Compliance struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// IndustryClassification represents the classification result for a domain
type IndustryClassification struct {
	// AI Response Fields
	CompanyName      string       `json:"companyName,omitempty"`
	ParentCompany    *string      `json:"parentCompany,omitempty"` // Pointer to distinguish between null and empty string
	Subsidiaries     []string     `json:"subsidiaries,omitempty"`
	Industry         string       `json:"industry"`
	SubIndustry      string       `json:"subIndustry,omitempty"`
	Compliances      []Compliance `json:"compliances,omitempty"`
	HeadquartersCity string       `json:"headquartersCity,omitempty"` // City where headquarters is located
	OperatingRegions []string     `json:"operatingRegions,omitempty"` // Geographic regions where organization is active
	PrimaryRegion    string       `json:"primaryRegion,omitempty"`    // Primary operating region

	// Legacy/Fallback Fields
	Other string `json:"other,omitempty"` // Used when industry doesn't match fixed categories

	// Internal Metadata Fields (added by system, not from AI)
	Domain       string `json:"domain"`
	Provider     string `json:"provider"`
	ProviderMeta string `json:"provider_meta,omitempty"` // Model name or version
}

// IndustryClassifier is an interface for industry classification providers
type IndustryClassifier interface {
	ClassifyDomain(domain string) (*IndustryClassification, error)
	GetProviderName() string
}
