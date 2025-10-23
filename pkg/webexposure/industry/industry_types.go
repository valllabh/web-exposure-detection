package industry

// IndustryClassification represents the classification result for a domain
type IndustryClassification struct {
	Domain       string   `json:"domain"`
	Industry     string   `json:"industry"`
	SubIndustry  string   `json:"subIndustry,omitempty"`
	Other        string   `json:"other,omitempty"`
	Compliances  []string `json:"compliances,omitempty"`
	Provider     string   `json:"provider"`
	ProviderMeta string   `json:"provider_meta,omitempty"` // Model name or version
}

// IndustryClassifier is an interface for industry classification providers
type IndustryClassifier interface {
	ClassifyDomain(domain string) (*IndustryClassification, error)
	GetProviderName() string
}
