package findings

// CVEStats represents CVE statistics for a technology
type CVEStats struct {
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
	Total    int    `json:"total"`
	KEV      int    `json:"kev"` // CISA Known Exploited Vulnerabilities count
	Updated  string `json:"updated,omitempty"`
}

// CWECategory represents a specific CWE weakness category
type CWECategory struct {
	ID    string `json:"id"`    // e.g., "CWE-79"
	Name  string `json:"name"`  // e.g., "Cross-site Scripting"
	Count int    `json:"count"` // Number of occurrences
}

// CWEStats represents CWE statistics for a technology
type CWEStats struct {
	Total         int           `json:"total"`
	TopCategories []CWECategory `json:"top_categories,omitempty"` // Top 3-5 weakness categories
	Updated       string        `json:"updated,omitempty"`
}

// SecurityInfo contains security-related information
type SecurityInfo struct {
	CVEApplicable *bool `json:"cve_applicable,omitempty"` // Whether CVE data should be queried (default: true for products, false for auth/metadata)
	CWEApplicable *bool `json:"cwe_applicable,omitempty"` // Whether CWE data should be queried (default: true for products with CVEs, false otherwise)
	CVE           *struct {
		SearchKey string   `json:"search_key,omitempty"` // Search key for vulnx queries
		Stats     CVEStats `json:"stats"`
		Updated   string   `json:"updated,omitempty"`
	} `json:"cve,omitempty"`
	Weaknesses *struct {
		Stats   CWEStats `json:"stats"`
		Updated string   `json:"updated,omitempty"`
	} `json:"weaknesses,omitempty"`
}

// FindingItem represents a finding with slug, display name, icon, and classification
type FindingItem struct {
	Slug             string        `json:"slug"`
	DisplayName      string        `json:"display_name"`
	Icon             string        `json:"icon"`                         // Icon filename (e.g., "react.svg")
	DisplayAs        string        `json:"display_as,omitempty"`         // How to display: "label" or "link"
	ShowInTech       bool          `json:"show_in_tech"`                 // Whether to show in Technology Exposure section
	Classification   []string      `json:"classification"`               // Classification tags: "webapp", "api", "ai"
	Values           []string      `json:"values,omitempty"`             // URLs or values when display_as is "link"
	Description      string        `json:"description,omitempty"`
	Labels           []string      `json:"labels,omitempty"`
	Security         *SecurityInfo `json:"security,omitempty"`
	CriticalityDelta float64       `json:"criticality_delta,omitempty"`  // Score delta for asset criticality scoring
	Count            int           `json:"count,omitempty"`              // Number of domains using this technology
}

// GetDisplayName returns the display name for this finding
func (f *FindingItem) GetDisplayName() string {
	if f.DisplayName != "" {
		return f.DisplayName
	}
	return f.Slug
}

// GetIcon returns the icon filename for this finding
func (f *FindingItem) GetIcon() string {
	if f.Icon != "" {
		return f.Icon
	}
	return f.Slug + ".svg"
}

// Discovery represents both API and Web App discoveries
type Discovery struct {
	Domain       string         `json:"domain"`
	Title        string         `json:"title,omitempty"`
	Description  string         `json:"description,omitempty"`
	Discovered   string         `json:"discovered"`
	FindingItems []*FindingItem `json:"findings"`              // Unified field for both JSON and HTML
	Criticality  *Criticality   `json:"criticality,omitempty"` // Asset criticality scoring
	URL          string         `json:"url,omitempty"`         // Original URL scanned
	IP           string         `json:"ip,omitempty"`          // Resolved IP address
}

// Backward compatibility type aliases
type APIFinding = Discovery
type WebAppFinding = Discovery
