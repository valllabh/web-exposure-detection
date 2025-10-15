package webexposure

// CVEStats represents CVE statistics for a technology
type CVEStats struct {
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
	Total    int    `json:"total"`
	Updated  string `json:"updated,omitempty"`
}

// SecurityInfo contains security-related information
type SecurityInfo struct {
	CVE *struct {
		Stats   CVEStats `json:"stats"`
		Updated string   `json:"updated,omitempty"`
	} `json:"cve,omitempty"`
}

// FindingItem represents a finding with slug, display name, icon, and classification
type FindingItem struct {
	Slug           string        `json:"slug"`
	DisplayName    string        `json:"display_name"`
	Icon           string        `json:"icon"`                 // Icon filename (e.g., "react.svg")
	DisplayAs      string        `json:"display_as,omitempty"` // How to display: "label" or "link"
	ShowInTech     bool          `json:"show_in_tech"`         // Whether to show in Technologies Detected section
	Classification []string      `json:"classification"`       // Classification tags: "webapp", "api", "ai"
	Values         []string      `json:"values,omitempty"`     // URLs or values when display_as is "link"
	Description    string        `json:"description,omitempty"`
	Labels         []string      `json:"labels,omitempty"`
	Security       *SecurityInfo `json:"security,omitempty"`
	Count          int           `json:"count,omitempty"` // Number of domains using this technology
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
	FindingItems []*FindingItem `json:"findings"` // Unified field for both JSON and HTML
}

// Backward compatibility type aliases
type APIFinding = Discovery
type WebAppFinding = Discovery
