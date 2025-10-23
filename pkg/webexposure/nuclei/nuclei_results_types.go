package nuclei

import (
	"encoding/xml"
)

// NucleiOptions configures the Nuclei scan
type NucleiOptions struct {
	TemplatesPath       string
	SpecificTemplates   []string
	IncludeTags         []string
	ExcludeTags         []string
	RateLimit           int
	BulkSize            int
	Concurrency         int
	Headless            bool
	OmitTemplate        bool
	OmitResponse        bool
	FollowHostRedirects bool
	ShowMatchLine       bool
	Timeout             int    // Timeout per request in seconds
	Delay               int    // Delay between requests in seconds
	ResultsWriter       string // Path to write results progressively (JSONL format)
	Debug               bool   // Enable debug mode (passed to Nuclei SDK)
	Silent              bool   // Enable silent mode (passed to Nuclei SDK)
}

// StoredResult is a minimal result structure for persistent storage
// Contains only fields needed for report generation
type StoredResult struct {
	Host        string              `json:"host"`
	TemplateID  string              `json:"template-id"`
	MatcherName string              `json:"matcher-name,omitempty"`
	URL         string              `json:"url,omitempty"`          // Original URL that was scanned
	MatchedAt   string              `json:"matched-at,omitempty"`   // Final URL after redirects
	IP          string              `json:"ip,omitempty"`           // Resolved IP address
	Findings    map[string][]string `json:"findings,omitempty"`     // Generic key-value findings from all templates
}

// FindingXML represents the new <f><k></k><vg><v></v></vg></f> structure
type FindingXML struct {
	XMLName    xml.Name   `xml:"f"`
	Key        string     `xml:"k"`  // Plain text key (NOT base64 encoded)
	ValueGroup ValueGroup `xml:"vg"` // Value group containing multiple base64-encoded values
}

// ValueGroup represents the <vg> element containing multiple <v> tags
type ValueGroup struct {
	Values []string `xml:"v"` // base64 encoded values
}

// GroupedResults represents results grouped by domain and template
type GroupedResults struct {
	Domains map[string]map[string]*StoredResult `json:"domains"`
}
