package webexposure

import (
	"embed"
	"encoding/json"
)

//go:embed findings.json
var findingsFS embed.FS

// Global findings map loaded from findings.json
var globalFindingsMap map[string]*FindingItem

// loadFindings loads the findings map from embedded findings.json
func loadFindings() error {
	data, err := findingsFS.ReadFile("findings.json")
	if err != nil {
		return err
	}

	globalFindingsMap = make(map[string]*FindingItem)
	return json.Unmarshal(data, &globalFindingsMap)
}

// NewFindingItem creates a FindingItem from a slug
func NewFindingItem(slug string) *FindingItem {
	// Load findings map on first use
	if globalFindingsMap == nil {
		if err := loadFindings(); err != nil {
			// Fallback to empty map if loading fails
			globalFindingsMap = make(map[string]*FindingItem)
		}
	}

	// Check if this slug exists in the loaded map
	if existing, ok := globalFindingsMap[slug]; ok {
		return existing
	}

	// Create new item if not found in map
	item := &FindingItem{
		Slug:        slug,
		DisplayName: slug,
		Icon:        slug + ".svg",
	}
	return item
}
