package findings

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
	logger := GetLogger()
	logger.Debug().Msg("Loading findings map from embedded findings.json")

	data, err := findingsFS.ReadFile("findings.json")
	if err != nil {
		logger.Error().Msgf("Failed to read embedded findings.json: %v", err)
		return err
	}

	globalFindingsMap = make(map[string]*FindingItem)
	if err := json.Unmarshal(data, &globalFindingsMap); err != nil {
		logger.Error().Msgf("Failed to unmarshal findings.json: %v", err)
		return err
	}

	logger.Debug().Msgf("Loaded %d findings from findings.json", len(globalFindingsMap))
	return nil
}

// NewFindingItem creates a FindingItem from a slug
func NewFindingItem(slug string) *FindingItem {
	logger := GetLogger()

	// Load findings map on first use
	if globalFindingsMap == nil {
		if err := loadFindings(); err != nil {
			// Fallback to empty map if loading fails
			logger.Warning().Msgf("Failed to load findings.json, using empty findings map: %v", err)
			globalFindingsMap = make(map[string]*FindingItem)
		}
	}

	// Check if this slug exists in the loaded map
	if existing, ok := globalFindingsMap[slug]; ok {
		logger.Debug().Msgf("Found existing finding item for slug: %s", slug)
		return existing
	}

	// Create new item if not found in map
	logger.Debug().Msgf("Created new finding item for unknown slug: %s", slug)
	item := &FindingItem{
		Slug:        slug,
		DisplayName: slug,
		Icon:        slug + ".svg",
	}
	return item
}
