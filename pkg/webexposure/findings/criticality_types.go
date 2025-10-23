package findings

// CriticalityFactor represents a single scoring factor
type CriticalityFactor struct {
	Factor     string  `json:"factor"`       // Human-readable description
	FactorSlug string  `json:"factor_slug"`  // Machine-readable slug
	ScoreDelta float64 `json:"score_delta"`  // Score change (+/-)
}

// Criticality represents the criticality assessment of a domain
type Criticality struct {
	Score    int                  `json:"score"`    // 1 to 5 (Qualys-aligned integer score)
	Category string               `json:"category"` // CRITICAL, HIGH, MEDIUM, LOW, MINIMAL
	Factors  []*CriticalityFactor `json:"factors"`  // Scoring breakdown
}

// NewCriticalityFactor creates a new criticality factor
func NewCriticalityFactor(factor, slug string, delta float64) *CriticalityFactor {
	return &CriticalityFactor{
		Factor:     factor,
		FactorSlug: slug,
		ScoreDelta: delta,
	}
}

// CriticalityDistribution shows how many assets fall into each criticality level
type CriticalityDistribution struct {
	Critical int `json:"critical"` // Score 5
	High     int `json:"high"`     // Score 4
	Medium   int `json:"medium"`   // Score 3
	Low      int `json:"low"`      // Score 2
	Minimal  int `json:"minimal"`  // Score 1
}
