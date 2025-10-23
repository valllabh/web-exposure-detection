package criticality

import (
	"github.com/projectdiscovery/gologger"

	"web-exposure-detection/pkg/webexposure/findings"
)

// GetLogger returns the shared logger instance
func GetLogger() *gologger.Logger {
	return gologger.DefaultLogger
}

// NewFindingItem creates a new finding item (re-export from findings package)
var NewFindingItem = findings.NewFindingItem

// NewCriticalityFactor re-exports from findings package
var NewCriticalityFactor = findings.NewCriticalityFactor
