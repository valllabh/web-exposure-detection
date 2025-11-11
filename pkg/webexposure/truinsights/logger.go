package truinsights

import (
	"github.com/projectdiscovery/gologger"
)

// GetLogger returns the global logger instance
func GetLogger() *gologger.Logger {
	return gologger.DefaultLogger
}
