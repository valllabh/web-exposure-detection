package industry

import (
	"github.com/projectdiscovery/gologger"
)

// GetLogger returns the shared logger instance
func GetLogger() *gologger.Logger {
	return gologger.DefaultLogger
}
