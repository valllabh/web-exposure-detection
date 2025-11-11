package ai

import (
	"github.com/projectdiscovery/gologger"
)

// GetLogger returns a logger for the AI package
func GetLogger() *gologger.Logger {
	return gologger.DefaultLogger
}
