package webexposure

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

// InitLogger configures the global logger based on flags
func InitLogger(debug bool, silent bool) {
	if debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
		gologger.Debug().Msg("Logger initialized in debug mode")
	} else if silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelWarning)
	} else {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo) // Default
	}
}

// GetLogger returns the configured logger instance
func GetLogger() *gologger.Logger {
	return gologger.DefaultLogger
}
