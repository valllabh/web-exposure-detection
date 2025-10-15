package main

import (
	cmd "web-exposure-detection/cmd/web-exposure-detection"
	"web-exposure-detection/pkg/webexposure"

	// Import dsl package first to ensure custom DSL functions are registered
	// before nuclei package initialization
	_ "github.com/projectdiscovery/dsl"
)

func init() {
	// This init ensures dsl package is imported and initialized first
	// Custom DSL functions registered in pkg/webexposure/dsl.go will be available
}

func main() {
	// Initialize embedded filesystems
	webexposure.SetEmbeddedFilesystems(ScanTemplatesFS, TemplatesFS)

	cmd.Execute()
}
