package main

import (
	"web-exposure-detection/cmd/web-exposure-detection"
	"web-exposure-detection/pkg/webexposure"
)

func main() {
	// Initialize embedded filesystems
	webexposure.SetEmbeddedFilesystems(ScanTemplatesFS, TemplatesFS)

	cmd.Execute()
}
