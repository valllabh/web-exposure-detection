package webexposure

import (
	"embed"
	"web-exposure-detection/pkg/webexposure/scanner"
)

// SetEmbeddedFilesystems sets the embedded filesystems from main package
func SetEmbeddedFilesystems(scanTemplates, templates embed.FS) {
	// Pass to scanner package
	scanner.SetEmbeddedFS(scanTemplates, templates)
}
