package webexposure

import (
	"embed"
	"web-exposure-detection/pkg/webexposure/scanner"
)

// scanTemplatesFS and templatesFS will be set from main package
var scanTemplatesFS embed.FS
var templatesFS embed.FS

// SetEmbeddedFilesystems sets the embedded filesystems from main package
func SetEmbeddedFilesystems(scanTemplates, templates embed.FS) {
	scanTemplatesFS = scanTemplates
	templatesFS = templates
	// Pass to scanner package
	scanner.SetEmbeddedFS(scanTemplates, templates)
}
