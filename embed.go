package main

import "embed"

//go:embed scan-templates
var ScanTemplatesFS embed.FS

//go:embed templates
var TemplatesFS embed.FS
