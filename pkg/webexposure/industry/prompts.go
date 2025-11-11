package industry

import (
	"embed"
	"fmt"
	"strings"
)

//go:embed prompts/*.md
var promptsFS embed.FS

// loadIndustryClassificationPrompt loads the industry classification prompt from embedded files
func loadIndustryClassificationPrompt() (string, error) {
	data, err := promptsFS.ReadFile("prompts/industry-classification.md")
	if err != nil {
		return "", fmt.Errorf("failed to read industry classification prompt: %w", err)
	}

	prompt := string(data)

	// Remove the markdown header section (everything before "You are an industry classification expert")
	if idx := strings.Index(prompt, "You are an industry classification expert"); idx != -1 {
		prompt = prompt[idx:]
	}

	return strings.TrimSpace(prompt), nil
}

// GetIndustryClassificationPrompt returns the industry classification prompt
func GetIndustryClassificationPrompt() (string, error) {
	return loadIndustryClassificationPrompt()
}
