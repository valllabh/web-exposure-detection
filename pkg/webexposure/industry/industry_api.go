package industry

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"web-exposure-detection/pkg/webexposure/ai"
)

const (
	defaultIndustryPreset = "@preset/industry-classification-prompt"
)

// AIBasedClassifier implements IndustryClassifier using any AI provider
type AIBasedClassifier struct {
	provider ai.Provider
}

// NewAIBasedClassifier creates a new AI based classifier using the default provider
func NewAIBasedClassifier() (*AIBasedClassifier, error) {
	logger := GetLogger()

	// Load default provider from configuration
	provider, err := ai.LoadDefaultProvider()
	if err != nil {
		// Try Perplexity as fallback (preferred for industry classification)
		provider, err = ai.LoadPerplexityProvider()
		if err != nil {
			logger.Debug().Msgf("Perplexity not available: %v, trying OpenRouter", err)
			// OpenRouter as secondary fallback for backward compatibility
			provider, err = ai.LoadOpenRouterProvider()
			if err != nil {
				return nil, fmt.Errorf("failed to load AI provider: %w", err)
			}
		}
	}

	logger.Debug().Msgf("Using AI provider: %s (model: %s)",
		provider.GetProviderName(), provider.GetDefaultModel())

	return &AIBasedClassifier{
		provider: provider,
	}, nil
}

// NewAIBasedClassifierWithProvider creates a new AI based classifier with a specific provider
func NewAIBasedClassifierWithProvider(provider ai.Provider) *AIBasedClassifier {
	return &AIBasedClassifier{
		provider: provider,
	}
}

// GetProviderName returns the provider name
func (c *AIBasedClassifier) GetProviderName() string {
	return c.provider.GetProviderName()
}

// ClassifyDomain classifies a domain using the configured AI provider
func (c *AIBasedClassifier) ClassifyDomain(domain string) (*IndustryClassification, error) {
	logger := GetLogger()
	logger.Debug().Msgf("Classifying domain with %s: %s", c.provider.GetProviderName(), domain)

	// Clean domain
	cleanDomain := strings.TrimPrefix(strings.TrimPrefix(domain, "https://"), "http://")
	cleanDomain = strings.TrimPrefix(cleanDomain, "www.")

	// Load industry classification prompt
	systemPrompt, err := GetIndustryClassificationPrompt()
	if err != nil {
		logger.Warning().Msgf("Failed to load industry classification prompt, using basic prompt: %v", err)
		systemPrompt = "You are an industry classification expert. Classify the domain into one of the predefined industry categories and return JSON with industry, subIndustry, and compliances fields."
	}

	// Create completion request with system prompt
	req := &ai.CompletionRequest{
		Messages: []ai.Message{
			{
				Role:    "system",
				Content: systemPrompt,
			},
			{
				Role:    "user",
				Content: cleanDomain,
			},
		},
	}

	// Configure model based on provider
	switch c.provider.GetProviderName() {
	case ai.ProviderPerplexity:
		// Use Perplexity's Sonar model with web search grounding for industry classification
		req.Model = "sonar"
		logger.Debug().Msg("Using Perplexity Sonar model with web search grounding")
	case ai.ProviderOpenRouter:
		// Use OpenAI o1 model via OpenRouter
		req.Model = "openai/o1"
		logger.Debug().Msg("Using OpenAI o1 model via OpenRouter")
	}

	// Send request
	ctx := context.Background()
	resp, err := c.provider.Complete(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("AI completion failed: %w", err)
	}

	logger.Debug().Msgf("%s response content: %s", c.provider.GetProviderName(), resp.Content)

	// Parse industry classification from content
	var result IndustryClassification
	content := resp.Content

	if err := json.Unmarshal([]byte(content), &result); err != nil {
		// Try to extract JSON from markdown code blocks
		content = ai.ExtractJSONFromMarkdown(content)
		if err := json.Unmarshal([]byte(content), &result); err != nil {
			return nil, fmt.Errorf("failed to parse industry classification from response: %w, content: %s", err, content)
		}
	}

	// Set metadata
	result.Domain = cleanDomain
	result.Provider = resp.ProviderName
	result.ProviderMeta = resp.Model

	logger.Debug().Msgf("Successfully classified %s as: %s (sub: %s)", cleanDomain, result.Industry, result.SubIndustry)

	return &result, nil
}

// ClassifyDomainIndustryWithCache classifies a domain with caching support
func ClassifyDomainIndustryWithCache(domain string, cacheFilePath string, force bool) (*IndustryClassification, error) {
	logger := GetLogger()

	// If force flag is set, remove cache file
	if force {
		logger.Debug().Msgf("Clearing industry classification cache: %s", cacheFilePath)
		if err := os.Remove(cacheFilePath); err != nil && !os.IsNotExist(err) {
			logger.Warning().Msgf("Failed to clear industry cache file: %v", err)
		}
	}

	// Try to load from cache first
	if !force {
		if classification, err := loadIndustryClassification(cacheFilePath); err == nil {
			logger.Debug().Msgf("Cache hit: loaded industry classification for %s", domain)
			return classification, nil
		} else {
			logger.Debug().Msgf("Cache miss or invalid cache: %v", err)
		}
	}

	// Perform fresh classification
	classifier, err := NewAIBasedClassifier()
	if err != nil {
		return nil, fmt.Errorf("failed to create classifier: %w", err)
	}

	result, err := classifier.ClassifyDomain(domain)
	if err != nil {
		return nil, fmt.Errorf("classification failed: %w", err)
	}

	// Save to cache
	if err := saveIndustryClassification(result, cacheFilePath); err != nil {
		logger.Warning().Msgf("Failed to save industry classification to cache: %v", err)
	} else {
		logger.Debug().Msgf("Saved industry classification to %s", cacheFilePath)
	}

	return result, nil
}

// loadIndustryClassification loads cached industry classification from file
func loadIndustryClassification(filePath string) (*IndustryClassification, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var classification IndustryClassification
	if err := json.Unmarshal(data, &classification); err != nil {
		return nil, err
	}

	return &classification, nil
}

// saveIndustryClassification saves industry classification to file
func saveIndustryClassification(classification *IndustryClassification, filePath string) error {
	data, err := json.MarshalIndent(classification, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, data, 0600)
}
