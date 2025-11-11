package ai

import (
	"fmt"
	"time"
)

const (
	// Provider names
	ProviderOpenRouter = "openrouter"
	ProviderPerplexity = "perplexity"

	// Default timeout
	DefaultTimeout = 30 * time.Second
)

// ProviderFactory creates AI providers based on configuration
type ProviderFactory struct {
	// Can be extended with caching, connection pooling, etc.
}

// NewProviderFactory creates a new provider factory
func NewProviderFactory() *ProviderFactory {
	return &ProviderFactory{}
}

// CreateProvider creates an AI provider based on configuration
func (f *ProviderFactory) CreateProvider(config *Config) (Provider, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	if config.APIKey == "" {
		return nil, fmt.Errorf("API key is required for provider %s", config.Provider)
	}

	// Set default timeout if not specified
	if config.Timeout == 0 {
		config.Timeout = DefaultTimeout
	}

	switch config.Provider {
	case ProviderOpenRouter:
		return newOpenRouterProvider(config)
	case ProviderPerplexity:
		return newPerplexityProvider(config)
	default:
		return nil, fmt.Errorf("unsupported AI provider: %s", config.Provider)
	}
}

// CreateProviderFromName is a convenience method to create a provider with minimal config
func (f *ProviderFactory) CreateProviderFromName(providerName, apiKey, model string) (Provider, error) {
	config := &Config{
		Provider: providerName,
		APIKey:   apiKey,
		Model:    model,
		Timeout:  DefaultTimeout,
	}
	return f.CreateProvider(config)
}
