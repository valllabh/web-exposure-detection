package ai

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/viper"
)

// ConfigLoader helps load AI provider configuration from viper
type ConfigLoader struct {
	viper *viper.Viper
}

// NewConfigLoader creates a new config loader
func NewConfigLoader(v *viper.Viper) *ConfigLoader {
	if v == nil {
		v = viper.GetViper()
	}
	return &ConfigLoader{viper: v}
}

// LoadProviderConfig loads configuration for a specific provider
// It checks both config file and environment variables
func (cl *ConfigLoader) LoadProviderConfig(providerName string) (*Config, error) {
	var apiKey, model, baseURL string
	var timeout time.Duration
	extraParams := make(map[string]string)

	switch providerName {
	case ProviderOpenRouter:
		apiKey = cl.getConfigValue("openrouter_api_key", "OPENROUTER_API_KEY")
		model = cl.getConfigValue("openrouter_model", "")
		baseURL = cl.getConfigValue("openrouter_base_url", "")
		timeout = cl.getConfigDuration("openrouter_timeout", DefaultTimeout)

	case ProviderPerplexity:
		apiKey = cl.getConfigValue("perplexity_api_key", "PERPLEXITY_API_KEY")
		model = cl.getConfigValue("perplexity_model", "")
		baseURL = cl.getConfigValue("perplexity_base_url", "")
		timeout = cl.getConfigDuration("perplexity_timeout", DefaultTimeout)

	default:
		return nil, fmt.Errorf("unsupported provider: %s", providerName)
	}

	if apiKey == "" {
		return nil, fmt.Errorf("API key not configured for provider %s", providerName)
	}

	return &Config{
		Provider:    providerName,
		APIKey:      apiKey,
		Model:       model,
		BaseURL:     baseURL,
		Timeout:     timeout,
		ExtraParams: extraParams,
	}, nil
}

// LoadDefaultProvider loads the default AI provider from configuration
// It checks "ai_provider" config key, defaults to "perplexity"
func (cl *ConfigLoader) LoadDefaultProvider() (Provider, error) {
	providerName := cl.viper.GetString("ai_provider")
	if providerName == "" {
		providerName = ProviderPerplexity // Default to Perplexity for industry classification
	}

	config, err := cl.LoadProviderConfig(providerName)
	if err != nil {
		return nil, fmt.Errorf("failed to load config for provider %s: %w", providerName, err)
	}

	factory := NewProviderFactory()
	return factory.CreateProvider(config)
}

// LoadProviderByName loads a specific provider by name
func (cl *ConfigLoader) LoadProviderByName(providerName string) (Provider, error) {
	config, err := cl.LoadProviderConfig(providerName)
	if err != nil {
		return nil, err
	}

	factory := NewProviderFactory()
	return factory.CreateProvider(config)
}

// getConfigValue gets a config value from viper or environment variable
func (cl *ConfigLoader) getConfigValue(configKey, envKey string) string {
	// First try viper config
	value := cl.viper.GetString(configKey)
	if value != "" {
		return value
	}

	// Fallback to environment variable if provided
	if envKey != "" {
		value = os.Getenv(envKey)
	}

	return value
}

// getConfigDuration gets a duration config value with fallback
func (cl *ConfigLoader) getConfigDuration(configKey string, defaultValue time.Duration) time.Duration {
	if cl.viper.IsSet(configKey) {
		return cl.viper.GetDuration(configKey)
	}
	return defaultValue
}

// Helper functions for backward compatibility and convenience

// LoadOpenRouterProvider loads an OpenRouter provider
func LoadOpenRouterProvider() (Provider, error) {
	loader := NewConfigLoader(nil)
	return loader.LoadProviderByName(ProviderOpenRouter)
}

// LoadPerplexityProvider loads a Perplexity provider with default timeout
func LoadPerplexityProvider() (Provider, error) {
	return LoadPerplexityProviderWithTimeout(DefaultTimeout)
}

// LoadPerplexityProviderWithTimeout loads a Perplexity provider with custom timeout
func LoadPerplexityProviderWithTimeout(timeout time.Duration) (Provider, error) {
	loader := NewConfigLoader(nil)
	config, err := loader.LoadProviderConfig(ProviderPerplexity)
	if err != nil {
		return nil, err
	}

	// Override timeout
	config.Timeout = timeout

	factory := NewProviderFactory()
	return factory.CreateProvider(config)
}

// LoadDefaultProvider loads the default provider from configuration
func LoadDefaultProvider() (Provider, error) {
	loader := NewConfigLoader(nil)
	return loader.LoadDefaultProvider()
}
