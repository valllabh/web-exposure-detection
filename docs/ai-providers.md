# AI Provider System

The AI provider system is a flexible, adapter based architecture for integrating multiple AI/LLM providers into the web exposure detection tool.

## Overview

The system is designed to support multiple AI providers through a common interface, making it easy to:
- Switch between different AI providers
- Add new providers without modifying existing code
- Use different providers for different use cases
- Configure providers through config files or environment variables

## Architecture

```
pkg/webexposure/ai/
├── ai.go              # Core interfaces and types
├── factory.go         # Provider factory pattern
├── config.go          # Configuration loading helpers
├── openrouter.go      # OpenRouter adapter
├── perplexity.go      # Perplexity adapter
└── logger.go          # Logger utilities
```

### Core Interfaces

**Provider Interface**
```go
type Provider interface {
    Complete(ctx context.Context, req *CompletionRequest) (*CompletionResponse, error)
    GetProviderName() string
    GetDefaultModel() string
}
```

**CompletionRequest**
```go
type CompletionRequest struct {
    Messages    []Message
    Model       string
    Temperature float64
    MaxTokens   int
    Timeout     time.Duration
}
```

**CompletionResponse**
```go
type CompletionResponse struct {
    Content      string
    Model        string
    ProviderName string
    Metadata     map[string]string
}
```

## Supported Providers

### Perplexity (Recommended for Industry Classification)
Provider for Perplexity AI research models with online capabilities.

**Configuration:**
```yaml
ai_provider: "perplexity"
perplexity_api_key: "pplx-..."
perplexity_model: "sonar"  # Sonar model with web search grounding (default)
# perplexity_model: "sonar-pro"  # Advanced Sonar Pro model for complex queries
perplexity_base_url: "https://api.perplexity.ai/chat/completions"  # optional
perplexity_timeout: "30s"  # optional
```

**Notes:**
- Perplexity is the **recommended provider** for industry classification
- Uses **Sonar** model by default with web search grounding capabilities
- The Sonar model can access real-time web information for accurate domain classification
- Returns enriched data: company name, parent company, subsidiaries, industry, and compliances
- The industry classification prompt is embedded and sent as a system message

**Environment Variable:**
```bash
export PERPLEXITY_API_KEY="pplx-..."
```

### OpenRouter
Provider for accessing multiple models through OpenRouter API.

**Configuration:**
```yaml
ai_provider: "openrouter"
openrouter_api_key: "your-api-key"
openrouter_model: "openai/o1"  # Uses OpenAI o1 120B model (default for industry classification)
# openrouter_model: "@preset/industry-classification-prompt"  # Legacy preset approach
openrouter_base_url: "https://openrouter.ai/api/v1/chat/completions"  # optional
openrouter_timeout: "30s"  # optional
```

**Notes:**
- When using OpenRouter for industry classification, the system automatically uses OpenAI o1 model
- The industry classification prompt is embedded in the binary and sent as a system message
- You can override the model using the `openrouter_model` config option

**Environment Variable:**
```bash
export OPENROUTER_API_KEY="your-api-key"
```

### Perplexity
Provider for Perplexity AI models.

**Configuration:**
```yaml
ai_provider: "perplexity"
perplexity_api_key: "your-api-key"
perplexity_model: "llama-3.1-sonar-small-128k-online"
perplexity_base_url: "https://api.perplexity.ai/chat/completions"  # optional
perplexity_timeout: "30s"  # optional
```

**Environment Variable:**
```bash
export PERPLEXITY_API_KEY="your-api-key"
```

## Usage Examples

### Loading Default Provider

```go
import "web-exposure-detection/pkg/webexposure/ai"

// Load from configuration (checks ai_provider config, defaults to perplexity)
provider, err := ai.LoadDefaultProvider()
if err != nil {
    return err
}
```

### Loading Specific Provider

```go
// Load OpenRouter
provider, err := ai.LoadOpenRouterProvider()

// Load Perplexity
provider, err := ai.LoadPerplexityProvider()
```

### Using Provider Factory

```go
factory := ai.NewProviderFactory()

config := &ai.Config{
    Provider: ai.ProviderOpenRouter,
    APIKey:   "your-api-key",
    Model:    "@preset/industry-classification-prompt",
    Timeout:  30 * time.Second,
}

provider, err := factory.CreateProvider(config)
```

### Making Completion Requests

```go
ctx := context.Background()

req := &ai.CompletionRequest{
    Messages: []ai.Message{
        {Role: "user", Content: "example.com"},
    },
}

resp, err := provider.Complete(ctx, req)
if err != nil {
    return err
}

fmt.Println("Response:", resp.Content)
fmt.Println("Model:", resp.Model)
fmt.Println("Provider:", resp.ProviderName)
```

### Using with Industry Classification

The industry classification system automatically uses the AI provider configured in your settings:

```go
import "web-exposure-detection/pkg/webexposure/industry"

// Uses default AI provider from configuration
classifier, err := industry.NewAIBasedClassifier()

result, err := classifier.ClassifyDomain("example.com")
```

## Configuration Priority

The system loads configuration in the following priority order:

1. Viper configuration file values
2. Environment variables
3. Default values

For example, for OpenRouter API key:
1. Check `openrouter_api_key` in config file
2. Check `OPENROUTER_API_KEY` environment variable
3. Error if not found

## Adding New Providers

To add a new AI provider:

1. Create a new provider implementation file (e.g., `anthropic.go`)
2. Implement the `Provider` interface
3. Add provider constant to `factory.go`
4. Add case in `CreateProvider` switch statement
5. Add configuration loading in `config.go`
6. Update documentation

Example skeleton:

```go
// newprovider.go
package ai

const ProviderNewProvider = "newprovider"

type newProvider struct {
    apiKey  string
    model   string
    // ... other fields
}

func newNewProvider(config *Config) (Provider, error) {
    // Implementation
}

func (p *newProvider) Complete(ctx context.Context, req *CompletionRequest) (*CompletionResponse, error) {
    // Implementation
}

func (p *newProvider) GetProviderName() string {
    return ProviderNewProvider
}

func (p *newProvider) GetDefaultModel() string {
    return p.model
}
```

## Utility Functions

### ExtractJSONFromMarkdown

Helper function to extract JSON from markdown code blocks in AI responses:

```go
content := resp.Content
jsonContent := ai.ExtractJSONFromMarkdown(content)
```

## Best Practices

1. **Always use context**: Pass context to Complete() for timeout control
2. **Handle errors**: AI providers can fail, always check errors
3. **Use configuration**: Don't hardcode API keys, use config files or env vars
4. **Log appropriately**: Use Debug level for API responses, Info for user facing messages
5. **Cache results**: AI calls are expensive, cache when possible (see industry classification)

## Troubleshooting

**Provider not loading:**
- Check API key is configured in config file or environment variable
- Verify provider name is spelled correctly
- Check logs for detailed error messages

**Request timeout:**
- Increase timeout in configuration
- Check network connectivity
- Verify API endpoint is reachable

**Parsing errors:**
- Use ExtractJSONFromMarkdown for responses in code blocks
- Check if model is returning expected format
- Review prompt/preset configuration
