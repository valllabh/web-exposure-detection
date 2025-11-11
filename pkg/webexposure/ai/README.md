# AI Provider Package

Multi provider AI/LLM integration system with adapter pattern.

## Package Overview

This package provides a clean abstraction layer for integrating multiple AI providers into the application. It uses the adapter pattern to support different AI/LLM services through a common interface.

## Files

- `ai.go` - Core interfaces and types (Provider, CompletionRequest, CompletionResponse, Config)
- `factory.go` - Provider factory pattern for creating providers
- `config.go` - Configuration loading helpers with viper integration
- `openrouter.go` - OpenRouter adapter implementation
- `perplexity.go` - Perplexity adapter implementation
- `logger.go` - Logger utilities

## Usage

```go
import "web-exposure-detection/pkg/webexposure/ai"

// Load default provider from configuration
provider, err := ai.LoadDefaultProvider()

// Or load specific provider
provider, err := ai.LoadOpenRouterProvider()
provider, err := ai.LoadPerplexityProvider()

// Use the provider
ctx := context.Background()
req := &ai.CompletionRequest{
    Messages: []ai.Message{
        {Role: "user", Content: "Hello"},
    },
}
resp, err := provider.Complete(ctx, req)
```

## Documentation

See [docs/ai-providers.md](../../../docs/ai-providers.md) for complete documentation including:
- Architecture overview
- Configuration guide
- Provider specific details
- Adding new providers
- Best practices

## Supported Providers

- **OpenRouter** - Access to multiple models through OpenRouter API
- **Perplexity** - Perplexity AI models

## Design Principles

1. **Provider Interface** - All providers implement the same interface
2. **Factory Pattern** - Centralized provider creation
3. **Configuration** - Viper integration with environment variable fallback
4. **Adapter Pattern** - Each provider is an independent adapter
5. **Context Support** - All requests support context for timeout control
