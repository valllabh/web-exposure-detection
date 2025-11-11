package ai

import (
	"context"
	"time"
)

// Message represents a chat message
type Message struct {
	Role    string // "user", "assistant", "system"
	Content string
}

// StreamCallback is called for each chunk of streamed response
type StreamCallback func(chunk string, isThinking bool)

// CompletionRequest represents a request for AI completion
type CompletionRequest struct {
	Messages       []Message
	Model          string         // Optional: provider-specific model name
	Temperature    float64        // Optional: 0.0 to 1.0, controls randomness
	MaxTokens      int            // Optional: max tokens in response
	Timeout        time.Duration  // Optional: request timeout
	Stream         bool           // Optional: enable streaming
	StreamCallback StreamCallback // Optional: callback for streaming chunks
}

// CompletionResponse represents the response from AI provider
type CompletionResponse struct {
	Content      string            // The actual response text
	Model        string            // Model used (may differ from request if using presets)
	ProviderName string            // Name of the provider that generated response
	Metadata     map[string]string // Provider-specific metadata
}

// Provider is the interface that all AI providers must implement
type Provider interface {
	// Complete sends a completion request and returns the response
	// Supports both streaming and non-streaming modes based on req.Stream
	Complete(ctx context.Context, req *CompletionRequest) (*CompletionResponse, error)

	// GetProviderName returns the name of this provider (e.g., "openrouter", "perplexity")
	GetProviderName() string

	// GetDefaultModel returns the default model for this provider
	GetDefaultModel() string
}

// Config represents configuration for an AI provider
type Config struct {
	Provider    string            // Provider name: "openrouter", "perplexity"
	APIKey      string            // API key for the provider
	Model       string            // Default model/preset to use
	Timeout     time.Duration     // Default timeout for requests
	BaseURL     string            // Optional: custom base URL
	ExtraParams map[string]string // Provider-specific extra parameters
}
