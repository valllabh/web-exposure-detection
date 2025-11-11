package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	openRouterDefaultURL = "https://openrouter.ai/api/v1/chat/completions"
)

// openRouterProvider implements the Provider interface for OpenRouter
type openRouterProvider struct {
	apiKey     string
	baseURL    string
	model      string
	timeout    time.Duration
	httpClient *http.Client
}

// openRouterRequest represents the request payload for OpenRouter API
type openRouterRequest struct {
	Model    string                   `json:"model"`
	Messages []openRouterMessage      `json:"messages"`
}

// openRouterMessage represents a message in the chat
type openRouterMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// openRouterResponse represents the response from OpenRouter API
type openRouterResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Model string `json:"model,omitempty"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// newOpenRouterProvider creates a new OpenRouter provider
func newOpenRouterProvider(config *Config) (Provider, error) {
	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = openRouterDefaultURL
	}

	return &openRouterProvider{
		apiKey:  config.APIKey,
		baseURL: baseURL,
		model:   config.Model,
		timeout: config.Timeout,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
	}, nil
}

// Complete sends a completion request to OpenRouter
func (p *openRouterProvider) Complete(ctx context.Context, req *CompletionRequest) (*CompletionResponse, error) {
	// Use model from request if specified, otherwise use provider default
	model := p.model
	if req.Model != "" {
		model = req.Model
	}

	// Convert messages
	messages := make([]openRouterMessage, len(req.Messages))
	for i, msg := range req.Messages {
		messages[i] = openRouterMessage{
			Role:    msg.Role,
			Content: msg.Content,
		}
	}

	// Create request body
	reqBody := openRouterRequest{
		Model:    model,
		Messages: messages,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var apiResp openRouterResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if apiResp.Error != nil {
		return nil, fmt.Errorf("API error: %s", apiResp.Error.Message)
	}

	if len(apiResp.Choices) == 0 {
		return nil, fmt.Errorf("no choices in API response")
	}

	// Build response
	content := apiResp.Choices[0].Message.Content
	responseModel := apiResp.Model
	if responseModel == "" {
		responseModel = model
	}

	return &CompletionResponse{
		Content:      content,
		Model:        responseModel,
		ProviderName: p.GetProviderName(),
		Metadata: map[string]string{
			"base_url": p.baseURL,
		},
	}, nil
}

// GetProviderName returns the provider name
func (p *openRouterProvider) GetProviderName() string {
	return ProviderOpenRouter
}

// GetDefaultModel returns the default model
func (p *openRouterProvider) GetDefaultModel() string {
	return p.model
}

// ExtractJSONFromMarkdown extracts JSON from markdown code blocks
// This is a utility function that can be used by consumers of the AI provider
func ExtractJSONFromMarkdown(content string) string {
	// Look for ```json ... ``` or ``` ... ```
	if strings.Contains(content, "```") {
		lines := strings.Split(content, "\n")
		var jsonLines []string
		inCodeBlock := false
		for _, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "```") {
				inCodeBlock = !inCodeBlock
				continue
			}
			if inCodeBlock {
				jsonLines = append(jsonLines, line)
			}
		}
		if len(jsonLines) > 0 {
			return strings.Join(jsonLines, "\n")
		}
	}
	return content
}
