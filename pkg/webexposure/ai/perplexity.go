package ai

import (
	"bufio"
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
	perplexityDefaultURL   = "https://api.perplexity.ai/chat/completions"
	perplexityDefaultModel = "sonar" // Sonar model with web search grounding
)

// perplexityProvider implements the Provider interface for Perplexity AI
type perplexityProvider struct {
	apiKey     string
	baseURL    string
	model      string
	timeout    time.Duration
	httpClient *http.Client
}

// perplexityRequest represents the request payload for Perplexity API
type perplexityRequest struct {
	Model       string              `json:"model"`
	Messages    []perplexityMessage `json:"messages"`
	Temperature *float64            `json:"temperature,omitempty"`
	MaxTokens   *int                `json:"max_tokens,omitempty"`
	Stream      bool                `json:"stream,omitempty"`
}

// perplexityMessage represents a message in the chat
type perplexityMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// perplexityResponse represents the response from Perplexity API
type perplexityResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
			Role    string `json:"role"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Model string `json:"model"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error,omitempty"`
}

// newPerplexityProvider creates a new Perplexity provider
func newPerplexityProvider(config *Config) (Provider, error) {
	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = perplexityDefaultURL
	}

	model := config.Model
	if model == "" {
		model = perplexityDefaultModel
	}

	return &perplexityProvider{
		apiKey:  config.APIKey,
		baseURL: baseURL,
		model:   model,
		timeout: config.Timeout,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
	}, nil
}

// Complete sends a completion request to Perplexity
func (p *perplexityProvider) Complete(ctx context.Context, req *CompletionRequest) (*CompletionResponse, error) {
	// Use model from request if specified, otherwise use provider default
	model := p.model
	if req.Model != "" {
		model = req.Model
	}

	// Convert messages
	messages := make([]perplexityMessage, len(req.Messages))
	for i, msg := range req.Messages {
		messages[i] = perplexityMessage{
			Role:    msg.Role,
			Content: msg.Content,
		}
	}

	// Create request body
	reqBody := perplexityRequest{
		Model:    model,
		Messages: messages,
		Stream:   req.Stream,
	}

	// Add optional parameters if provided
	if req.Temperature > 0 {
		reqBody.Temperature = &req.Temperature
	}
	if req.MaxTokens > 0 {
		reqBody.MaxTokens = &req.MaxTokens
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

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Handle streaming response
	if req.Stream {
		return p.handleStreamingResponse(ctx, resp, model, req.StreamCallback)
	}

	// Handle non-streaming response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response
	var apiResp perplexityResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if apiResp.Error != nil {
		return nil, fmt.Errorf("API error: %s (type: %s, code: %s)",
			apiResp.Error.Message, apiResp.Error.Type, apiResp.Error.Code)
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

	metadata := map[string]string{
		"base_url":      p.baseURL,
		"finish_reason": apiResp.Choices[0].FinishReason,
	}

	return &CompletionResponse{
		Content:      content,
		Model:        responseModel,
		ProviderName: p.GetProviderName(),
		Metadata:     metadata,
	}, nil
}

// handleStreamingResponse processes SSE streaming response
func (p *perplexityProvider) handleStreamingResponse(ctx context.Context, resp *http.Response, model string, callback StreamCallback) (*CompletionResponse, error) {
	var fullContent strings.Builder
	var responseModel string
	var finishReason string
	inThinkTag := false
	var thinkContent strings.Builder

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		line := scanner.Text()

		// SSE format: "data: {...}"
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		data := strings.TrimPrefix(line, "data: ")

		// Check for stream end
		if data == "[DONE]" {
			break
		}

		// Parse chunk
		var chunk struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
				FinishReason string `json:"finish_reason"`
			} `json:"choices"`
			Model string `json:"model"`
		}

		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue // Skip malformed chunks
		}

		if len(chunk.Choices) == 0 {
			continue
		}

		// Extract model and finish reason
		if chunk.Model != "" {
			responseModel = chunk.Model
		}
		if chunk.Choices[0].FinishReason != "" {
			finishReason = chunk.Choices[0].FinishReason
		}

		// Process content chunk
		content := chunk.Choices[0].Delta.Content
		if content == "" {
			continue
		}

		// Track <think> tags and call callback
		for _, char := range content {
			fullContent.WriteRune(char)

			// Detect <think> opening tag
			if strings.HasSuffix(fullContent.String(), "<think>") && !inThinkTag {
				inThinkTag = true
				thinkContent.Reset()
				if callback != nil {
					callback("<think>", true)
				}
			} else if strings.HasSuffix(fullContent.String(), "</think>") && inThinkTag {
				// Detect </think> closing tag
				inThinkTag = false
				if callback != nil {
					callback("</think>", true)
				}
			} else if inThinkTag {
				// Inside think tag
				thinkContent.WriteRune(char)
				if callback != nil {
					callback(string(char), true)
				}
			} else {
				// Outside think tag (actual response)
				if callback != nil {
					callback(string(char), false)
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading stream: %w", err)
	}

	if responseModel == "" {
		responseModel = model
	}

	metadata := map[string]string{
		"base_url":      p.baseURL,
		"finish_reason": finishReason,
		"streaming":     "true",
	}

	return &CompletionResponse{
		Content:      fullContent.String(),
		Model:        responseModel,
		ProviderName: p.GetProviderName(),
		Metadata:     metadata,
	}, nil
}

// GetProviderName returns the provider name
func (p *perplexityProvider) GetProviderName() string {
	return ProviderPerplexity
}

// GetDefaultModel returns the default model
func (p *perplexityProvider) GetDefaultModel() string {
	return p.model
}
