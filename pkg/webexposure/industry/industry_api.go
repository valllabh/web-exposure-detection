package industry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

const (
	openRouterURL                = "https://openrouter.ai/api/v1/chat/completions"
	defaultIndustryPreset        = "@preset/industry-classification-prompt"
	requestTimeout               = 30 * time.Second
)

// OpenRouterClassifier implements IndustryClassifier using OpenRouter API
type OpenRouterClassifier struct {
	apiKey     string
	model      string
	httpClient *http.Client
}

// OpenRouterRequest represents the request payload for OpenRouter API
type OpenRouterRequest struct {
	Model    string              `json:"model"`
	Messages []OpenRouterMessage `json:"messages"`
}

// OpenRouterMessage represents a message in the chat
type OpenRouterMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// OpenRouterResponse represents the response from OpenRouter API
type OpenRouterResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// NewOpenRouterClassifier creates a new OpenRouter classifier
func NewOpenRouterClassifier() (*OpenRouterClassifier, error) {
	logger := GetLogger()

	// Try to get API key from viper (config file or env)
	apiKey := viper.GetString("openrouter_api_key")
	if apiKey == "" {
		// Fallback to environment variable
		apiKey = os.Getenv("OPENROUTER_API_KEY")
	}

	if apiKey == "" {
		return nil, fmt.Errorf("OPENROUTER_API_KEY not configured (use config file or environment variable)")
	}

	// Use preset as model by default, allow override via config
	model := viper.GetString("openrouter_model")
	if model == "" {
		model = defaultIndustryPreset
		logger.Debug().Msgf("Using default industry classification preset: %s", model)
	} else {
		logger.Debug().Msgf("Using custom model/preset: %s", model)
	}

	return &OpenRouterClassifier{
		apiKey: apiKey,
		model:  model,
		httpClient: &http.Client{
			Timeout: requestTimeout,
		},
	}, nil
}

// GetProviderName returns the provider name
func (c *OpenRouterClassifier) GetProviderName() string {
	return "openrouter"
}

// ClassifyDomain classifies a domain using OpenRouter API
func (c *OpenRouterClassifier) ClassifyDomain(domain string) (*IndustryClassification, error) {
	logger := GetLogger()
	logger.Debug().Msgf("Classifying domain with OpenRouter: %s", domain)

	// Clean domain
	cleanDomain := strings.TrimPrefix(strings.TrimPrefix(domain, "https://"), "http://")
	cleanDomain = strings.TrimPrefix(cleanDomain, "www.")

	// Create request - preset is used as the model parameter
	reqBody := OpenRouterRequest{
		Model: c.model,
		Messages: []OpenRouterMessage{
			{
				Role:    "user",
				Content: cleanDomain,
			},
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", openRouterURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	// Make request
	startTime := time.Now()
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	duration := time.Since(startTime)
	logger.Debug().Msgf("OpenRouter API response time: %v", duration)

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned non-200 status: %d, body: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var apiResp OpenRouterResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if apiResp.Error != nil {
		return nil, fmt.Errorf("API error: %s", apiResp.Error.Message)
	}

	if len(apiResp.Choices) == 0 {
		return nil, fmt.Errorf("no choices in API response")
	}

	// Extract JSON from response content
	content := apiResp.Choices[0].Message.Content
	logger.Debug().Msgf("OpenRouter response content: %s", content)

	// Parse industry classification from content
	var result IndustryClassification
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		// Try to extract JSON from markdown code blocks
		content = extractJSONFromMarkdown(content)
		if err := json.Unmarshal([]byte(content), &result); err != nil {
			return nil, fmt.Errorf("failed to parse industry classification from response: %w, content: %s", err, content)
		}
	}

	// Set metadata
	result.Domain = cleanDomain
	result.Provider = "openrouter"
	result.ProviderMeta = c.model

	logger.Debug().Msgf("Successfully classified %s as: %s (sub: %s)", cleanDomain, result.Industry, result.SubIndustry)

	return &result, nil
}

// extractJSONFromMarkdown extracts JSON from markdown code blocks
func extractJSONFromMarkdown(content string) string {
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

// getIndustryClassifier returns a configured industry classifier or nil (private)
func getIndustryClassifier() IndustryClassifier {
	logger := GetLogger()

	// Try OpenRouter first
	classifier, err := NewOpenRouterClassifier()
	if err != nil {
		logger.Debug().Msgf("OpenRouter classifier not available: %v", err)
		return nil
	}

	return classifier
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
	classifier := getIndustryClassifier()
	if classifier == nil {
		return nil, fmt.Errorf("no industry classifier configured")
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
