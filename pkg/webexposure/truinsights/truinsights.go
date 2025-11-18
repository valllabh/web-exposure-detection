package truinsights

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"web-exposure-detection/pkg/webexposure/ai"
)

//go:embed prompts/*.md
var promptsFS embed.FS

// Generator generates TRU insights using AI
type Generator struct {
	provider ai.Provider
}

// NewGenerator creates a new TRU insights generator with extended timeout
func NewGenerator() (*Generator, error) {
	// Load Perplexity provider with custom timeout for TRU insights
	// TRU insights require longer timeout due to:
	// - Web search and research
	// - Processing large prompts
	// - Generating detailed JSON responses
	provider, err := ai.LoadPerplexityProviderWithTimeout(5 * time.Minute)
	if err != nil {
		return nil, fmt.Errorf("failed to load Perplexity provider: %w (ensure PERPLEXITY_API_KEY is set)", err)
	}

	return &Generator{
		provider: provider,
	}, nil
}

// NewGeneratorWithProvider creates a generator with a specific provider
func NewGeneratorWithProvider(provider ai.Provider) *Generator {
	return &Generator{
		provider: provider,
	}
}

// Generate generates TRU insights for a domain
func (g *Generator) Generate(domain string, force bool) (*TRUInsightsResult, error) {
	return g.GenerateWithDebug(domain, force, false)
}

// GenerateWithDebug generates TRU insights with optional debug mode
func (g *Generator) GenerateWithDebug(domain string, force bool, debug bool) (*TRUInsightsResult, error) {
	// Check cache first
	jsonFile := fmt.Sprintf("results/%s/tru-insights-TAS.json", domain)
	if !force {
		if _, err := os.Stat(jsonFile); err == nil {
			logger := GetLogger()
			logger.Info().Msg("Loading TRU insights from cache...")
			content, err := os.ReadFile(jsonFile)
			if err == nil {
				// Load metadata
				var promptLen int
				metadataFile := fmt.Sprintf("results/%s/tru-insights-metadata.json", domain)
				if metaData, err := os.ReadFile(metadataFile); err == nil {
					var meta map[string]interface{}
					json.Unmarshal(metaData, &meta)
					if pl, ok := meta["prompt_length"].(float64); ok {
						promptLen = int(pl)
					}
				}

				return &TRUInsightsResult{
					Content:      string(content),
					Provider:     "perplexity",
					Model:        "sonar-reasoning",
					GeneratedAt:  time.Now().Format(time.RFC3339),
					PromptLength: promptLen,
				}, nil
			}
		}
	}

	// Load input files
	input, err := g.loadInputFiles(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to load input files: %w", err)
	}

	// Load prompt
	prompt, err := g.loadPrompt()
	if err != nil {
		return nil, fmt.Errorf("failed to load prompt: %w", err)
	}

	// Prepare the combined prompt with data
	combinedPrompt, err := g.prepareCombinedPrompt(prompt, input)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare combined prompt: %w", err)
	}

	// Log prompt length and size comparison
	logger := GetLogger()
	promptLength := len(combinedPrompt)

	// Calculate original unoptimized size for comparison
	originalJSON, _ := json.Marshal(input.WebExposureResult)
	originalSize := len(prompt) + len(originalJSON)
	savedBytes := originalSize - promptLength
	savedPercent := 0.0
	if originalSize > 0 {
		savedPercent = float64(savedBytes) / float64(originalSize) * 100
	}

	logger.Info().Msgf("Final prompt length: %d characters (saved %d bytes, %.1f%% reduction)",
		promptLength, savedBytes, savedPercent)

	// Save prompt in debug mode
	if debug {
		promptFile := fmt.Sprintf("results/%s/tru-insights-prompt.md", domain)
		if err := os.WriteFile(promptFile, []byte(combinedPrompt), 0644); err != nil {
			logger.Warning().Msgf("Failed to save debug prompt: %v", err)
		} else {
			logger.Info().Msgf("Debug: Saved final prompt to %s", promptFile)
		}
	}

	// Call Perplexity API
	logger.Info().Msg("Sending request to Perplexity AI (this may take 1-3 minutes)...")
	logger.Info().Msg("Model: sonar-reasoning with web search grounding")
	logger.Info().Msg("Streaming enabled: showing AI reasoning in real-time...")

	// Create streaming callback to show thinking in logs
	var thinkingBuffer strings.Builder
	streamCallback := func(chunk string, isThinking bool) {
		if isThinking {
			thinkingBuffer.WriteString(chunk)
			// Log thinking content periodically (every 50 chars to avoid spam)
			if thinkingBuffer.Len()%50 == 0 && thinkingBuffer.Len() > 0 {
				logger.Debug().Msgf("[AI Thinking] ...%s...",
					truncateString(thinkingBuffer.String(), 60))
			}
		}
	}

	req := &ai.CompletionRequest{
		Messages: []ai.Message{
			{
				Role:    "user",
				Content: combinedPrompt,
			},
		},
		Model:          "sonar-reasoning", // Use sonar-reasoning for research tasks
		Temperature:    0.3,               // Lower temperature for more consistent results
		Stream:         true,              // Enable streaming
		StreamCallback: streamCallback,    // Real-time callback
	}

	// Use context with extended timeout (6 minutes to buffer beyond HTTP timeout)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	logger.Info().Msg("Waiting for AI response (timeout: 5 minutes)...")
	resp, err := g.provider.Complete(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to generate TRU insights: %w", err)
	}

	logger.Info().Msg("Received complete response from Perplexity AI")

	// Strip <think> tags from response (sonar-reasoning includes reasoning)
	cleanContent := stripThinkTags(resp.Content)

	// Validate JSON response
	var jsonCheck interface{}
	if err := json.Unmarshal([]byte(cleanContent), &jsonCheck); err != nil {
		logger.Warning().Msgf("AI response is not valid JSON after cleaning: %v", err)
		logger.Warning().Msg("Saving raw response for debugging")
	}

	// Create result with clean JSON content
	result := &TRUInsightsResult{
		Content:      cleanContent,
		Provider:     resp.ProviderName,
		Model:        resp.Model,
		GeneratedAt:  time.Now().Format(time.RFC3339),
		PromptLength: promptLength,
	}

	// Save JSON response to file
	jsonFile = fmt.Sprintf("results/%s/tru-insights-TAS.json", domain)
	if err := os.WriteFile(jsonFile, []byte(result.Content), 0644); err != nil {
		return nil, fmt.Errorf("failed to save JSON: %w", err)
	}
	logger.Info().Msgf("Saved TRU insights to: %s", jsonFile)

	// Also save metadata
	metadataFile := fmt.Sprintf("results/%s/tru-insights-metadata.json", domain)
	metadata := map[string]interface{}{
		"provider":      result.Provider,
		"model":         result.Model,
		"generated_at":  result.GeneratedAt,
		"prompt_length": result.PromptLength,
	}
	metadataJSON, _ := json.MarshalIndent(metadata, "", "  ")
	os.WriteFile(metadataFile, metadataJSON, 0644)

	return result, nil
}

// loadInputFiles loads and processes all required input files
func (g *Generator) loadInputFiles(domain string) (*TRUInsightsInput, error) {
	resultsDir := fmt.Sprintf("results/%s", domain)

	// Load domain discovery result and extract statistics
	var err error
	domainStats, err := g.loadDomainDiscoveryStats(filepath.Join(resultsDir, "domain-discovery-result.json"))
	if err != nil {
		return nil, fmt.Errorf("failed to load domain discovery stats: %w", err)
	}

	// Load web exposure result (full)
	webExposure, err := g.loadJSONFile(filepath.Join(resultsDir, "web-exposure-result.json"))
	if err != nil {
		return nil, fmt.Errorf("failed to load web exposure result: %w", err)
	}

	// Load industry classification (full)
	industryClass, err := g.loadJSONFile(filepath.Join(resultsDir, "industry-classification.json"))
	if err != nil {
		return nil, fmt.Errorf("failed to load industry classification: %w", err)
	}

	return &TRUInsightsInput{
		DomainStats:            domainStats,
		WebExposureResult:      webExposure,
		IndustryClassification: industryClass,
	}, nil
}

// loadDomainDiscoveryStats extracts only statistics from domain discovery result
func (g *Generator) loadDomainDiscoveryStats(path string) (*DomainDiscoveryStatistics, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	stats := &DomainDiscoveryStatistics{
		DomainList: []string{},
	}

	// Extract statistics
	if statsData, ok := raw["statistics"].(map[string]interface{}); ok {
		if val, ok := statsData["total_subdomains"].(float64); ok {
			stats.TotalSubdomains = int(val)
		}
		if val, ok := statsData["active_services"].(float64); ok {
			stats.ActiveServices = int(val)
		}
	}

	// Extract domain list
	if domains, ok := raw["domains"].(map[string]interface{}); ok {
		for domain := range domains {
			stats.DomainList = append(stats.DomainList, domain)
		}
		stats.TotalDomains = len(stats.DomainList)
		if len(stats.DomainList) > 0 {
			stats.PrimaryDomain = stats.DomainList[0]
		}
	}

	return stats, nil
}

// loadJSONFile loads a JSON file into a generic interface
func (g *Generator) loadJSONFile(path string) (interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var result interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return result, nil
}

// loadPrompt loads the threat landscape assessment prompt
func (g *Generator) loadPrompt() (string, error) {
	// Try embedded prompt first
	data, err := promptsFS.ReadFile("prompts/threat-landscape.md")
	if err != nil {
		// Fallback to file system
		data, err = os.ReadFile("prompts/threat-landscape.md")
		if err != nil {
			return "", fmt.Errorf("failed to load prompt from both embed and filesystem: %w", err)
		}
	}

	return string(data), nil
}

// prepareCombinedPrompt combines the prompt template with input data
func (g *Generator) prepareCombinedPrompt(prompt string, input *TRUInsightsInput) (string, error) {
	// Extract compact summary from web exposure
	webSummary, err := extractWebExposureSummary(input.WebExposureResult)
	if err != nil {
		return "", fmt.Errorf("failed to extract web exposure summary: %w", err)
	}

	// Extract optimized findings
	optimizedFindings, err := extractOptimizedFindings(input.WebExposureResult)
	if err != nil {
		return "", fmt.Errorf("failed to extract optimized findings: %w", err)
	}

	// Format as markdown (without duplicates)
	webExposureMD := webSummary.formatAsMarkdown()
	findingsMD := optimizedFindings.formatAsMarkdown()

	// Format domain stats as markdown (statistics only, no list)
	domainStatsMD := formatDomainStatsAsMarkdown(input.DomainStats)

	// Format industry classification as markdown
	industryMD := formatIndustryAsMarkdown(input.IndustryClassification)

	// Combine prompt with data
	combined := fmt.Sprintf(`%s

---

## Input Data

### 1. Domain Discovery Statistics
%s

---

### 2. Web Exposure Summary
%s

---

### 3. Findings Analysis (Deduplicated)
%s

---

### 4. Industry Classification
%s

---

Please analyze the above data and generate TRU insights as specified in the prompt.
Return your analysis in markdown format with clear sections and findings.
`, prompt, domainStatsMD, webExposureMD, findingsMD, industryMD)

	return combined, nil
}

// formatDomainStatsAsMarkdown converts domain stats to markdown (statistics only)
func formatDomainStatsAsMarkdown(stats *DomainDiscoveryStatistics) string {
	var md strings.Builder

	md.WriteString(fmt.Sprintf("- **Total domains discovered**: %d\n", stats.TotalDomains))
	md.WriteString(fmt.Sprintf("- **Subdomains**: %d\n", stats.TotalSubdomains))
	md.WriteString(fmt.Sprintf("- **Active services**: %d\n", stats.ActiveServices))
	md.WriteString(fmt.Sprintf("- **Primary domain**: %s\n", stats.PrimaryDomain))

	// Note: Domain list removed to save context - details are in findings section

	return md.String()
}

// formatIndustryAsMarkdown converts industry classification to markdown
func formatIndustryAsMarkdown(industryData interface{}) string {
	data, ok := industryData.(map[string]interface{})
	if !ok {
		return "No industry classification available"
	}

	var md strings.Builder

	if domain := getStringValue(data, "domain"); domain != "" {
		md.WriteString(fmt.Sprintf("- **Domain**: %s\n", domain))
	}

	if industry := getStringValue(data, "industry"); industry != "" {
		md.WriteString(fmt.Sprintf("- **Industry**: %s\n", industry))
	}

	if subIndustry := getStringValue(data, "subIndustry"); subIndustry != "" {
		md.WriteString(fmt.Sprintf("- **Sub-industry**: %s\n", subIndustry))
	}

	if headquartersCity := getStringValue(data, "headquartersCity"); headquartersCity != "" {
		md.WriteString(fmt.Sprintf("- **Headquarters**: %s\n", headquartersCity))
	}

	// Extract operating regions if present
	if operatingRegions, ok := data["operatingRegions"].([]interface{}); ok && len(operatingRegions) > 0 {
		var regionList []string
		for _, region := range operatingRegions {
			if regionStr, ok := region.(string); ok {
				regionList = append(regionList, regionStr)
			}
		}
		if len(regionList) > 0 {
			md.WriteString(fmt.Sprintf("- **Operating regions**: %s\n", strings.Join(regionList, ", ")))
		}
	}

	if primaryRegion := getStringValue(data, "primaryRegion"); primaryRegion != "" {
		md.WriteString(fmt.Sprintf("- **Primary region**: %s\n", primaryRegion))
	}

	// Extract compliances if present
	if compliances, ok := data["compliances"].([]interface{}); ok && len(compliances) > 0 {
		md.WriteString("- **Compliance frameworks**: ")
		var compList []string
		for _, comp := range compliances {
			if compStr, ok := comp.(string); ok {
				compList = append(compList, compStr)
			}
		}
		md.WriteString(fmt.Sprintf("%s\n", strings.Join(compList, ", ")))
	}

	return md.String()
}

// truncateString truncates a string to maxLen characters
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	// Take last maxLen characters to show most recent thinking
	return s[len(s)-maxLen:]
}

// stripThinkTags removes <think>...</think> tags from AI response
func stripThinkTags(content string) string {
	// Remove <think>...</think> blocks (sonar-reasoning includes reasoning)
	result := content

	// Find and remove all <think> blocks
	for {
		startIdx := strings.Index(result, "<think>")
		if startIdx == -1 {
			break
		}

		endIdx := strings.Index(result[startIdx:], "</think>")
		if endIdx == -1 {
			// No closing tag, remove from start to end
			result = result[:startIdx]
			break
		}

		// Remove the entire block including tags
		endIdx += startIdx + len("</think>")
		result = result[:startIdx] + result[endIdx:]
	}

	return strings.TrimSpace(result)
}

// Cache functions removed - now using direct JSON file storage
