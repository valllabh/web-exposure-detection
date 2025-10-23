# Industry Detection via AI API Integration

## Overview

Automatic industry classification for scanned domains using AI-powered APIs (Clearbit, Perplexity, or Anthropic Claude). This enhances asset criticality assessment by providing industry vertical context.

## Requirements

- Automatically detect industry vertical for a given domain
- Support multiple API providers (Clearbit, Perplexity, Claude)
- Integrate into existing scan workflow
- Cache results to minimize API calls
- Handle API failures gracefully

## API Provider Research

### 1. OpenRouter API (Recommended - Implemented)

**Endpoint**: `https://openrouter.ai/api/v1/chat/completions`

**Authentication**: Bearer token via `Authorization` header

**Pricing**: Varies by model, llama-3.2-3b-instruct is very cost effective

**Model**: `meta-llama/llama-3.2-3b-instruct` (default)

**Preset**: `@preset/industry-classification-prompt` (custom preset for structured output)

**Request Example**:
```bash
curl https://openrouter.ai/api/v1/chat/completions \
  -H "Authorization: Bearer $OPENROUTER_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "@preset/industry-classification-prompt",
    "messages": [
      {
        "role": "user",
        "content": "example.com"
      }
    ]
  }'
```

**Note**: The preset is used as the `model` parameter value, not as a separate field.

**Response Format**:
```json
{
  "industry": "Healthcare",
  "subIndustry": "Telemedicine Services",
  "compliances": ["HIPAA", "GDPR", "SOC 2"]
}
```

**Pros**:
- Custom preset provides structured industry classification prompt
- Consistent JSON output format with industry, sub-industry, and compliance frameworks
- Supports compliance detection (HIPAA, PCI DSS, GDPR, SOC 2)
- Cost effective with small models
- Multiple model options available
- Easy to swap models without code changes

**Cons**:
- Requires API key
- Quality depends on model selection
- May need web search for accuracy (not implemented in base llama model)

**Configuration**:
```yaml
# ~/.web-exposure-detection.yaml
openrouter_api_key: "sk-or-v1-..."
# openrouter_model defaults to "@preset/industry-classification-prompt"
# Override with specific model if needed:
# openrouter_model: "meta-llama/llama-3.2-3b-instruct"
```

Or via environment variable:
```bash
export OPENROUTER_API_KEY="sk-or-v1-..."
```

**Default behavior**: Uses `@preset/industry-classification-prompt` preset unless overridden in config.

**Implementation**: See `pkg/webexposure/industry_api.go`

**Prompt**: See `docs/research/industry-classification-prompt.md`

### 2. Clearbit API

**Endpoint**: `https://company.clearbit.com/v2/companies/find?domain={domain}`

**Authentication**: Bearer token via `Authorization` header

**Pricing**: Pay per enrichment (pricing varies by plan)

**Coverage**: 99% for enriched domains

**Response Example**:
```json
{
  "domain": "shopify.com",
  "name": "Shopify",
  "category": {
    "industry": "E-commerce",
    "sector": "Retail"
  },
  "tags": ["ecommerce", "saas", "payments"],
  "metrics": {
    "employeesRange": "10000+"
  }
}
```

**Pros**:
- Structured NAICS/SIC industry codes
- High accuracy and coverage
- Direct domain to industry mapping
- Returns additional company metadata

**Cons**:
- Requires paid API key
- Credits based pricing
- May not cover all domains

**Integration**:
```go
type ClearbitClassifier struct {
    apiKey     string
    httpClient *http.Client
}

func (c *ClearbitClassifier) ClassifyDomain(domain string) (*IndustryClassification, error) {
    url := fmt.Sprintf("https://company.clearbit.com/v2/companies/find?domain=%s", domain)
    req, _ := http.NewRequest("GET", url, nil)
    req.Header.Set("Authorization", "Bearer "+c.apiKey)
    // ... handle response
}
```

### 2. Perplexity API

**Endpoint**: `https://api.perplexity.ai/chat/completions`

**Authentication**: Bearer token via `Authorization` header

**Pricing**: $5 per 1,000 requests

**Coverage**: Web search based, good for recent/current domains

**Request Example**:
```json
{
  "model": "llama-3.1-sonar-small-128k-online",
  "messages": [
    {
      "role": "user",
      "content": "What industry vertical does shopify.com belong to? Return only: {\"industry\": \"...\", \"sector\": \"...\"}"
    }
  ]
}
```

**Pros**:
- Search based, can handle new/emerging companies
- Transparent pricing
- Can provide reasoning for classification

**Cons**:
- No dedicated industry classification endpoint
- Requires parsing natural language responses
- Less structured than Clearbit
- May hallucinate for unknown domains

### 3. Anthropic Claude API

**Endpoint**: `https://api.anthropic.com/v1/messages`

**Authentication**: `x-api-key` header

**Model**: `claude-3-5-sonnet-20241022`

**Pricing**: Token based ($3/1M input tokens, $15/1M output tokens)

**Request Example**:
```json
{
  "model": "claude-3-5-sonnet-20241022",
  "max_tokens": 500,
  "messages": [
    {
      "role": "user",
      "content": "Analyze the domain \"shopify.com\" and classify its industry. Return ONLY JSON: {\"industry\": \"primary industry\", \"sector\": \"broader sector\", \"tags\": [\"tag1\", \"tag2\"]}"
    }
  ]
}
```

**Pros**:
- Highly accurate for domain classification
- Can infer from domain name alone
- Structured output via prompting
- Handles edge cases well

**Cons**:
- Requires API key
- Token based pricing
- May lack real time company data
- Slower than direct lookup APIs

## Implementation Design

### Industry Classification Interface

```go
type IndustryClassifier interface {
    ClassifyDomain(domain string) (*IndustryClassification, error)
    GetProviderName() string
}

type IndustryClassification struct {
    Domain   string   `json:"domain"`
    Industry string   `json:"industry"`
    Sector   string   `json:"sector,omitempty"`
    Tags     []string `json:"tags,omitempty"`
    Provider string   `json:"provider"`
    NAICS    string   `json:"naics,omitempty"`
    SIC      string   `json:"sic,omitempty"`
}
```

### Integration Points

#### 1. Scan Workflow Integration (scanner.go)

```go
func (s *scanner) ScanWithPreset(...) error {
    // ... existing domain discovery ...

    // Step 2.5: Industry Classification (if API configured)
    var industryClassification *IndustryClassification
    classifier := GetIndustryClassifier()
    if classifier != nil {
        classification, err := ClassifyDomainIndustry(targetDomain)
        if err != nil {
            logger.Warning().Msgf("Industry classification failed: %v", err)
        } else {
            industryClassification = classification

            // Save to file
            industryFile := filepath.Join(resultsDir, "industry-classification.json")
            data, _ := json.MarshalIndent(classification, "", "  ")
            os.WriteFile(industryFile, data, 0600)
        }
    }

    s.industryClassification = industryClassification

    // ... continue with nuclei scan ...
}
```

#### 2. Report Metadata (report_types.go)

```go
type ReportMetadata struct {
    Title        string        `json:"title"`
    Date         string        `json:"date"`
    TargetDomain string        `json:"target_domain"`
    Timestamp    time.Time     `json:"timestamp"`
    Industry     *IndustryInfo `json:"industry,omitempty"`
}

type IndustryInfo struct {
    Industry string   `json:"industry"`
    Sector   string   `json:"sector,omitempty"`
    Tags     []string `json:"tags,omitempty"`
    Provider string   `json:"provider,omitempty"`
}
```

#### 3. Report Generation (report.go)

```go
func (s *scanner) GenerateReport(grouped *GroupedResults, targetDomain string) (*ExposureReport, error) {
    // ... existing report generation ...

    metadata := &ReportMetadata{
        Title:        fmt.Sprintf("External Application Discovery for %s", targetDomain),
        TargetDomain: targetDomain,
        Timestamp:    time.Now(),
    }

    if s.industryClassification != nil {
        metadata.Industry = &IndustryInfo{
            Industry: s.industryClassification.Industry,
            Sector:   s.industryClassification.Sector,
            Tags:     s.industryClassification.Tags,
            Provider: s.industryClassification.Provider,
        }
    }

    report.ReportMetadata = metadata
    return report, nil
}
```

### Configuration

Environment variables or config file for API key management:

```bash
# OpenRouter (implemented)
export OPENROUTER_API_KEY="sk-or-v1-..."

# Or via config file ~/.web-exposure-detection.yaml
openrouter_api_key: "sk-or-v1-..."
openrouter_model: "meta-llama/llama-3.2-3b-instruct"  # Optional
```

Future providers:
```bash
# Clearbit (not implemented)
export CLEARBIT_API_KEY="sk_..."

# Claude (not implemented)
export ANTHROPIC_API_KEY="sk-ant-..."

# Perplexity (not implemented)
export PERPLEXITY_API_KEY="pplx-..."
```

Current implementation:
1. OpenRouter (structured output with compliance detection)

### Caching Strategy

Results cached in `results/{domain}/industry-classification.json`:

```json
{
  "domain": "shopify.com",
  "industry": "E-commerce",
  "sector": "Retail",
  "tags": ["ecommerce", "saas", "payments"],
  "provider": "clearbit"
}
```

Cache invalidation: Manual (delete file) or via --force flag

### Error Handling

```go
func ClassifyDomainIndustry(domain string) (*IndustryClassification, error) {
    classifier := GetIndustryClassifier()
    if classifier == nil {
        return nil, fmt.Errorf("no industry classifier configured")
    }

    result, err := classifier.ClassifyDomain(domain)
    if err != nil {
        // Log warning but don't fail scan
        logger.Warning().Msgf("Industry classification failed: %s", err)
        return nil, err
    }

    return result, nil
}
```

Non blocking: Industry classification failures do not stop the scan workflow.

## Industry Findings in findings.json

15 industry classifications with criticality deltas:

```json
{
  "industry.healthcare": {
    "slug": "industry.healthcare",
    "display_name": "Healthcare",
    "classification": ["industry"],
    "criticality_delta": 1.8
  },
  "industry.financial": {
    "slug": "industry.financial",
    "display_name": "Financial Services",
    "classification": ["industry"],
    "criticality_delta": 1.7
  },
  "industry.government": {
    "slug": "industry.government",
    "display_name": "Government",
    "classification": ["industry"],
    "criticality_delta": 2.0
  }
}
```

Industries covered:
- Healthcare (1.8)
- Financial Services (1.7)
- Government (2.0)
- Telecommunications (1.5)
- E-commerce & Retail (1.3)
- Technology & Software (1.0)
- Education (0.9)
- Manufacturing (1.1)
- Media & Entertainment (0.6)
- Energy & Utilities (1.6)
- Transportation & Logistics (1.0)
- Real Estate (0.5)
- Legal Services (1.4)
- Non-profit & NGO (0.4)
- Hospitality & Travel (0.8)

## Use Cases

1. **Enhanced Criticality Scoring**: Industry vertical adds context to asset criticality
2. **Compliance Prioritization**: Identify regulated industries (Healthcare, Finance, Government)
3. **Attack Surface Insights**: Industry specific threat modeling
4. **Portfolio Analysis**: Group assets by industry for risk assessment

## Future Enhancements

1. Industry based template selection (e.g., HIPAA specific checks for healthcare)
2. Industry specific vulnerability prioritization
3. Compliance framework mapping (PCI-DSS for retail, HIPAA for healthcare)
4. Industry peer comparison (compare findings against industry baseline)
5. Automatic tag enrichment based on industry

## Example Output

```json
{
  "schema_version": "v1",
  "report_metadata": {
    "title": "External Application Discovery for shopify.com",
    "target_domain": "shopify.com",
    "timestamp": "2025-01-18T10:30:00Z",
    "industry": {
      "industry": "E-commerce",
      "sector": "Retail",
      "tags": ["ecommerce", "saas", "payments"],
      "provider": "clearbit"
    }
  },
  "summary": {
    "total_apps": 15,
    "apis_found": 8,
    "average_criticality": 5.0
  }
}
```

## Decision Matrix

| Criteria | OpenRouter | Clearbit | Perplexity | Claude |
|----------|------------|----------|------------|--------|
| Accuracy | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| Coverage | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ |
| Speed | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ |
| Cost | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| Ease | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| Compliance | ⭐⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐ |

**Recommendation**: Use OpenRouter (implemented) for structured classification with compliance detection. Clearbit provides better accuracy but lacks compliance detection.

## Implementation Status

**Status**: OpenRouter integration complete, scan workflow integration pending

**Completed**:
1. ✅ Created `pkg/webexposure/industry_types.go` with IndustryClassifier interface
2. ✅ Implemented `pkg/webexposure/industry_api.go` with OpenRouter support
3. ✅ Added viper configuration support for API key management
4. ✅ Created example config file `.web-exposure-detection.yaml.example`
5. ✅ Documented industry classification prompt in `docs/research/industry-classification-prompt.md`
6. ✅ Updated API provider research documentation
7. ✅ Created `classify` CLI command for testing (`cmd/web-exposure-detection/classify.go`)

**Pending**:
1. Integrate into scan workflow (scanner.go)
2. Add industry findings to findings.json (15 industries with criticality deltas)
3. Update report types (report_types.go) to include IndustryInfo
4. Update report generation (report.go) to include industry metadata
5. Add caching support (save/load from industry-classification.json)

## Testing

**CLI Command**:
```bash
# Set API key
export OPENROUTER_API_KEY="sk-or-v1-..."

# Classify a domain
./bin/web-exposure-detection classify example.com

# With debug output
./bin/web-exposure-detection classify --debug shopify.com
```

**Example output**:
```json
{
  "domain": "example.com",
  "industry": "Technology",
  "subIndustry": "Cloud Infrastructure",
  "compliances": ["SOC 2", "GDPR"],
  "provider": "openrouter",
  "provider_meta": "@preset/industry-classification-prompt"
}
```
