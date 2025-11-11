# Industry Classification

Automatic industry classification for domains using AI providers. Powered by Perplexity Research API by default.

## Quick Start

### Setup

```bash
# Set Perplexity API key (RECOMMENDED)
export PERPLEXITY_API_KEY="pplx-..."

# Or create config file
cat > ~/.web-exposure-detection.yaml << EOF
ai_provider: "perplexity"
perplexity_api_key: "pplx-..."
EOF
```

### Usage

```bash
# Classify a single domain
./bin/web-exposure-detection classify example.com

# With debug output
./bin/web-exposure-detection classify --debug shopify.com

# Help
./bin/web-exposure-detection classify --help
```

## Output Format

```json
{
  "companyName": "Example Technologies Inc.",
  "parentCompany": null,
  "subsidiaries": ["Example Cloud Services", "Example AI Labs"],
  "industry": "Technology",
  "subIndustry": "Cloud Infrastructure and DevOps Tools",
  "compliances": ["SOC 2", "GDPR"],
  "domain": "example.com",
  "provider": "perplexity",
  "provider_meta": "sonar"
}
```

### Field Descriptions

**AI Generated Fields:**
- `companyName`: Official legal name of the company
- `parentCompany`: Name of parent/holding company (null if none)
- `subsidiaries`: Array of subsidiary company names (empty array if none)
- `industry`: Industry category from fixed list
- `subIndustry`: Specific niche or specialization
- `compliances`: Applicable regulatory compliance frameworks

**System Metadata Fields:**
- `domain`: The domain that was classified
- `provider`: AI provider used (e.g., "perplexity", "openrouter")
- `provider_meta`: Model name or version used

## Industry Categories

20 fixed categories:
- Healthcare
- Financial Services
- Technology
- Government/Public
- Retail/E-commerce
- Education
- Telecommunications
- Insurance
- Manufacturing
- Energy/Utilities
- Transportation
- Entertainment/Media
- Hospitality/Travel
- Pharmaceutical
- Automotive
- Real Estate
- Professional Services
- Industrial/Manufacturing
- Agriculture/Food
- Global Average

## Compliance Frameworks

Automatically detects applicable regulations:
- **HIPAA** - Healthcare data protection
- **PCI DSS v4.0** - Payment card data
- **GDPR** - EU data privacy
- **SOC 2** - SaaS/Cloud security

## Configuration

The tool supports multiple AI providers. See [AI Providers Documentation](./ai-providers.md) for detailed configuration.

### Quick Setup - Perplexity (Recommended)

**Environment Variable:**
```bash
export PERPLEXITY_API_KEY="pplx-..."
```

**Config File:**
Create `~/.web-exposure-detection.yaml`:
```yaml
ai_provider: "perplexity"
perplexity_api_key: "pplx-..."
# Optional: override default model
# perplexity_model: "sonar"  # Default: web search grounding
# perplexity_model: "sonar-pro"  # Advanced model
```

### Alternative Providers

**OpenRouter:**
```yaml
ai_provider: "openrouter"
openrouter_api_key: "sk-or-v1-..."
# openrouter_model: "openai/o1"
```

Or via environment:
```bash
export OPENROUTER_API_KEY="sk-or-v1-..."
```

### Default Behavior
When using **Perplexity** (default provider), the system:
- Automatically uses **Sonar** model with web search grounding
- Loads the industry classification prompt from embedded files
- Sends the prompt as a system message with the domain as user message
- Leverages Perplexity's real-time web search for accurate classification
- Returns enriched data including company name, parent company, and subsidiaries

When using **OpenRouter**, the system:
- Automatically uses OpenAI o1 (120B parameter) model
- Same prompt and message structure

You can override the model by setting the appropriate config key.

## Examples

```bash
# E-commerce site
./bin/web-exposure-detection classify shopify.com
# Output: Retail/E-commerce, PCI DSS, GDPR

# Healthcare provider
./bin/web-exposure-detection classify mayoclinic.org
# Output: Healthcare, HIPAA, GDPR, SOC 2

# SaaS company
./bin/web-exposure-detection classify github.com
# Output: Technology, SOC 2, GDPR

# Financial services
./bin/web-exposure-detection classify stripe.com
# Output: Financial Services, PCI DSS, SOC 2, GDPR
```

## Error Handling

```bash
# Missing API key
./bin/web-exposure-detection classify example.com
# Error: OPENROUTER_API_KEY not configured

# Invalid domain
./bin/web-exposure-detection classify invalid
# API will attempt classification, may return "Other" category
```

## Integration

Currently standalone command. Future integration points:
- Scan workflow (`scan` command will auto-classify)
- Report generation (industry shown in HTML/PDF reports)
- Criticality scoring (industry adds context to asset risk)

## See Also

- [API Provider Research](./research/industry-detection-api.md) - Full API documentation
- [Classification Prompt](./research/industry-classification-prompt.md) - Prompt specification
- [Research Documentation](./research/README.md) - Overall research status
