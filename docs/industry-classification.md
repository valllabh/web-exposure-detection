# Industry Classification

Automatic industry classification for domains using OpenRouter API.

## Quick Start

### Setup

```bash
# Set API key
export OPENROUTER_API_KEY="sk-or-v1-..."

# Or create config file
cat > ~/.web-exposure-detection.yaml << EOF
openrouter_api_key: "sk-or-v1-..."
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
  "domain": "example.com",
  "industry": "Technology",
  "subIndustry": "Cloud Infrastructure and DevOps Tools",
  "compliances": ["SOC 2", "GDPR"],
  "provider": "openrouter",
  "provider_meta": "@preset/industry-classification-prompt"
}
```

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

### Environment Variable
```bash
export OPENROUTER_API_KEY="sk-or-v1-..."
```

### Config File
Create `~/.web-exposure-detection.yaml`:
```yaml
openrouter_api_key: "sk-or-v1-..."
# Optional: override default preset
# openrouter_model: "meta-llama/llama-3.2-3b-instruct"
```

### Default Behavior
Uses `@preset/industry-classification-prompt` OpenRouter preset by default.

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
