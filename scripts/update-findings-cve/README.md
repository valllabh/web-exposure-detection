# CVE and CWE Statistics Update Scripts

Scripts for updating CVE and CWE statistics in findings.json using vulnx (ProjectDiscovery's vulnerability intelligence tool).

## Prerequisites

1. **Install vulnx**
   ```bash
   go install github.com/projectdiscovery/cvemap/cmd/vulnx@latest
   ```

2. **Authenticate with ProjectDiscovery Cloud** (recommended to avoid rate limits)
   ```bash
   vulnx auth --api-key YOUR_API_KEY
   ```
   Get your free API key from: https://cloud.projectdiscovery.io/

3. **Verify installation**
   ```bash
   vulnx version
   vulnx healthcheck
   ```

## Usage

### Update CVE Statistics

```bash
# From project root
make update-cve-stats

# Or directly
python3 scripts/update-findings-cve/update-cve-stats.py

# Resume from a specific finding (if interrupted)
python3 scripts/update-findings-cve/update-cve-stats.py --resume-from frontend.backbone

# Adjust rate limits via environment variables
RATE_LIMIT_DELAY=3.0 make update-cve-stats
```

### Update CWE Statistics

CWE data is populated based on security research for each technology category:

```bash
# From project root
python3 scripts/update-findings-cve/populate-cwe-from-research.py
```

This script applies researched common weakness patterns for each technology type (frontend frameworks, backend frameworks, CMS, API servers, AI services, gateways) without requiring API calls.

### Test Single Finding

```bash
python3 scripts/update-findings-cve/test-single-finding.py react
```

## What Gets Updated

### CVE Statistics

Updates `pkg/webexposure/findings/findings.json` with CVE statistics:

```json
{
  "frontend.react": {
    "security": {
      "cve": {
        "search_key": "react",
        "stats": {
          "critical": 0,
          "high": 0,
          "medium": 1,
          "low": 0,
          "total": 1,
          "kev": 0
        },
        "updated": "2025-10-23T04:51:46Z"
      }
    }
  }
}
```

### CWE Statistics (Weakness Enumeration)

```json
{
  "frontend.react": {
    "security": {
      "cve": { ... },
      "weaknesses": {
        "stats": {
          "total": 5,
          "top_categories": [
            {"id": "CWE-79", "name": "Cross-site Scripting (XSS)", "count": 3},
            {"id": "CWE-20", "name": "Improper Input Validation", "count": 2}
          ]
        },
        "updated": "2025-10-23T05:30:00Z"
      }
    }
  }
}
```

## How It Works

### CVE Update Process

1. **Search Key Generation**: For each finding, generates a search key (e.g., "React.js" → "react")
2. **CVE Query**: Queries vulnx for total CVE count
3. **Severity Breakdown**: Queries for critical, high, medium, low counts
4. **KEV Check**: Checks if CVEs are in CISA's Known Exploited Vulnerabilities catalog
5. **Update**: Updates findings.json with statistics and timestamp
6. **Progress Saving**: Saves every 5 findings to prevent data loss

### CWE Update Process

CWE data is based on security research rather than API queries:

1. **Category Mapping**: Each finding is mapped to a technology category (frontend, backend_framework, cms, ecommerce, api_server, ai_service, gateway)
2. **Apply Research Data**: Technology specific CWE patterns are applied based on security research
3. **Common Weaknesses**: Each category has 5 researched common weaknesses (e.g., XSS for frontend, SQL injection for CMS)
4. **Prevalence Counts**: Weaknesses include prevalence indicators (3-5) showing how common they are
5. **Update**: Adds weaknesses section to findings.json with technology appropriate CWEs

Research includes OWASP Top 10, OWASP API Security Top 10, OWASP LLM Top 10, and real world CVE analysis for each technology type.

## Rate Limiting & Performance

### Default Delays

- **CVE Script**: 2.0s between findings, 0.5s between queries (~6 queries per finding)
- **CWE Script**: 0.5s between queries
- **Total Runtime**: ~15-20 minutes for all findings

### Customize Delays

```bash
# Increase delays to avoid rate limits
RATE_LIMIT_DELAY=3.0 QUERY_DELAY=1.0 make update-cve-stats

# Faster (if you have higher rate limits)
RATE_LIMIT_DELAY=1.0 QUERY_DELAY=0.3 make update-cve-stats
```

### Resume After Interruption

If the script is interrupted, resume from where it left off:

```bash
python3 scripts/update-findings-cve/update-cve-stats.py --resume-from frontend.backbone
```

## Rate Limit Handling

The scripts include automatic retry logic:
- **3 retries** with exponential backoff (10s, 20s, 30s)
- **Progress saving** every 5 findings
- **Resume capability** to continue from any point

If you hit rate limits repeatedly:
1. Check authentication: `vulnx healthcheck`
2. Increase delays: `RATE_LIMIT_DELAY=5.0 make update-cve-stats`
3. Wait 5-10 minutes and resume from last processed finding

## Files

**Main Scripts:**
- `update-cve-stats.py`: Updates CVE statistics for applicable findings (uses vulnx API)
- `populate-cwe-from-research.py`: Populates CWE/weakness data based on security research (no API required)

**Configuration Scripts:**
- `mark-cve-applicable.py`: Mark product findings with cve_applicable=true
- `mark-cve-inapplicable.py`: Mark non-product findings with cve_applicable=false
- `mark-cwe-applicable.py`: Mark product findings with cwe_applicable=true
- `mark-cwe-inapplicable.py`: Mark non-product findings with cwe_applicable=false
- `apply-cve-applicability-review.py`: Apply reviewed CVE applicability decisions
- `cleanup-inapplicable-cve-data.py`: Remove CVE data from findings with cve_applicable=false

**Testing Scripts:**
- `test-single-finding.py`: Test script for a single finding
- `test-cve-update.sh`: Shell script for testing the update process
- `test-security-preservation.py`: Verify security object preservation

**Documentation:**
- `README.md`: This file
- `CVE-APPLICABILITY-REVIEW.md`: Detailed review of CVE applicability for each category

## Troubleshooting

**Rate Limit Errors**
```
ERROR: Rate limit exceeded after 3 retries. Skipping.
```
Solutions:
- Authenticate: `vulnx auth --api-key YOUR_KEY`
- Increase delays: `RATE_LIMIT_DELAY=5.0 make update-cve-stats`
- Resume later: `python3 scripts/update-findings-cve/update-cve-stats.py --resume-from SLUG`

**vulnx not found**
```
Error: vulnx is not installed.
```
Solution: `go install github.com/projectdiscovery/cvemap/cmd/vulnx@latest`

**No CVEs found**
This is normal for findings without CVEs (e.g., auth methods, metadata). The script shows:
```
No CVEs found (checked: 2025-10-23T04:51:46Z)
```

**Progress Lost**
The script saves progress every 5 findings. If interrupted, your last checkpoint is saved in findings.json.

## Controlling Which Findings Get CVE and CWE Data

### The `cve_applicable` and `cwe_applicable` Flags

All findings are explicitly configured with security applicability flags:

**Product findings (59 total) - Both flags `true`**
```json
{
  "frontend.react": {
    "security": {
      "cve_applicable": true,
      "cwe_applicable": true,
      "cve": {
        "search_key": "react",
        "stats": { ... }
      },
      "weaknesses": {
        "stats": { ... }
      }
    }
  }
}
```

**Non-product findings (39 total) - Both flags `false`**
```json
{
  "auth.social.google": {
    "security": {
      "cve_applicable": false,
      "cwe_applicable": false
    }
  }
}
```

### Current Configuration (After Review)

**CVE Data WILL BE Queried (59 findings):**
- 24 Frontend Frameworks (React, Angular, Vue, Next.js, etc.)
- 8 Backend Frameworks (Django, Laravel, Express, etc.)
- 6 CMS Platforms (WordPress, Drupal, Joomla, etc.)
- 6 E-commerce Platforms (Magento, WooCommerce, etc.)
- 7 API Servers (FastAPI, Flask, NestJS, etc.)
- 5 API Specifications (OpenAPI, Swagger, etc.)
- 9 AI Services (Ollama, OpenAI, Vector DBs, etc.)
- 9 Gateways/Proxies (Nginx, Kong, Cloudflare, etc.)
- 2 Site Builders (Wix, Squarespace)

**CVE Data WILL BE SKIPPED (39 findings):**
- 18 Authentication methods (`auth.*`)
- 3 Metadata/server patterns (`page.*`, `server.*`)
- 18 Cloud services, specifications, and content types:
  - 2 Cloud e-commerce (Shopify, BigCommerce)
  - 2 Cloud site builders (Wix, Squarespace)
  - 5 API specifications (OpenAPI, Swagger, Postman, WADL, WSDL)
  - 2 Content type indicators (JSON API, XML API)
  - 3 Cloud AI services (OpenAI, Anthropic, Pinecone)
  - 3 Cloud gateways (Cloudflare, Akamai, Apigee)
  - 1 Domain pattern (api.domain_pattern)

### Managing Configuration

**Add new product findings (will query CVEs):**
```bash
# Update mark-cve-applicable.py and run:
python3 scripts/update-findings-cve/mark-cve-applicable.py
```

**Add new exclusions (skip CVEs):**
```bash
# Update mark-cve-inapplicable.py and run:
python3 scripts/update-findings-cve/mark-cve-inapplicable.py
```

**Manual configuration:**
```json
"security": {
  "cve_applicable": true   // or false
}
```

## Notes

- CVE stats use vulnx API and query real time vulnerability data
- CWE stats use researched common weakness patterns per technology category
- Scripts preserve all security object fields (cve_applicable, cwe_applicable, cve, weaknesses)
- CVE updates are incremental: progress saved every 5 findings
- CVE script can safely interrupt and resume with `--resume-from`
- CWE data is technology specific and based on OWASP research and real world CVE analysis

## Check Your Data

```bash
# View all CVE update timestamps
jq -r 'to_entries[] | select(.value.security != null) | "\(.key): \(.value.security.cve.updated)"' pkg/webexposure/findings/findings.json

# View KEV counts (CISA Known Exploited Vulnerabilities)
jq -r 'to_entries[] | select(.value.security.cve.stats.kev > 0) | "\(.key): \(.value.security.cve.stats.kev) KEV CVEs"' pkg/webexposure/findings/findings.json

# View CWE data
jq -r 'to_entries[] | select(.value.security.weaknesses != null) | "\(.key): \(.value.security.weaknesses.stats.total) unique CWEs"' pkg/webexposure/findings/findings.json
```

## Run Frequency

- Run periodically (weekly/monthly) to get latest CVE/CWE stats
- NOT part of regular build process (run manually when needed)
- CVE data changes slowly, no need to run on every build
- Check `updated` timestamp to see when data was last fetched
