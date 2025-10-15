# How to Write a Nuclei Template

This guide documents the working pattern for writing Nuclei templates for web exposure detection, including all 93 hierarchical detection keys.

---

## Critical DSL Variable Behavior

### Problem: Undefined Variables in DSL Expressions

When a regex extractor doesn't match anything, the variable is **NOT SET** in the DSL context. This causes downstream DSL expressions to fail.

**Example of the problem:**
```yaml
extractors:
  - type: regex
    name: blank_root
    internal: true
    regex:
      - "(?i)Apache2 Default Page"
    group: 0

  - type: dsl
    dsl:
      - 'len(blank_root) > 0 ? "true" : "false"'  # FAILS if blank_root doesn't match
```

**What happens:**
1. If regex doesn't match → `blank_root` variable doesn't exist
2. DSL tries to evaluate `len(blank_root)`
3. govaluate returns error: `"No parameter 'blank_root' found."`
4. Nuclei catches error (checks for "No parameter" prefix)
5. **Entire DSL extractor returns empty result**
6. Template produces no output

### Nuclei DSL Evaluation Flow

**File:** `/pkg/operators/extractors/extract.go`

```go
func (e *Extractor) ExtractDSL(data map[string]interface{}) map[string]struct{} {
    results := make(map[string]struct{})

    for _, compiledExpression := range e.dslCompiled {
        result, err := compiledExpression.Evaluate(data)
        // Ignore errors related to missing parameters
        if err != nil && !strings.HasPrefix(err.Error(), "No parameter") {
            return results
        }

        if result != nil {
            resultString := fmt.Sprint(result)
            if resultString != "" {
                results[resultString] = struct{}{}
            }
        }
    }
    return results
}
```

**Key points:**
- Errors with "No parameter" prefix are silently ignored
- DSL expression produces no output when variable is undefined
- Template execution continues (doesn't crash)

## Solutions That Don't Work

### ❌ Solution 1: Using `len()` on undefined variable
```yaml
- type: dsl
  dsl:
    - 'len(blank_root) > 0 ? "true" : "false"'
```
**Problem:** `len()` function receives undefined variable, govaluate fails before `len()` executes.

### ❌ Solution 2: Using `||` operator for null coalescing
```yaml
- type: dsl
  dsl:
    - 'len(blank_root || "") > 0 ? "true" : "false"'
```
**Problem:** `blank_root` lookup fails before `||` operator evaluates.

### ❌ Solution 3: Variable assignment in DSL
```yaml
- type: dsl
  dsl:
    - 'blank_root = blank_root || ""'
```
**Problem:** govaluate doesn't support assignment operators. Variables can only be set in `variables:` section.

### ❌ Solution 4: Regex with literal string fallback
```yaml
- type: regex
  name: blank_root
  regex:
    - "(?i)Apache2 Default Page"
    - "__NOT_BLANK__"  # Literal string that won't exist in HTML
  group: 0
```
**Problem:** Literal string never matches in real content, extractor still returns no value.

### ❌ Solution 5: Regex with catch-all pattern
```yaml
- type: regex
  name: blank_root
  regex:
    - "(?i)Apache2 Default Page"
    - "(?s)."  # Match any character
  group: 0
```
**Problem:** Catches everything, DSL can't distinguish between blank and non-blank pages.

### ❌ Solution 6: Chained DSL extractors
```yaml
- type: regex
  name: blank_root_match
  internal: true
  regex:
    - "(?i)Apache2 Default Page"
  group: 0

- type: dsl
  name: blank_root_status
  internal: true
  dsl:
    - 'len(blank_root_match) > 0 ? "true" : "false"'
```
**Problem:** Second DSL extractor fails when `blank_root_match` is undefined.

## Solution That Works

### ✅ Use DSL Extractor with Built-in Variables

DSL extractors can access built-in variables like `body` which **always exist** in the context.

```yaml
extractors:
  # Direct DSL check on body (always available)
  - type: dsl
    name: blank_root_status
    internal: true
    dsl:
      - 'contains(body, "Apache2 Default Page") || contains(body, "Welcome to nginx") ? "true" : "false"'

  # Use the guaranteed-to-exist variable
  - type: dsl
    dsl:
      - |
        "<result>" +
          "<is-blank-root>" +
            blank_root_status +
          "</is-blank-root>" +
        "</result>"
```

**Why this works:**
1. `body` variable is always present in DSL context (standard HTTP variable)
2. DSL extractors always produce output (unlike regex extractors)
3. `blank_root_status` is guaranteed to exist for subsequent extractors
4. No dependency on potentially undefined variables

## Built-in DSL Variables (Always Available)

When using DSL extractors, these variables are always present:

**HTTP Response Variables:**
- `body` - Response body content
- `headers` - Response headers
- `all_headers` - Combined body and headers
- `status_code` - HTTP status code
- `content_length` - Content-Length header
- `content_type` - Content-Type header
- `host` - Target host
- `ip` - Target IP address
- `cname` - Canonical name (if available)

## DSL Helper Functions

**String Functions:**
- `contains(str, substr)` - Check if string contains substring
- `len(str)` - Get string length (ONLY use with variables that exist!)
- `to_lower(str)` - Convert to lowercase
- `to_upper(str)` - Convert to uppercase
- `trim(str)` - Remove whitespace
- `regex(pattern, str)` - Match regex pattern

**Logical Operators:**
- `||` - Logical OR
- `&&` - Logical AND
- `!` - Logical NOT
- `? :` - Ternary conditional

**Comparison Operators:**
- `==`, `!=`, `>`, `<`, `>=`, `<=`
- `=~` - Regex match
- `!~` - Regex not match

## Extractor Execution Order

Extractors execute **sequentially** in the order they are defined. Later extractors can reference earlier extractors by name.

**Requirements:**
- Use `internal: true` to avoid printing values
- Give extractors a `name` to reference them
- Ensure referenced variables will exist (use DSL extractors for guaranteed output)

## Best Practices

### 1. Prefer DSL extractors for boolean/status checks
```yaml
# Good - DSL always returns a value
- type: dsl
  name: has_auth
  internal: true
  dsl:
    - 'contains(body, "login") ? "true" : "false"'
```

### 2. Use regex for capturing specific content
```yaml
# Good - Only for extracting actual content
- type: regex
  name: page_title
  internal: true
  regex:
    - "<title>([^<]+)</title>"
  group: 1
```

### 3. Always check variable existence when chaining
```yaml
# If you must reference a regex extractor in DSL:
- type: regex
  name: optional_value
  internal: true
  regex:
    - "some pattern"
  group: 1

# Use len() check with ternary
- type: dsl
  dsl:
    - '(len(optional_value) > 0 ? optional_value : "default")'
```

**But better:** Use DSL for the entire check to avoid the problem.

### 4. Group related patterns in DSL
```yaml
# Better than multiple regex extractors for boolean checks
- type: dsl
  name: has_blank_root
  internal: true
  dsl:
    - |
      contains(body, "Apache2 Default Page") ||
      contains(body, "Welcome to nginx") ||
      contains(body, "IIS Windows Server") ||
      regex("(?i)<body[^>]*>\\s*</body>", body) ? "true" : "false"
```

## Common Pitfalls

### Pitfall 1: Assuming undefined variables = empty string
**Wrong assumption:** `len(undefined_var)` returns 0
**Reality:** Error before `len()` executes

### Pitfall 2: Using extractors for existence checks
**Wrong approach:** Check if regex extractor matched by testing variable
**Right approach:** Use DSL with `contains()` or `regex()` on `body`

### Pitfall 3: Complex variable dependency chains
**Wrong:** Multiple extractors depending on each other
**Right:** Single DSL extractor doing all checks on built-in variables

## Template Structure for Reliable Output

```yaml
headless:
  - steps:
      - action: navigate
        args:
          url: "{{BaseURL}}"
      - action: waitload

    extractors:
      # Extract actual content (may or may not match)
      - type: regex
        name: page_title
        internal: true
        part: body
        regex:
          - "<title>([^<]+)</title>"
        group: 1

      # Boolean checks using DSL (always return values)
      - type: dsl
        name: has_auth
        internal: true
        dsl:
          - 'contains(body, "login") ? "true" : "false"'

      - type: dsl
        name: is_blank
        internal: true
        dsl:
          - 'contains(body, "Apache2 Default Page") ? "true" : "false"'

      # Final output - all dependencies guaranteed to exist
      - type: dsl
        dsl:
          - |
            "<result>" +
              "<title>" + (len(page_title) > 0 ? page_title : "") + "</title>" +
              "<has-auth>" + has_auth + "</has-auth>" +
              "<is-blank>" + is_blank + "</is-blank>" +
            "</result>"
```

## Debugging Tips

### 1. Test with verbose mode
```bash
nuclei -t template.yaml -u https://example.com -v
```

### 2. Check for "No parameter" warnings
Look for warnings like:
```
[WRN] No parameter 'variable_name' found
```

### 3. Test extractors independently
Create minimal templates to test each extractor in isolation.

### 4. Use simple DSL expressions first
Start with basic checks before building complex logic.

## References

- Nuclei v3 GitHub: https://github.com/projectdiscovery/nuclei
- DSL Library: https://github.com/projectdiscovery/dsl
- DSL Helper Functions: https://docs.projectdiscovery.io/templates/reference/helper-functions
- govaluate: https://github.com/Knetic/govaluate
- Nuclei DSL evaluation: `/pkg/operators/extractors/extract.go`
- Variable context building: `/pkg/protocols/http/operators.go`

## Hierarchical Key Structure

### Key Naming Pattern

All findings use hierarchical dot-separated keys with underscores for multi-word items.

**Pattern:** `category.subcategory.item`

**Naming Rules:**
- Use underscores for multi-word items: `mcp_server`, `vector_db`, `json_xml`
- Keep categories singular: `frontend` not `frontends`
- Maximum 4 levels: `api.ai.vector_db.pinecone`
- Template keys match findings.json exactly

**Examples:**
- `frontend.react`, `frontend.angular`, `frontend.nextjs`
- `backend.cms.wordpress`, `backend.framework.django`
- `api.domain_pattern`, `api.spec.openapi`, `api.spec.swagger`, `api.spec.postman`
- `api.server.fastapi`, `api.server.flask`, `api.server.json_xml`
- `api.ai.openai_endpoint`, `api.ai.mcp_server`, `api.ai.ollama_server`
- `api.ai.vector_db.pinecone`, `api.ai.vector_db.weaviate`
- `auth.social.google`, `auth.enterprise.okta`, `auth.traditional.basic_auth`
- `gateway.nginx`, `gateway.kong`, `gateway.cloudflare`

### Implementation

```yaml
extractors:
  - type: regex
    name: nginx
    part: header
    internal: true
    regex:
      - "(?i)(nginx)"
    group: 1

  - type: dsl
    dsl:
      - 'len(nginx) > 0 ? to_value_group("gateway.nginx", nginx) : ""'
```

### Complete Key Reference

**94 total detection keys organized by category:**

**Frontend (24):** react, angular, vuejs, svelte, ember, preact, solidjs, backbone, alpine, lit, marko, mithril, inferno, hyperapp, dojo, knockout, meteor, nextjs, nuxtjs, gatsby, remix, astro, qwik, fresh

**Backend CMS (6):** wordpress, drupal, joomla, typo3, ghost, kentico

**Backend E-commerce (6):** shopify, magento, woocommerce, prestashop, bigcommerce, opencart

**Backend Site Builders (2):** wix, squarespace

**Backend Frameworks (8):** laravel, django, aspnet, rails, express, jsp, php, spring

**Auth Traditional (3):** basic_auth, registration, password_recovery

**Auth Enterprise (7):** saml_sso, microsoft, okta, auth0, onelogin, keycloak, adfs

**Auth Social (6):** google, facebook, twitter, linkedin, github, apple

**Auth Other (2):** mfa, passwordless

**API Domain & Specs (6):** domain_pattern, spec.openapi, spec.swagger, spec.postman, spec.wadl, spec.wsdl

**API Servers (6):** server.json_xml, server.fastapi, server.flask, server.gin, server.koa, server.nestjs

**API AI (4):** ai.mcp_server, ai.openai_endpoint, ai.ollama_server, ai.anthropic_endpoint

**API Vector DBs (5):** ai.vector_db.pinecone, ai.vector_db.weaviate, ai.vector_db.qdrant, ai.vector_db.milvus, ai.vector_db.chroma

**Gateway (9):** nginx, kong, envoy, traefik, cloudflare, akamai, haproxy, zuul, apigee

**Metadata/Status (3):** page.page_title, page.page_description, server.blank_root_status

### Example Output

```json
{
  "host": "example.com",
  "template-id": "frontend-tech-detection",
  "findings": {
    "page.page_title": ["Example Site"],
    "frontend.react": ["data-reactroot"],
    "gateway.nginx": ["nginx"],
    "auth.social.google": ["Sign in with Google"],
    "auth.enterprise.okta": ["Sign in with Okta"],
    "backend.cms.wordpress": ["wp-content"],
    "api.domain_pattern": ["api"],
    "api.spec.openapi": ["https://example.com/openapi.json"],
    "api.spec.postman": ["https://example.com/postman.json"],
    "api.server.fastapi": ["uvicorn"],
    "api.ai.openai_endpoint": ["api.example.com/v1/models"],
    "api.ai.vector_db.pinecone": ["vectors.pinecone.io/describe_index_stats"]
  }
}
```

## Nuclei Template Structure - Working Pattern

Based on working templates, use this structure:

### Template Structure

```yaml
id: template-id
info:
  name: Template Name
  author: Author Name
  severity: info
  description: Brief description
  tags: tag1,tag2,tag3

http:  # or headless for browser-based detection
  - method: GET
    path:
      - "{{BaseURL}}"
    redirects: true
    max-redirects: 10
    extractors:
      # Internal regex extractors (capture content)
      - type: regex
        name: variable_name
        part: body  # or header, host, etc.
        group: 1
        internal: true
        regex:
          - "(?i)pattern_to_match"

      # DSL extractors (conditional output with hierarchical keys)
      - type: dsl
        dsl:
          - 'len(variable_name) > 0 ? to_value_group("category.subcategory.item", variable_name) : ""'
```

### Key Points

1. **No matchers needed** - DSL handles conditional logic
2. **Hierarchical keys** - Use dot notation: `category.subcategory.item`
3. **Underscores in keys** - Multi-word items: `mcp_server`, `vector_db`
4. **Internal extractors** - Mark regex as `internal: true` to avoid output
5. **DSL checks length** - Only call `to_value_group()` when data exists

### Real Example

```yaml
id: ai-detection
info:
  name: AI Services Detection
  author: valllabh
  severity: info
  description: Detects AI endpoints
  tags: exposure,api,ai

http:
  - method: GET
    path:
      - "{{BaseURL}}/v1/models"
    extractors:
      - type: regex
        name: openai_response
        part: body
        group: 0
        internal: true
        regex:
          - '(?i)"object"\s*:\s*"(list|model)"'

      - type: dsl
        dsl:
          - 'len(openai_response) > 0 ? to_value_group("api.ai.openai_endpoint", host + path) : ""'
```

### Minimal Info Section

```yaml
info:
  name: Template Name
  author: Author Name
  severity: info
  description: What this detects
  tags: tag1,tag2,tag3
```

Avoid adding `reference`, `classification`, `metadata` unless required.

## Managing Detections

### Adding New Detections

When adding new detections:

1. **Update scan template** with hierarchical key:
   ```yaml
   - type: dsl
     dsl:
       - 'len(variable) > 0 ? to_value_group("category.subcategory.item_name", variable) : ""'
   ```

2. **Add to findings.json** with same hierarchical key:
   ```json
   {
     "category.subcategory.item_name": {
       "slug": "category.subcategory.item_name",
       "display_name": "Display Name",
       "icon": "icon-name.svg",
       "show_in_tech": true,
       "classification": ["webapp"],
       "description": "Clear description of what this technology/finding is",
       "labels": ["Category", "Technology Type", "Additional Label"]
     }
   }
   ```

   **Field Descriptions:**
   - `slug`: Same as key, hierarchical identifier
   - `display_name`: Human-readable name shown in reports
   - `icon`: SVG filename in `templates/assets/`
   - `show_in_tech`: `true` to display in technology section, `false` to hide
   - `classification`: Array of classifications (`["webapp"]`, `["api"]`, `["api-spec"]`, `["ai"]`, `["~webapp", "~api"]` for gateways)
   - `description`: Clear, concise explanation of the technology/finding (1-2 sentences)
   - `labels`: Array of category labels (e.g., `["Frontend Framework", "JS Library"]`, `["CMS", "PHP"]`, `["API Gateway", "Microservices"]`)
   - `security`: Optional field with CVE statistics (auto-generated by `scripts/update-cve-stats.sh`)

   **Label Examples:**
   - Frontend: `["Frontend Framework", "JS Library"]`, `["Static Site Generator"]`
   - Backend: `["Backend Framework", "Python"]`, `["CMS", "PHP"]`
   - E-commerce: `["E-commerce Platform", "SaaS"]`
   - Auth: `["Social Authentication", "OAuth"]`, `["Enterprise Authentication", "SSO"]`
   - API: `["API Specification", "REST"]`, `["API Server", "Node.js"]`
   - AI: `["AI", "LLM", "OpenAI"]`, `["AI", "Vector Database"]`
   - Gateway: `["API Gateway", "Microservices"]`, `["CDN", "Security"]`

3. **Create SVG icon** in `templates/assets/icon-name.svg`

4. **Update report.go** if needed (e.g., add to `isTechnologyTemplate()` map for new template files)

5. **Update key reference** in this document above

6. **Update CVE statistics** (optional): Run `make update-cve-stats` to fetch CVE data for the new finding

### Removing Detections

When removing detections:

1. **Remove from scan template** - Delete regex extractor and DSL extractor

2. **Remove from findings.json** - Delete entire JSON entry (including all fields: slug, display_name, icon, show_in_tech, classification, description, labels)

3. **Remove SVG icon** - Delete `templates/assets/icon-name.svg`

4. **Update key counts** in this document (total keys, category counts)

## CVE Statistics

### Updating CVE Data

CVE statistics are automatically collected from cvemap and added to findings.json.

**To update CVE statistics:**
```bash
# Using make (recommended)
make update-cve-stats

# Or directly
./scripts/update-findings-cve/update-cve-stats.sh
```

**Prerequisites:**
- Install cvemap: https://github.com/projectdiscovery/cvemap
- Install jq: `brew install jq`

**Output format:**
```json
{
  "backend.framework.express": {
    ...existing fields...,
    "security": {
      "cve": {
        "stats": {
          "critical": 0,
          "high": 0,
          "medium": 4,
          "low": 0,
          "total": 4
        },
        "updated": "2025-06-21T10:30:45Z"
      }
    }
  }
}
```

**When to run:**
- After adding new findings
- Periodically (weekly/monthly) for latest CVE data
- NOT part of regular build process (manual only)
- Check `updated` timestamp to see when data was last fetched

**Check last update time:**
```bash
jq -r 'to_entries[] | select(.value.security != null) | "\(.key): \(.value.security.cve.updated)"' pkg/webexposure/findings.json
```

**What gets CVE data:**
- Frontend frameworks (React, Vue, Angular, etc.)
- Backend frameworks (Django, Laravel, Rails, etc.)
- CMS platforms (WordPress, Drupal, etc.)
- API servers (FastAPI, Flask, Express, etc.)
- Infrastructure (Nginx, Kong, etc.)
- **Note:** Timestamp is ALWAYS added, even if 0 CVEs found (tracks last check time)

**What is skipped:**
- Metadata findings (page.*, server.*)
- Auth methods (auth.traditional.*, auth.mfa, auth.passwordless)
- Domain patterns (api.domain_pattern)

## Summary - Key Rules

1. **Variable Safety:** If a variable might not exist, don't reference it directly in DSL. Use DSL extractors on built-in variables (`body`, `headers`, etc.) that are guaranteed to exist.

2. **Hierarchical Keys:** Always use dot-separated keys in `to_value_group()` like `category.subcategory.item`. Multi-word items use underscores: `mcp_server`, `vector_db`.

3. **Template Pattern:** Use only `extractors` with internal regex + DSL. No `matchers` sections needed. DSL handles conditional output via `len()` checks.

4. **Key Consistency:** Template keys match findings.json exactly. Code calls `NewFindingItem("frontend.react")` and finds it in findings.json.
