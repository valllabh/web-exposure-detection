# Update Findings CVE Statistics

Scripts to update CVE statistics in findings.json using cvemap.

### update-cve-stats.py

Updates `pkg/webexposure/findings.json` with CVE statistics from cvemap.

**Prerequisites:**
- `cvemap` - Install from: https://github.com/projectdiscovery/cvemap
- `python3` - Built into macOS/Linux

**Usage:**
```bash
# Using make (recommended)
make update-cve-stats

# Or directly
python3 scripts/update-findings-cve/update-cve-stats.py
```

**What it does:**
1. Queries cvemap for CVE data for each technology in findings.json (loops through all findings)
2. Counts CVEs by severity (critical, high, medium, low)
3. Adds timestamp in ISO 8601 format (UTC) - ALWAYS, even if 0 CVEs found
4. Updates findings.json with security statistics

**Output format in findings.json:**
```json
{
  "backend.framework.express": {
    "slug": "backend.framework.express",
    "display_name": "Express.js",
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

**Notes:**
- Loops through ALL findings in findings.json
- Always adds security section with timestamp (even if 0 CVEs found - tracks last check)
- Skips metadata/status findings (page.*, server.*)
- Skips auth methods (features, not products)
- Normalizes product names for cvemap queries
- Includes 0.5s delay between queries to avoid rate limiting
- Timestamps in UTC using ISO 8601 format

**Run frequency:**
- Run periodically (weekly/monthly) to get latest CVE stats
- NOT part of regular build process (run manually when needed)
- CVE data changes slowly, no need to run on every build
- Check `updated` timestamp to see when CVE data was last fetched

**Check last update time:**
```bash
# View all CVE update timestamps
jq -r 'to_entries[] | select(.value.security != null) | "\(.key): \(.value.security.cve.updated)"' pkg/webexposure/findings.json
```

### test-cve-update.sh

Test script to verify CVE collection logic without modifying findings.json.

**Usage:**
```bash
./scripts/update-findings-cve/test-cve-update.sh
```

Tests CVE collection for wordpress, react, and express to verify the logic works correctly.
