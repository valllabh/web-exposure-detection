#!/usr/bin/env python3

"""
Update CWE statistics for findings.json using vulnx.
This script queries vulnx for CWE data and updates findings.json with weakness statistics.
Usage: python3 scripts/update-findings-cve/update-cwe-stats.py
"""

import json
import subprocess
import sys
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter

FINDINGS_FILE = Path("pkg/webexposure/findings/findings.json")


def check_dependencies():
    """Check if required tools are installed."""
    try:
        result = subprocess.run(["vulnx", "version"], capture_output=True, check=True, text=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: vulnx is not installed.")
        print("Install it with: go install github.com/projectdiscovery/cvemap/cmd/vulnx@latest")
        sys.exit(1)

    # Check for API authentication
    creds_file = os.path.expanduser("~/.pdcp/credentials.yaml")
    if not os.path.exists(creds_file):
        print("Warning: vulnx not authenticated. You may hit rate limits.")
        print("Get API key from: https://cloud.projectdiscovery.io/")
        print("Authenticate with: vulnx auth --api-key YOUR_KEY")
        print()


def should_query_finding(finding):
    """Check if a finding should be queried for CWEs based on security.cwe_applicable flag."""
    # Check security.cwe_applicable field (default is True if not specified)
    security = finding.get('security', {})
    cwe_applicable = security.get('cwe_applicable', True)

    # If explicitly set to False, skip
    if cwe_applicable is False:
        return False

    return True


def get_cwe_stats(search_key, slug):
    """Query vulnx for CWE statistics."""
    print(f"  Querying vulnx for CWE data: {search_key}...")

    try:
        # Get current timestamp in ISO 8601 format (UTC)
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Query vulnx with CWE field extraction
        # We'll fetch up to 50 results to get a good sample of CWE data
        result = subprocess.run(
            ["vulnx", "search", search_key, "--field", "cwe", "--limit", "50", "--silent"],
            capture_output=True,
            text=True,
            timeout=30,
            env=os.environ.copy()
        )

        # Check for rate limit error
        if "Rate limit exceeded" in result.stderr or "Rate limit exceeded" in result.stdout:
            print(f"    ERROR: Rate limit exceeded. API key required.")
            return None

        if not result.stdout.strip():
            print(f"    No CWE data found (checked: {timestamp})")
            return {
                "slug": slug,
                "stats": {
                    "total": 0,
                    "top_categories": []
                },
                "updated": timestamp
            }

        # Parse CWE data from output
        # The output format is typically one CWE per line, e.g., "CWE-79"
        cwe_list = []
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if line and line.startswith('CWE-'):
                cwe_list.append(line)

        if not cwe_list:
            print(f"    No CWE data found in output (checked: {timestamp})")
            return {
                "slug": slug,
                "stats": {
                    "total": 0,
                    "top_categories": []
                },
                "updated": timestamp
            }

        # Count CWE occurrences
        cwe_counter = Counter(cwe_list)
        total = sum(cwe_counter.values())

        # Get top 5 CWE categories
        top_cwes = cwe_counter.most_common(5)

        # Map CWE IDs to names (basic mapping, can be enhanced)
        cwe_names = get_cwe_names()

        top_categories = []
        for cwe_id, count in top_cwes:
            cwe_name = cwe_names.get(cwe_id, "Unknown Weakness")
            top_categories.append({
                "id": cwe_id,
                "name": cwe_name,
                "count": count
            })

        print(f"    Found {len(set(cwe_list))} unique CWEs across {total} CVEs")
        print(f"    Top CWE: {top_categories[0]['id']} - {top_categories[0]['name']} ({top_categories[0]['count']})")

        return {
            "slug": slug,
            "stats": {
                "total": len(set(cwe_list)),
                "top_categories": top_categories
            },
            "updated": timestamp
        }

    except subprocess.TimeoutExpired:
        print(f"    Warning: vulnx query timed out for {search_key}")
        return None
    except Exception as e:
        print(f"    Warning: Error querying vulnx for {search_key}: {e}")
        return None


def get_cwe_names():
    """
    Return a mapping of common CWE IDs to their names.
    This is a subset of the most common CWEs.
    """
    return {
        "CWE-79": "Cross-site Scripting (XSS)",
        "CWE-89": "SQL Injection",
        "CWE-22": "Path Traversal",
        "CWE-20": "Improper Input Validation",
        "CWE-78": "OS Command Injection",
        "CWE-94": "Code Injection",
        "CWE-119": "Buffer Overflow",
        "CWE-200": "Information Exposure",
        "CWE-284": "Improper Access Control",
        "CWE-287": "Improper Authentication",
        "CWE-295": "Certificate Validation",
        "CWE-306": "Missing Authentication",
        "CWE-312": "Cleartext Storage of Sensitive Information",
        "CWE-352": "Cross-Site Request Forgery (CSRF)",
        "CWE-362": "Race Condition",
        "CWE-416": "Use After Free",
        "CWE-434": "Unrestricted File Upload",
        "CWE-476": "NULL Pointer Dereference",
        "CWE-502": "Deserialization of Untrusted Data",
        "CWE-522": "Insufficiently Protected Credentials",
        "CWE-611": "XML External Entity (XXE)",
        "CWE-787": "Out-of-bounds Write",
        "CWE-798": "Hard-coded Credentials",
        "CWE-862": "Missing Authorization",
        "CWE-863": "Incorrect Authorization",
        "CWE-918": "Server-Side Request Forgery (SSRF)",
        "CWE-1021": "Improper Restriction of Rendered UI Layers",
    }


def main():
    print("Starting CWE statistics update with vulnx...")
    print()

    # Check dependencies
    check_dependencies()

    # Load findings
    if not FINDINGS_FILE.exists():
        print(f"Error: {FINDINGS_FILE} not found")
        sys.exit(1)

    with open(FINDINGS_FILE, 'r') as f:
        findings = json.load(f)

    total_findings = len(findings)
    print(f"Total findings in file: {total_findings}")
    print()

    # Process each finding
    results = []
    count = 0
    processed = 0
    skipped = 0

    print("Processing findings...")
    for slug, finding in findings.items():
        count += 1
        display_name = finding.get('display_name', slug)
        print(f"[{count}/{total_findings}] Processing: {slug} - {display_name}")

        # Check if we should query this finding based on cwe_applicable flag
        if not should_query_finding(finding):
            print("  Skipping (cwe_applicable=false)")
            skipped += 1
            continue

        # Get search_key from security.cve if present
        search_key = None
        if 'security' in finding and 'cve' in finding['security']:
            search_key = finding['security']['cve'].get('search_key')

        if not search_key:
            print("  Skipping (no search_key in security.cve)")
            skipped += 1
            continue

        # Get CWE stats
        stats = get_cwe_stats(search_key, slug)
        if stats:
            results.append(stats)
            processed += 1

        # Small delay to avoid rate limiting
        time.sleep(0.5)

    print()
    print(f"Processed: {processed} findings")
    print(f"Skipped: {skipped} findings")
    print()

    if not results:
        print("No products queried (all findings were skipped)")
        return

    # Update findings with CWE statistics
    print("Updating findings.json with CWE statistics...")
    for result in results:
        slug = result['slug']
        if slug in findings:
            # Initialize security section if not present
            if 'security' not in findings[slug]:
                findings[slug]['security'] = {}

            # Add weaknesses data
            findings[slug]['security']['weaknesses'] = {
                'stats': result['stats'],
                'updated': result['updated']
            }

    # Write updated findings back to file
    with open(FINDINGS_FILE, 'w') as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)
        f.write('\n')  # Add trailing newline

    print()
    print("✓ CWE statistics updated successfully!")
    print()
    print("Summary:")
    for slug, finding in findings.items():
        if 'security' in finding and 'weaknesses' in finding['security']:
            weaknesses = finding['security']['weaknesses']
            stats = weaknesses['stats']
            top_cwes = ", ".join([f"{c['id']}" for c in stats['top_categories'][:3]])
            print(f"{slug}: "
                  f"total_cwes={stats['total']}, "
                  f"top={top_cwes} "
                  f"(updated: {weaknesses['updated']})")


if __name__ == '__main__':
    main()
