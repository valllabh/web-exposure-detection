#!/usr/bin/env python3

"""
Populate CWE statistics in findings.json based on security research.

This script uses researched common weakness data for each technology category
to populate the CWE/weaknesses field in findings.json.

Usage: python3 scripts/update-findings-cve/populate-cwe-from-research.py
"""

import json
from datetime import datetime, timezone
from pathlib import Path

FINDINGS_FILE = Path("pkg/webexposure/findings/findings.json")

# CWE data by category based on security research
CWE_DATA = {
    "frontend": {
        "top_cwes": [
            {"id": "CWE-79", "name": "Cross-Site Scripting (XSS)", "count": 5},
            {"id": "CWE-1104", "name": "Use of Unmaintained Third Party Components", "count": 5},
            {"id": "CWE-829", "name": "Inclusion of Functionality from Untrusted Control Sphere", "count": 4},
            {"id": "CWE-20", "name": "Improper Input Validation", "count": 4},
            {"id": "CWE-601", "name": "URL Redirection to Untrusted Site", "count": 3},
        ]
    },
    "backend_framework": {
        "top_cwes": [
            {"id": "CWE-89", "name": "SQL Injection", "count": 4},
            {"id": "CWE-287", "name": "Improper Authentication", "count": 4},
            {"id": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)", "count": 3},
            {"id": "CWE-502", "name": "Deserialization of Untrusted Data", "count": 3},
            {"id": "CWE-1333", "name": "Inefficient Regular Expression Complexity", "count": 3},
        ]
    },
    "cms": {
        "top_cwes": [
            {"id": "CWE-79", "name": "Cross-Site Scripting (XSS)", "count": 5},
            {"id": "CWE-94", "name": "Code Injection", "count": 5},
            {"id": "CWE-89", "name": "SQL Injection", "count": 4},
            {"id": "CWE-434", "name": "Unrestricted Upload of File with Dangerous Type", "count": 4},
            {"id": "CWE-284", "name": "Improper Access Control", "count": 4},
        ]
    },
    "ecommerce": {
        "top_cwes": [
            {"id": "CWE-79", "name": "Cross-Site Scripting (XSS)", "count": 5},
            {"id": "CWE-89", "name": "SQL Injection", "count": 4},
            {"id": "CWE-285", "name": "Improper Authorization", "count": 4},
            {"id": "CWE-20", "name": "Improper Input Validation", "count": 4},
            {"id": "CWE-22", "name": "Path Traversal", "count": 3},
        ]
    },
    "api_server": {
        "top_cwes": [
            {"id": "CWE-285", "name": "Improper Authorization", "count": 5},
            {"id": "CWE-287", "name": "Improper Authentication", "count": 5},
            {"id": "CWE-918", "name": "Server-Side Request Forgery (SSRF)", "count": 4},
            {"id": "CWE-20", "name": "Improper Input Validation", "count": 4},
            {"id": "CWE-770", "name": "Allocation of Resources Without Limits", "count": 4},
        ]
    },
    "ai_service": {
        "top_cwes": [
            {"id": "CWE-77", "name": "Prompt Injection", "count": 5},
            {"id": "CWE-200", "name": "Exposure of Sensitive Information", "count": 5},
            {"id": "CWE-306", "name": "Missing Authentication for Critical Function", "count": 5},
            {"id": "CWE-502", "name": "Deserialization of Untrusted Data", "count": 4},
            {"id": "CWE-94", "name": "Code Injection", "count": 4},
        ]
    },
    "gateway": {
        "top_cwes": [
            {"id": "CWE-16", "name": "Configuration", "count": 5},
            {"id": "CWE-200", "name": "Exposure of Sensitive Information", "count": 4},
            {"id": "CWE-20", "name": "Improper Input Validation", "count": 4},
            {"id": "CWE-693", "name": "Protection Mechanism Failure", "count": 4},
            {"id": "CWE-522", "name": "Insufficiently Protected Credentials", "count": 3},
        ]
    },
}


def get_category_for_finding(slug):
    """Determine the CWE category for a finding based on its slug."""
    if slug.startswith('frontend.'):
        return "frontend"
    elif slug.startswith('backend.cms.'):
        return "cms"
    elif slug.startswith('backend.ecommerce.'):
        return "ecommerce"
    elif slug.startswith('backend.framework.') or slug.startswith('backend.sitebuilder.'):
        return "backend_framework"
    elif slug.startswith('api.server.'):
        return "api_server"
    elif slug.startswith('api.ai.'):
        return "ai_service"
    elif slug.startswith('gateway.'):
        return "gateway"
    else:
        return None


def should_update_finding(finding):
    """Check if a finding should have CWE data populated."""
    security = finding.get('security', {})
    cwe_applicable = security.get('cwe_applicable', True)

    # Only update if cwe_applicable is True
    return cwe_applicable is True


def main():
    print("Populating CWE data from security research...")
    print()

    # Load findings
    if not FINDINGS_FILE.exists():
        print(f"Error: {FINDINGS_FILE} not found")
        return 1

    with open(FINDINGS_FILE, 'r') as f:
        findings = json.load(f)

    total_findings = len(findings)
    updated_count = 0
    skipped_count = 0
    no_category_count = 0

    print(f"Total findings: {total_findings}")
    print()

    # Track by category
    by_category = {}

    # Get current timestamp
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Process each finding
    print("Processing findings...")
    for slug, finding in findings.items():
        # Check if we should update this finding
        if not should_update_finding(finding):
            print(f"[{updated_count + skipped_count + no_category_count + 1}/{total_findings}] Skipping: {slug} (cwe_applicable=false)")
            skipped_count += 1
            continue

        # Get category for this finding
        category = get_category_for_finding(slug)
        if not category:
            print(f"[{updated_count + skipped_count + no_category_count + 1}/{total_findings}] Skipping: {slug} (no category mapping)")
            no_category_count += 1
            continue

        # Get CWE data for this category
        cwe_data = CWE_DATA.get(category)
        if not cwe_data:
            print(f"[{updated_count + skipped_count + no_category_count + 1}/{total_findings}] Skipping: {slug} (no CWE data for category)")
            no_category_count += 1
            continue

        # Initialize security object if needed
        if 'security' not in finding:
            finding['security'] = {}

        # Populate weaknesses data
        total_unique_cwes = len(cwe_data['top_cwes'])
        finding['security']['weaknesses'] = {
            'stats': {
                'total': total_unique_cwes,
                'top_categories': cwe_data['top_cwes']
            },
            'updated': timestamp
        }

        display_name = finding.get('display_name', slug)
        print(f"[{updated_count + skipped_count + no_category_count + 1}/{total_findings}] Updated: {slug} - {display_name} ({category})")
        print(f"  CWEs: {', '.join([c['id'] for c in cwe_data['top_cwes'][:3]])}")

        updated_count += 1
        by_category[category] = by_category.get(category, 0) + 1

    print()
    print("=" * 70)
    print(f"Updated: {updated_count} findings")
    print(f"Skipped (cwe_applicable=false): {skipped_count}")
    print(f"Skipped (no category): {no_category_count}")
    print()

    if by_category:
        print("Breakdown by category:")
        for category in sorted(by_category.keys()):
            print(f"  {category}: {by_category[category]}")
        print()

    if updated_count > 0:
        # Write updated findings back to file
        with open(FINDINGS_FILE, 'w') as f:
            json.dump(findings, f, indent=2, ensure_ascii=False)
            f.write('\n')

        print(f"✓ Updated {FINDINGS_FILE}")
        print()

        # Show sample
        print("Sample CWE data:")
        sample_slug = None
        for slug, finding in findings.items():
            if 'security' in finding and 'weaknesses' in finding['security']:
                sample_slug = slug
                break

        if sample_slug:
            sample = findings[sample_slug]
            print(f"\n{sample_slug}:")
            weaknesses = sample['security']['weaknesses']
            print(f"  Total unique CWEs: {weaknesses['stats']['total']}")
            print(f"  Top weaknesses:")
            for cwe in weaknesses['stats']['top_categories'][:3]:
                print(f"    - {cwe['id']}: {cwe['name']} (prevalence: {cwe['count']})")
            print(f"  Updated: {weaknesses['updated']}")
    else:
        print("No findings updated")

    return 0


if __name__ == '__main__':
    exit(main())
