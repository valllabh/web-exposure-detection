#!/usr/bin/env python3

"""
Mark findings with cwe_applicable=false where CWE data is NOT applicable.

This script explicitly sets cwe_applicable=false for findings where
cve_applicable=false, since CWE data comes from CVEs.

Usage: python3 scripts/update-findings-cve/mark-cwe-inapplicable.py
"""

import json
from pathlib import Path

FINDINGS_FILE = Path("pkg/webexposure/findings/findings.json")


def should_mark_inapplicable(slug, finding):
    """
    Returns True if CWE data is NOT applicable.

    CWE data is not applicable for:
    - Findings where cve_applicable=false (auth methods, metadata, cloud services, etc.)
    """
    security = finding.get('security', {})

    # If CVE data is not applicable, then CWE data is also not applicable
    cve_applicable = security.get('cve_applicable', True)
    if cve_applicable is False:
        return True

    return False


def get_category(slug):
    """Get human-readable category for the finding."""
    if slug.startswith('auth.'):
        return "Authentication"
    elif slug.startswith('page.'):
        return "Page Metadata"
    elif slug.startswith('server.'):
        return "Server Pattern"
    elif slug == 'api.domain_pattern':
        return "Domain Pattern"
    elif slug.startswith('backend.ecommerce.'):
        return "Cloud E-commerce"
    elif slug.startswith('backend.sitebuilder.'):
        return "Cloud Site Builder"
    elif slug.startswith('api.spec.'):
        return "API Specification"
    elif slug.startswith('api.ai.'):
        return "Cloud AI Service"
    elif slug.startswith('gateway.'):
        return "Cloud Gateway"
    else:
        return "Other"


def main():
    print("Marking findings with cwe_applicable=false...")
    print()

    # Load findings
    if not FINDINGS_FILE.exists():
        print(f"Error: {FINDINGS_FILE} not found")
        return 1

    with open(FINDINGS_FILE, 'r') as f:
        findings = json.load(f)

    total_findings = len(findings)
    marked_count = 0
    skipped_count = 0
    already_marked = 0

    print(f"Total findings: {total_findings}")
    print()

    # Track by category
    by_category = {}

    # Process each finding
    for slug, finding in findings.items():
        if should_mark_inapplicable(slug, finding):
            # Initialize security object if not present
            if 'security' not in finding:
                finding['security'] = {}

            # Check if already marked
            if finding['security'].get('cwe_applicable') is False:
                already_marked += 1
                continue

            finding['security']['cwe_applicable'] = False
            category = get_category(slug)
            print(f"✓ {slug} - Marked as false ({category})")
            marked_count += 1

            # Track by category
            by_category[category] = by_category.get(category, 0) + 1
        else:
            skipped_count += 1

    print()
    print("=" * 60)
    print(f"Newly marked: {marked_count}")
    print(f"Already marked: {already_marked}")
    print(f"Skipped (cve_applicable=true): {skipped_count}")
    print(f"Total marked as NOT applicable: {marked_count + already_marked}")
    print()

    if by_category:
        print("Breakdown by category:")
        for category in sorted(by_category.keys()):
            print(f"  {category}: {by_category[category]}")
        print()

    if marked_count > 0:
        # Write updated findings back to file
        with open(FINDINGS_FILE, 'w') as f:
            json.dump(findings, f, indent=2, ensure_ascii=False)
            f.write('\n')

        print(f"✓ Updated {FINDINGS_FILE}")
    else:
        print("No changes needed")

    return 0


if __name__ == '__main__':
    exit(main())
