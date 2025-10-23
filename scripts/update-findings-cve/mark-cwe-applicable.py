#!/usr/bin/env python3

"""
Mark product findings with cwe_applicable=true where CWE data IS applicable.

This script explicitly sets cwe_applicable=true for all findings that have
cve_applicable=true, since CWE data is derived from CVEs.

Usage: python3 scripts/update-findings-cve/mark-cwe-applicable.py
"""

import json
from pathlib import Path

FINDINGS_FILE = Path("pkg/webexposure/findings/findings.json")


def should_mark_applicable(slug, finding):
    """
    Determine if a finding should be marked with cwe_applicable=true.

    Returns True if CWE data IS applicable (should mark as true).
    CWE data is applicable for all findings where cve_applicable=true.
    """
    security = finding.get('security', {})

    # If already explicitly marked as false, don't change
    if security.get('cwe_applicable') is False:
        return False

    # CWE data is applicable if CVE data is applicable
    cve_applicable = security.get('cve_applicable', True)
    return cve_applicable is True


def get_category(slug):
    """Get human-readable category for the finding."""
    if slug.startswith('frontend.'):
        return "Frontend Framework"
    elif slug.startswith('backend.cms.'):
        return "CMS Platform"
    elif slug.startswith('backend.ecommerce.'):
        return "E-commerce Platform"
    elif slug.startswith('backend.sitebuilder.'):
        return "Site Builder"
    elif slug.startswith('backend.framework.'):
        return "Backend Framework"
    elif slug.startswith('api.server.'):
        return "API Server"
    elif slug.startswith('api.spec.'):
        return "API Specification"
    elif slug.startswith('api.ai.'):
        return "AI Service"
    elif slug.startswith('gateway.'):
        return "Gateway/Proxy"
    else:
        return "Other Product"


def main():
    print("Marking product findings with cwe_applicable=true...")
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
        if should_mark_applicable(slug, finding):
            # Initialize security object if not present
            if 'security' not in finding:
                finding['security'] = {}

            # Check if already marked
            if finding['security'].get('cwe_applicable') is True:
                already_marked += 1
                continue

            finding['security']['cwe_applicable'] = True
            category = get_category(slug)
            print(f"✓ {slug} - Marked as true ({category})")
            marked_count += 1

            # Track by category
            by_category[category] = by_category.get(category, 0) + 1
        else:
            skipped_count += 1

    print()
    print("=" * 60)
    print(f"Newly marked: {marked_count}")
    print(f"Already marked: {already_marked}")
    print(f"Skipped (cve_applicable=false or cwe_applicable=false): {skipped_count}")
    print(f"Total marked as applicable: {marked_count + already_marked}")
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
