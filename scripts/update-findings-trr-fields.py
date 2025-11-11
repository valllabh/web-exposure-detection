#!/usr/bin/env python3
"""
Update findings.json with TRR fields (technology_weight and weighted_severity_score)
This is a one-time data update script for the True Risk Range PoC
"""

import json
import math
from typing import Dict, Any

# Technology weight mapping based on classification and slug patterns
TECHNOLOGY_WEIGHTS = {
    # Backend/API frameworks (highest impact)
    'backend': 3.5,
    'api_framework': 3.5,
    'database': 3.0,
    'auth_system': 3.0,

    # Web servers and infrastructure
    'web_server': 2.5,
    'application_server': 2.5,

    # Frontend frameworks
    'frontend': 2.0,
    'js_library': 2.0,

    # CDN and managed services (lower direct impact)
    'cdn': 1.5,
    'gateway': 1.5,
    'managed_service': 1.5,

    # Default for other technologies
    'default': 2.0
}

# QDS estimates by severity level (Qualys-inspired)
QDS_ESTIMATES = {
    'critical': 85,
    'high': 70,
    'medium': 50,
    'low': 25
}

# Severity weights (Qualys-inspired)
SEVERITY_WEIGHTS = {
    'critical': 10.0,
    'high': 5.0,
    'medium': 2.0,
    'low': 0.5
}

def determine_technology_weight(slug: str, classification: list, labels: list) -> float:
    """Determine technology weight based on slug, classification, and labels"""

    slug_lower = slug.lower()

    # Check slug patterns
    if any(x in slug_lower for x in ['backend', 'express', 'django', 'spring', 'rails', 'fastapi']):
        return TECHNOLOGY_WEIGHTS['backend']

    if any(x in slug_lower for x in ['api', 'graphql', 'rest', 'grpc']):
        return TECHNOLOGY_WEIGHTS['api_framework']

    if any(x in slug_lower for x in ['database', 'postgres', 'mysql', 'mongodb', 'redis']):
        return TECHNOLOGY_WEIGHTS['database']

    if any(x in slug_lower for x in ['auth', 'saml', 'oauth', 'okta', 'sso']):
        return TECHNOLOGY_WEIGHTS['auth_system']

    if any(x in slug_lower for x in ['nginx', 'apache', 'iis', 'tomcat']):
        return TECHNOLOGY_WEIGHTS['web_server']

    if any(x in slug_lower for x in ['frontend', 'react', 'vue', 'angular', 'jquery', 'svelte']):
        return TECHNOLOGY_WEIGHTS['frontend']

    if any(x in slug_lower for x in ['cdn', 'cloudflare', 'akamai', 'fastly']):
        return TECHNOLOGY_WEIGHTS['cdn']

    if any(x in slug_lower for x in ['gateway', 'cloudfront', 'waf']):
        return TECHNOLOGY_WEIGHTS['gateway']

    # Check classifications
    if 'api' in classification:
        return TECHNOLOGY_WEIGHTS['api_framework']

    if 'webapp' in classification:
        return TECHNOLOGY_WEIGHTS['frontend']

    # Check labels
    label_str = ' '.join(labels).lower()
    if 'backend' in label_str or 'framework' in label_str:
        return TECHNOLOGY_WEIGHTS['backend']

    if 'database' in label_str:
        return TECHNOLOGY_WEIGHTS['database']

    if 'frontend' in label_str or 'js library' in label_str:
        return TECHNOLOGY_WEIGHTS['frontend']

    if 'cdn' in label_str or 'managed' in label_str:
        return TECHNOLOGY_WEIGHTS['cdn']

    # Default
    return TECHNOLOGY_WEIGHTS['default']

def calculate_weighted_severity_score(cve_stats: Dict[str, int]) -> float:
    """
    Calculate weighted severity score from CVE statistics

    Returns a 0-100 scale "threat index" for the technology

    Approach:
    1. Determine severity tier (70-100 for critical, 50-70 for high, etc.)
    2. Adjust by volume within tier (logarithmic scale)
    3. Add KEV bonus (known exploitation increases threat)
    4. Cap at 100
    """

    critical = cve_stats.get('critical', 0)
    high = cve_stats.get('high', 0)
    medium = cve_stats.get('medium', 0)
    low = cve_stats.get('low', 0)
    total = cve_stats.get('total', 0)
    kev = cve_stats.get('kev', 0)

    if total == 0:
        return 0.0

    # Step 1: Determine base severity tier
    if critical > 0:
        base_score = 70  # Critical tier
    elif high > 0:
        base_score = 50  # High tier
    elif medium > 0:
        base_score = 30  # Medium tier
    else:
        base_score = 10  # Low tier only

    # Step 2: Volume adjustment (logarithmic, within +0 to +20 range)
    # Few CVEs (1-10): +0 to +5
    # Moderate (11-50): +5 to +12
    # Many (51-100): +12 to +18
    # Extensive (100+): +18 to +20 (capped)
    if total <= 10:
        volume_bonus = min(total * 0.5, 5)
    elif total <= 50:
        volume_bonus = 5 + min((total - 10) * 0.175, 7)
    elif total <= 100:
        volume_bonus = 12 + min((total - 50) * 0.12, 6)
    else:
        # Logarithmic for very large counts
        volume_bonus = 18 + min(math.log10(total - 99) * 2, 2)

    # Step 3: KEV bonus (active exploitation is critical signal)
    # 0 KEV: +0
    # 1-2 KEV: +10
    # 3-5 KEV: +15
    # 6-10 KEV: +18
    # 10+ KEV: +20
    if kev == 0:
        kev_bonus = 0
    elif kev <= 2:
        kev_bonus = 10
    elif kev <= 5:
        kev_bonus = 15
    elif kev <= 10:
        kev_bonus = 18
    else:
        kev_bonus = 20

    # Step 4: Calculate final score (capped at 100)
    final_score = min(base_score + volume_bonus + kev_bonus, 100)

    return round(final_score, 2)

def update_findings_json(input_path: str, output_path: str = None):
    """Update findings.json with TRR fields"""

    if output_path is None:
        output_path = input_path

    print(f"Reading {input_path}...")
    with open(input_path, 'r') as f:
        findings = json.load(f)

    updated_count = 0

    print("\nProcessing findings...")
    for slug, item in findings.items():
        # Add technology_weight
        classification = item.get('classification', [])
        labels = item.get('labels', [])
        tech_weight = determine_technology_weight(slug, classification, labels)
        item['technology_weight'] = tech_weight

        # Calculate weighted_severity_score if CVE data exists
        security = item.get('security', {})
        if security:
            cve = security.get('cve', {})
            if cve:
                stats = cve.get('stats', {})
                if stats.get('total', 0) > 0:
                    weighted_score = calculate_weighted_severity_score(stats)
                    item['weighted_severity_score'] = weighted_score
                    updated_count += 1

                    print(f"  {slug}:")
                    print(f"    Technology Weight: {tech_weight}")
                    print(f"    CVEs: C:{stats.get('critical', 0)} H:{stats.get('high', 0)} M:{stats.get('medium', 0)} L:{stats.get('low', 0)} (KEV:{stats.get('kev', 0)})")
                    print(f"    Weighted Severity Score: {weighted_score}")
                else:
                    # No CVEs, set score to 0
                    item['weighted_severity_score'] = 0.0
            else:
                # No CVE data, set score to 0
                item['weighted_severity_score'] = 0.0
        else:
            # No security data, set score to 0
            item['weighted_severity_score'] = 0.0

    print(f"\nUpdated {updated_count} findings with weighted_severity_score")
    print(f"Total findings processed: {len(findings)}")

    # Write updated JSON
    print(f"\nWriting updated findings to {output_path}...")
    with open(output_path, 'w') as f:
        json.dump(findings, f, indent=2)

    print("Done!")

if __name__ == '__main__':
    import sys

    input_path = 'pkg/webexposure/findings/findings.json'
    output_path = None

    if len(sys.argv) > 1:
        input_path = sys.argv[1]
    if len(sys.argv) > 2:
        output_path = sys.argv[2]

    update_findings_json(input_path, output_path)
