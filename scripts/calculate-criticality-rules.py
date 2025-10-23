#!/usr/bin/env python3
"""
Rule-based criticality scoring using domain patterns and HTTP response data.
Based on: docs/research/using-http-response-for-criticality.md
"""

import json
import re
import sys
from typing import Dict, List, Tuple

# Domain patterns (30% weight)
CRITICAL_DOMAIN_PATTERNS = {
    'pay.': 1.5, 'payment.': 1.5, 'checkout.': 1.5,
    'auth.': 1.2, 'sso.': 1.2,
    'portal.': 0.7, 'portal-': 0.7,
    'admin.': 0.8, 'console.': 0.8,
    'api.': 0.5, '-api.': 0.5, 'api-': 0.5,
    'www.': 0.5,
}

DEV_PATTERNS = {
    'dev.': -0.7, 'dev-': -0.7, '.dev.': -0.7,
    'test.': -0.7, 'test-': -0.7, '.test.': -0.7,
    'staging.': -0.6, 'staging-': -0.6,
    'sandbox.': -0.7, 'demo.': -0.6,
    'uat.': -0.6, 'qa.': -0.6,
}

# Title keywords (25% weight)
TITLE_KEYWORDS = {
    'portal': 0.6, 'login': 0.5, 'admin': 0.7,
    'dashboard': 0.5, 'console': 0.6,
    'enterprise': 0.4, 'platform': 0.4,
    'payment': 0.8, 'checkout': 0.8,
    'api': 0.3,
}

TITLE_NEGATIVE = {
    '404': -0.5, 'not found': -0.5,
    '403': -0.5, 'forbidden': -0.5,
    'error': -0.4,
    'test': -0.7, 'development': -0.8,
    'staging': -0.6, 'demo': -0.5,
}

# Findings scoring (20% weight)
FINDINGS_WEIGHTS = {
    'auth.enterprise.saml_sso': 0.6,
    'auth.mfa': 0.5,
    'auth.traditional.basic_auth': 0.2,
    'auth.traditional.registration': 0.4,
    'auth.traditional.password_recovery': 0.3,
    'backend.cms.wordpress': 0.3,
    'backend.cms.drupal': 0.3,
    'api.domain_pattern': 0.4,
    'gateway.cloudflare': 0.2,
    'gateway.nginx': 0.0,
}

def score_domain_pattern(domain: str) -> Tuple[float, List[str]]:
    """Score domain name patterns"""
    factors = []
    score = 0.0

    domain_lower = domain.lower()

    # Check dev/test patterns first (override)
    for pattern, weight in DEV_PATTERNS.items():
        if pattern in domain_lower:
            score = weight
            factors.append(f"Dev/test pattern '{pattern}': {weight:+.1f}")
            return score, factors

    # Check critical patterns
    for pattern, weight in CRITICAL_DOMAIN_PATTERNS.items():
        if pattern in domain_lower:
            score += weight
            factors.append(f"Domain pattern '{pattern}': {weight:+.1f}")

    return score, factors

def score_title(title: str) -> Tuple[float, List[str]]:
    """Score page title keywords"""
    if not title:
        return 0.0, []

    factors = []
    score = 0.0

    title_lower = title.lower()

    # Check negative patterns first
    for keyword, weight in TITLE_NEGATIVE.items():
        if keyword in title_lower:
            score += weight
            factors.append(f"Title '{keyword}': {weight:+.1f}")

    # Check positive keywords
    for keyword, weight in TITLE_KEYWORDS.items():
        if keyword in title_lower:
            score += weight
            factors.append(f"Title '{keyword}': {weight:+.1f}")

    return score, factors

def score_findings(findings: List[str]) -> Tuple[float, List[str]]:
    """Score Nuclei findings"""
    if not findings:
        return 0.0, []

    factors = []
    score = 0.0
    auth_count = 0

    for finding in findings:
        if finding in FINDINGS_WEIGHTS:
            weight = FINDINGS_WEIGHTS[finding]
            if weight > 0:
                score += weight
                # Shorten finding name for display
                short_name = finding.split('.')[-1]
                factors.append(f"Finding '{short_name}': {weight:+.1f}")

                if finding.startswith('auth.'):
                    auth_count += 1

    # Multiple auth types bonus
    if auth_count >= 3:
        bonus = 0.3
        score += bonus
        factors.append(f"Multiple auth ({auth_count} types): {bonus:+.1f}")

    return score, factors

def is_error_page(title: str, html: str = "") -> bool:
    """Check if this is an error page"""
    if not title:
        return False

    title_lower = title.lower()
    error_indicators = [
        ('404', 'not found'),
        ('403', 'forbidden'),
        ('500', 'internal server error'),
        ('503', 'service unavailable'),
    ]

    for code, text in error_indicators:
        if code in title_lower or text in title_lower:
            return True

    return False

def extract_title_from_html(html: str) -> str:
    """Extract title from HTML response"""
    if not html:
        return ""

    match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE)
    return match.group(1).strip() if match else ""

def has_login_form(html: str) -> bool:
    """Check for login/password forms in HTML"""
    if not html:
        return False

    # Password input fields
    if re.search(r'<input[^>]+type=["\']password["\']', html, re.IGNORECASE):
        return True

    # Login forms
    if re.search(r'<form[^>]*?(login|signin|sign-in|authenticate)', html, re.IGNORECASE):
        return True

    return False

def has_payment_keywords(html: str) -> bool:
    """Check for payment/commerce keywords"""
    if not html:
        return False

    html_lower = html.lower()
    payment_keywords = [
        'checkout', 'payment', 'pay now', 'billing',
        'credit card', 'cvv', 'card number',
    ]

    return any(keyword in html_lower for keyword in payment_keywords)

def calculate_criticality(domain: str, title: str, findings: List[str], html: str = "") -> Dict:
    """
    Calculate criticality score using rule-based approach

    Approach: Start with base 1.0 and add raw component scores directly
    """
    base_score = 1.0
    all_factors = []

    # 1. Domain Pattern
    domain_score, domain_factors = score_domain_pattern(domain)
    all_factors.extend(domain_factors)

    # 2. Title
    title_score, title_factors = score_title(title)
    all_factors.extend(title_factors)

    # 3. HTTP Content
    http_score = 0.0
    if html:
        if is_error_page(title, html):
            http_score = -0.8
            all_factors.append("Error page: -0.8")
        elif has_payment_keywords(html):
            http_score = 1.0
            all_factors.append("Payment keywords: +1.0")
        elif has_login_form(html):
            http_score = 0.5
            all_factors.append("Login form: +0.5")

    # 4. Nuclei Findings
    findings_score, findings_factors = score_findings(findings)
    all_factors.extend(findings_factors)

    # 5. Tech Stack - not implemented yet
    tech_score = 0.0

    # Calculate final score (direct addition, no percentage weighting)
    total_score = base_score + domain_score + title_score + http_score + findings_score + tech_score
    final_score = max(0.1, min(5.0, round(total_score, 2)))

    # Determine category
    if final_score >= 3.5:
        category = "CRITICAL"
    elif final_score >= 2.0:
        category = "HIGH"
    elif final_score >= 1.0:
        category = "MEDIUM"
    else:
        category = "LOW"

    return {
        'domain': domain,
        'score': final_score,
        'category': category,
        'factors': all_factors,
        'breakdown': {
            'base': base_score,
            'domain': round(domain_score, 2),
            'title': round(title_score, 2),
            'http': round(http_score, 2),
            'findings': round(findings_score, 2),
            'tech': round(tech_score, 2),
        }
    }

def main():
    if len(sys.argv) < 2:
        print("Usage: ./calculate-criticality-rules.py <test-data.json>")
        sys.exit(1)

    test_file = sys.argv[1]

    with open(test_file, 'r') as f:
        test_data = json.load(f)

    print("=" * 80)
    print("RULE-BASED CRITICALITY SCORING - POC RESULTS")
    print("=" * 80)
    print()

    results = []
    for entry in test_data:
        domain = entry.get('domain', '')
        title = entry.get('title', '')
        findings = entry.get('findings', [])
        html = entry.get('html', '')

        result = calculate_criticality(domain, title, findings, html)
        results.append(result)

        # Print result
        print(f"Domain: {domain}")
        print(f"Title: {title}")
        print(f"Score: {result['score']} ({result['category']})")
        print()
        print("Calculation:")
        print(f"  Base:     {result['breakdown']['base']:.2f}")
        print(f"  Domain:   {result['breakdown']['domain']:+.2f}")
        print(f"  Title:    {result['breakdown']['title']:+.2f}")
        print(f"  HTTP:     {result['breakdown']['http']:+.2f}")
        print(f"  Findings: {result['breakdown']['findings']:+.2f}")
        print(f"  Tech:     {result['breakdown']['tech']:+.2f}")
        print(f"  TOTAL:    {result['score']:.2f} ({result['category']})")
        print()
        print("Factors:")
        for factor in result['factors']:
            print(f"  - {factor}")
        print()
        print("-" * 80)
        print()

    # Summary
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print()

    # Sort by score descending
    results.sort(key=lambda x: x['score'], reverse=True)

    print(f"{'Domain':<40} {'Score':<8} {'Category':<10}")
    print("-" * 80)
    for r in results:
        print(f"{r['domain']:<40} {r['score']:<8.2f} {r['category']:<10}")

    print()
    print("Category Distribution:")
    categories = {}
    for r in results:
        cat = r['category']
        categories[cat] = categories.get(cat, 0) + 1

    for cat in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = categories.get(cat, 0)
        print(f"  {cat}: {count}")

if __name__ == '__main__':
    main()
