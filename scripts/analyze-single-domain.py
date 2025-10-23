#!/usr/bin/env python3
"""
Detailed analysis of a single domain's criticality scoring.
Shows extracted HTTP data and scoring breakdown.
"""

import json
import re
import sys

def extract_title_from_html(html: str) -> str:
    """Extract title from HTML response"""
    if not html:
        return ""
    match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    if match:
        title = match.group(1).strip()
        title = re.sub(r'\s+', ' ', title)
        return title
    return ""

def extract_description_from_html(html: str) -> str:
    """Extract meta description from HTML"""
    if not html:
        return ""

    match = re.search(
        r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']',
        html,
        re.IGNORECASE
    )

    if not match:
        match = re.search(
            r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']description["\']',
            html,
            re.IGNORECASE
        )

    return match.group(1).strip() if match else ""

def has_password_field(html: str) -> bool:
    """Check for password input fields"""
    return bool(re.search(r'<input[^>]+type=["\']password["\']', html, re.IGNORECASE))

def has_login_form(html: str) -> bool:
    """Check for login forms"""
    return bool(re.search(r'<form[^>]*?(login|signin|sign-in)', html, re.IGNORECASE))

def has_registration_form(html: str) -> bool:
    """Check for registration forms"""
    return bool(re.search(r'<form[^>]*?(register|signup|sign-up)', html, re.IGNORECASE))

def has_payment_keywords(html: str) -> bool:
    """Check for payment keywords"""
    keywords = ['checkout', 'payment', 'cvv', 'credit card']
    html_lower = html.lower()
    return any(k in html_lower for k in keywords)

def has_sso_indicators(html: str) -> bool:
    """Check for SSO indicators"""
    indicators = ['saml', 'sso', 'okta', 'auth0']
    html_lower = html.lower()
    return any(i in html_lower for i in indicators)

def analyze_domain(jsonl_file: str, domain: str):
    """Analyze a specific domain from JSONL file"""

    print("=" * 80)
    print(f"DOMAIN ANALYSIS: {domain}")
    print("=" * 80)
    print()

    # Find the domain in JSONL
    entry = None
    with open(jsonl_file, 'r') as f:
        for line in f:
            if line.strip():
                data = json.loads(line)
                if data.get('host') == domain:
                    entry = data
                    break

    if not entry:
        print(f"Domain not found in {jsonl_file}")
        return

    # Extract data
    html = entry.get('response', '')
    url = entry.get('url', '')
    extracted = entry.get('extracted-results', {})

    title = extract_title_from_html(html)
    description = extract_description_from_html(html)

    # Analyze HTTP content
    has_password = has_password_field(html)
    has_login = has_login_form(html)
    has_registration = has_registration_form(html)
    has_payment = has_payment_keywords(html)
    has_sso = has_sso_indicators(html)

    # Print analysis
    print(f"URL: {url}")
    print()

    print("EXTRACTED HTTP DATA:")
    print("-" * 80)
    print(f"Title:       {title}")
    print(f"Description: {description}")
    print(f"HTML size:   {len(html)} bytes")
    print()

    print("DETECTED FEATURES:")
    print("-" * 80)
    print(f"Password field:     {'YES' if has_password else 'NO'}")
    print(f"Login form:         {'YES' if has_login else 'NO'}")
    print(f"Registration form:  {'YES' if has_registration else 'NO'}")
    print(f"Payment keywords:   {'YES' if has_payment else 'NO'}")
    print(f"SSO indicators:     {'YES' if has_sso else 'NO'}")
    print()

    print("NUCLEI FINDINGS:")
    print("-" * 80)
    if extracted:
        if isinstance(extracted, dict):
            for key, value in extracted.items():
                print(f"  {key}: {value}")
        elif isinstance(extracted, list):
            for item in extracted:
                print(f"  {item}")
        else:
            print(f"  {extracted}")
    else:
        print("  (none)")
    print()

    # Load criticality score if available
    score_file = jsonl_file.replace('.jsonl', '-criticality-scores.json')
    try:
        with open(score_file, 'r') as f:
            scores = json.load(f)
            domain_score = next((s for s in scores if s['domain'] == domain), None)

            if domain_score:
                print("CRITICALITY SCORE:")
                print("-" * 80)
                print(f"Score:    {domain_score['score']} / 5.0")
                print(f"Category: {domain_score['category']}")
                print()
                print("Breakdown:")
                for key, value in domain_score['breakdown'].items():
                    print(f"  {key:12s}: {value:+.2f}")
                print()
                print("Factors:")
                for factor in domain_score['factors']:
                    print(f"  - {factor}")
    except FileNotFoundError:
        pass

    # Show sample HTML
    if html:
        print()
        print("HTML SAMPLE (first 500 chars):")
        print("-" * 80)
        print(html[:500])

def main():
    if len(sys.argv) < 3:
        print("Usage: ./analyze-single-domain.py <results.jsonl> <domain>")
        print("\nExample:")
        print("  ./analyze-single-domain.py results/qualys.com/nuclei-results/results.jsonl portal.qg2.apps.qualys.com")
        sys.exit(1)

    jsonl_file = sys.argv[1]
    domain = sys.argv[2]

    analyze_domain(jsonl_file, domain)

if __name__ == '__main__':
    main()
