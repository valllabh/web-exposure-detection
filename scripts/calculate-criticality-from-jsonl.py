#!/usr/bin/env python3
"""
Rule-based criticality scoring with JSONL support.
Parses nuclei-results/results.jsonl to extract HTTP response data.
"""

import json
import re
import sys
from typing import Dict, List, Tuple, Optional
from collections import defaultdict

# Domain patterns
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

# Title keywords
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

# Description keywords
DESCRIPTION_KEYWORDS = {
    'enterprise': 0.3, 'platform': 0.3,
    'payment': 0.6, 'checkout': 0.6,
    'admin': 0.5, 'management': 0.4,
    'portal': 0.4, 'dashboard': 0.4,
}

# HTTP content patterns
PAYMENT_KEYWORDS = [
    'checkout', 'payment', 'pay now', 'billing',
    'credit card', 'cvv', 'card number',
    'purchase', 'buy now', 'add to cart'
]

SSO_INDICATORS = [
    'saml', 'sso', 'single sign-on',
    'microsoft', 'azure ad', 'okta',
    'auth0', 'onelogin', 'keycloak'
]

# Findings weights
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
}

def read_jsonl(filepath: str) -> List[Dict]:
    """Read JSONL file (one JSON object per line)"""
    results = []
    with open(filepath, 'r') as f:
        for line_num, line in enumerate(f, 1):
            if line.strip():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(f"Warning: Failed to parse line {line_num}: {e}", file=sys.stderr)
    return results

def extract_title_from_html(html: str) -> str:
    """Extract title from HTML response"""
    if not html:
        return ""

    match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    if match:
        title = match.group(1).strip()
        # Remove extra whitespace
        title = re.sub(r'\s+', ' ', title)
        return title
    return ""

def extract_description_from_html(html: str) -> str:
    """Extract meta description from HTML"""
    if not html:
        return ""

    # Method 1: name="description"
    match = re.search(
        r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']',
        html,
        re.IGNORECASE
    )

    # Method 2: content first
    if not match:
        match = re.search(
            r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']description["\']',
            html,
            re.IGNORECASE
        )

    return match.group(1).strip() if match else ""

def has_password_field(html: str) -> bool:
    """Check for password input fields"""
    if not html:
        return False
    return bool(re.search(r'<input[^>]+type=["\']password["\']', html, re.IGNORECASE))

def has_login_form(html: str) -> bool:
    """Check for login/signin forms"""
    if not html:
        return False
    return bool(re.search(
        r'<form[^>]*?(login|signin|sign-in|authenticate)',
        html,
        re.IGNORECASE
    ))

def has_registration_form(html: str) -> bool:
    """Check for registration/signup forms"""
    if not html:
        return False
    return bool(re.search(
        r'<form[^>]*?(register|signup|sign-up|create.account)',
        html,
        re.IGNORECASE
    ))

def has_payment_keywords(html: str) -> bool:
    """Check for payment/commerce keywords"""
    if not html:
        return False
    html_lower = html.lower()
    return any(keyword in html_lower for keyword in PAYMENT_KEYWORDS)

def has_sso_indicators(html: str) -> bool:
    """Check for SSO/enterprise auth indicators"""
    if not html:
        return False
    html_lower = html.lower()
    return any(indicator in html_lower for indicator in SSO_INDICATORS)

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
        ('it works', ''),
        ('nginx', 'welcome'),
        ('apache', 'default page'),
    ]

    for code, text in error_indicators:
        if code in title_lower:
            if not text or text in title_lower:
                return True

    return False

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
            factors.append(f"Domain '{pattern}': {weight:+.1f}")

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

def score_description(description: str) -> Tuple[float, List[str]]:
    """Score meta description keywords"""
    if not description:
        return 0.0, []

    factors = []
    score = 0.0
    desc_lower = description.lower()

    for keyword, weight in DESCRIPTION_KEYWORDS.items():
        if keyword in desc_lower:
            score += weight
            factors.append(f"Description '{keyword}': {weight:+.1f}")

    return score, factors

def score_http_content(html: str, title: str) -> Tuple[float, List[str]]:
    """Score HTTP response content"""
    if not html:
        return 0.0, []

    factors = []
    score = 0.0

    # Error pages (strong negative)
    if is_error_page(title, html):
        score -= 0.8
        factors.append("Error page: -0.8")
        return score, factors

    # Payment indicators (strong positive)
    if has_payment_keywords(html):
        score += 1.0
        factors.append("Payment keywords: +1.0")

    # Login/auth forms
    if has_password_field(html) or has_login_form(html):
        score += 0.5
        factors.append("Login/password form: +0.5")

    # Registration
    if has_registration_form(html):
        score += 0.4
        factors.append("Registration form: +0.4")

    # SSO indicators
    if has_sso_indicators(html):
        score += 0.3
        factors.append("SSO indicators: +0.3")

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

def calculate_criticality(domain: str, title: str, description: str,
                         findings: List[str], html: str = "") -> Dict:
    """
    Calculate criticality score using rule-based approach with HTTP data
    """
    base_score = 1.0
    all_factors = []

    # 1. Domain Pattern
    domain_score, domain_factors = score_domain_pattern(domain)
    all_factors.extend(domain_factors)

    # 2. Title
    title_score, title_factors = score_title(title)
    all_factors.extend(title_factors)

    # 3. Description
    desc_score, desc_factors = score_description(description)
    all_factors.extend(desc_factors)

    # 4. HTTP Content
    http_score, http_factors = score_http_content(html, title)
    all_factors.extend(http_factors)

    # 5. Nuclei Findings
    findings_score, findings_factors = score_findings(findings)
    all_factors.extend(findings_factors)

    # Calculate final score
    total_score = base_score + domain_score + title_score + desc_score + http_score + findings_score
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
            'description': round(desc_score, 2),
            'http': round(http_score, 2),
            'findings': round(findings_score, 2),
        }
    }

def parse_jsonl_entry(entry: Dict) -> Optional[Dict]:
    """Extract relevant data from JSONL entry"""
    host = entry.get('host', '')
    if not host:
        return None

    # Get response HTML
    html = entry.get('response', '')

    # Extract from findings (if available)
    extracted = entry.get('extracted-results', {})

    # Build findings list from extracted-results keys
    findings = []
    if isinstance(extracted, dict):
        for key in extracted.keys():
            if key.startswith(('auth.', 'backend.', 'gateway.', 'api.', 'frontend.')):
                findings.append(key)

    # Extract title and description from HTML
    title = extract_title_from_html(html)
    description = extract_description_from_html(html)

    return {
        'domain': host,
        'title': title,
        'description': description,
        'findings': findings,
        'html': html,
    }

def main():
    if len(sys.argv) < 2:
        print("Usage: ./calculate-criticality-from-jsonl.py <results.jsonl>")
        print("\nExample:")
        print("  ./calculate-criticality-from-jsonl.py results/qualys.com/nuclei-results/results.jsonl")
        sys.exit(1)

    jsonl_file = sys.argv[1]

    print("=" * 80)
    print("RULE-BASED CRITICALITY SCORING - JSONL PARSER")
    print("=" * 80)
    print(f"Reading: {jsonl_file}")
    print()

    # Read JSONL file
    entries = read_jsonl(jsonl_file)
    print(f"Parsed {len(entries)} JSONL entries")
    print()

    # Group by domain (take the entry with most findings)
    domains_data = {}
    for entry in entries:
        parsed = parse_jsonl_entry(entry)
        if not parsed:
            continue

        domain = parsed['domain']

        # Use entry with most findings
        if domain not in domains_data or len(parsed['findings']) > len(domains_data[domain]['findings']):
            domains_data[domain] = parsed

    print(f"Found {len(domains_data)} unique domains")
    print()

    # Calculate criticality for each domain
    results = []
    for domain, data in domains_data.items():
        result = calculate_criticality(
            domain=data['domain'],
            title=data['title'],
            description=data['description'],
            findings=data['findings'],
            html=data['html']
        )
        results.append(result)

    # Sort by score descending
    results.sort(key=lambda x: x['score'], reverse=True)

    # Print top 20 and bottom 10
    print("=" * 80)
    print("TOP 20 DOMAINS (Highest Risk)")
    print("=" * 80)
    print()

    for i, result in enumerate(results[:20], 1):
        print(f"{i}. {result['domain']}")
        print(f"   Score: {result['score']} ({result['category']})")
        if result['factors']:
            print(f"   Key factors: {', '.join(result['factors'][:3])}")
        print()

    print("=" * 80)
    print("BOTTOM 10 DOMAINS (Lowest Risk)")
    print("=" * 80)
    print()

    for i, result in enumerate(results[-10:], 1):
        print(f"{i}. {result['domain']}")
        print(f"   Score: {result['score']} ({result['category']})")
        if result['factors']:
            print(f"   Key factors: {', '.join(result['factors'][:3])}")
        print()

    # Summary statistics
    print("=" * 80)
    print("SUMMARY STATISTICS")
    print("=" * 80)
    print()

    categories = defaultdict(int)
    for r in results:
        categories[r['category']] += 1

    total = len(results)
    print(f"Total domains: {total}")
    print()
    print("Category Distribution:")
    for cat in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = categories[cat]
        pct = (count / total * 100) if total > 0 else 0
        print(f"  {cat:10s}: {count:4d} ({pct:5.1f}%)")

    print()
    print(f"Average score: {sum(r['score'] for r in results) / total:.2f}")
    print(f"Median score:  {results[len(results)//2]['score']:.2f}")
    print(f"Max score:     {results[0]['score']:.2f}")
    print(f"Min score:     {results[-1]['score']:.2f}")

    # Save full results to JSON
    output_file = jsonl_file.replace('.jsonl', '-criticality-scores.json')
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print()
    print(f"Full results saved to: {output_file}")

if __name__ == '__main__':
    main()
