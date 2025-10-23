#!/usr/bin/env python3
"""
Semantic criticality analysis - extract insights beyond Nuclei findings.
No AI - rule-based keyword matching and heuristics.
"""

import json
import re
from typing import Dict, List, Tuple

# Operational vs Marketing keywords
MARKETING_KEYWORDS = [
    'discover', 'learn', 'explore', 'transform', 'revolutionize',
    'free trial', 'pricing', 'contact us', 'request demo', 'get started',
    'sign up', 'subscribe', 'newsletter', 'solutions', 'products',
    'testimonials', 'case studies', 'customers', 'partners'
]

OPERATIONAL_KEYWORDS = [
    'login', 'admin', 'configure', 'manage', 'control',
    'dashboard', 'console', 'settings', 'preferences',
    'user management', 'access control', 'permissions'
]

# Tracking/analytics services
TRACKING_SERVICES = [
    'google-analytics', 'googletagmanager', 'gtm.js',
    'mixpanel', 'segment.com', 'amplitude', 'heap',
    'clarity.ms', 'hotjar', 'crazyegg'
]

# Marketing automation
MARKETING_TOOLS = [
    'marketo', 'hubspot', 'salesforce', 'pardot',
    'eloqua', 'drift', 'intercom', 'zendesk',
    'livechat', 'tawk.to'
]

# A/B testing tools
AB_TESTING_TOOLS = [
    'optimizely', 'vwo', 'visualwebsiteoptimizer',
    'google-optimize', 'ab tasty'
]

# Data sensitivity keywords
PII_KEYWORDS = [
    'personal information', 'personally identifiable', 'pii',
    'social security', 'ssn', 'passport', 'driver license',
    'date of birth', 'dob', 'address', 'phone number',
    'email address', 'full name'
]

FINANCIAL_KEYWORDS = [
    'credit card', 'bank account', 'routing number',
    'financial records', 'transaction history', 'payment details',
    'account balance', 'wire transfer', 'ach', 'swift'
]

HEALTH_KEYWORDS = [
    'medical records', 'patient data', 'hipaa', 'phi',
    'health information', 'diagnosis', 'prescription',
    'healthcare', 'clinical'
]

COMPLIANCE_KEYWORDS = [
    'gdpr', 'ccpa', 'sox', 'sarbanes-oxley',
    'pci-dss', 'pci compliance', 'iso 27001',
    'data protection', 'privacy policy', 'regulatory compliance'
]

CONFIDENTIAL_KEYWORDS = [
    'confidential', 'proprietary', 'internal only',
    'restricted access', 'classified', 'sensitive',
    'for internal use', 'employees only', 'staff only'
]

# Business function keywords
ADMIN_FUNCTION_KEYWORDS = [
    'admin console', 'administration', 'user management',
    'control panel', 'system configuration', 'database admin',
    'access control', 'permissions', 'roles', 'privileges',
    'system settings', 'configuration'
]

DATA_OPS_KEYWORDS = [
    'data export', 'bulk operations', 'batch processing',
    'report generation', 'query builder', 'data warehouse',
    'analytics', 'business intelligence', 'etl'
]

INFRASTRUCTURE_KEYWORDS = [
    'deployment', 'production environment', 'server management',
    'infrastructure', 'kubernetes', 'docker', 'cloud resources',
    'monitoring', 'observability', 'metrics'
]

SUPPORT_KEYWORDS = [
    'help center', 'documentation', 'knowledge base',
    'faq', 'support ticket', 'community forum',
    'getting started', 'user guide', 'tutorial'
]

def extract_text_content(html: str) -> str:
    """Extract meaningful text from HTML (strip tags and scripts)"""
    if not html:
        return ""

    # Remove script and style tags with content
    html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL | re.IGNORECASE)

    # Remove HTML comments
    html = re.sub(r'<!--.*?-->', '', html, flags=re.DOTALL)

    # Remove HTML tags
    text = re.sub(r'<[^>]+>', ' ', html)

    # Decode HTML entities
    text = text.replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>')
    text = text.replace('&quot;', '"').replace('&#39;', "'")

    # Clean whitespace
    text = re.sub(r'\s+', ' ', text).strip()

    return text.lower()

def count_external_scripts(html: str) -> Tuple[int, List[str]]:
    """Count external script sources"""
    if not html:
        return 0, []

    # Find all external scripts
    scripts = re.findall(r'<script[^>]+src=["\']https?://([^"\']+)["\']', html, re.IGNORECASE)

    # Extract domains
    domains = []
    for script in scripts:
        domain = script.split('/')[0]
        if domain not in domains:
            domains.append(domain)

    return len(domains), domains

def analyze_operational_context(html: str, text: str) -> Tuple[float, str, List[str]]:
    """Determine if operational tool or marketing site"""
    factors = []
    score = 0.0

    # Count tracking scripts
    tracking_count = sum(1 for service in TRACKING_SERVICES if service in html.lower())

    # Count marketing tools
    marketing_tools_count = sum(1 for tool in MARKETING_TOOLS if tool in html.lower())

    # Check A/B testing
    has_ab_testing = any(tool in html.lower() for tool in AB_TESTING_TOOLS)

    # Count external scripts
    external_count, external_domains = count_external_scripts(html)

    # Count marketing keywords in text
    marketing_keyword_count = sum(1 for kw in MARKETING_KEYWORDS if kw in text)

    # Count operational keywords
    operational_keyword_count = sum(1 for kw in OPERATIONAL_KEYWORDS if kw in text)

    # Scoring logic
    if tracking_count >= 3 or marketing_tools_count >= 2 or has_ab_testing:
        score = -0.5
        context = "MARKETING"
        factors.append(f"Marketing site (tracking={tracking_count}, tools={marketing_tools_count})")

    elif external_count > 10:
        score = -0.4
        context = "MARKETING"
        factors.append(f"Heavy external integration ({external_count} domains)")

    elif operational_keyword_count > marketing_keyword_count and operational_keyword_count >= 2:
        score = 0.8
        context = "OPERATIONAL"
        factors.append(f"Operational tool (keywords={operational_keyword_count})")

    elif marketing_keyword_count >= 5:
        score = -0.3
        context = "MARKETING"
        factors.append(f"Marketing content (keywords={marketing_keyword_count})")

    elif external_count < 3:
        score = 0.3
        context = "OPERATIONAL"
        factors.append(f"Minimal external dependencies ({external_count})")

    else:
        score = 0.0
        context = "UNKNOWN"

    return score, context, factors

def analyze_data_sensitivity(text: str) -> Tuple[float, List[str]]:
    """Detect data sensitivity indicators"""
    factors = []
    score = 0.0

    # Check for negation patterns first
    negation_pattern = r'(do not|don\'t|does not|doesn\'t|no|never|without)\s+\w+\s+(store|collect|save|share|sell)'

    # PII indicators
    pii_matches = [kw for kw in PII_KEYWORDS if kw in text]
    if pii_matches:
        # Check if negated
        if not re.search(negation_pattern + r'.*' + pii_matches[0], text):
            score += 1.0
            factors.append(f"PII handling ({len(pii_matches)} indicators)")

    # Financial data
    financial_matches = [kw for kw in FINANCIAL_KEYWORDS if kw in text]
    if financial_matches:
        if not re.search(negation_pattern + r'.*' + financial_matches[0], text):
            score += 0.9
            factors.append(f"Financial data ({len(financial_matches)} indicators)")

    # Health data
    health_matches = [kw for kw in HEALTH_KEYWORDS if kw in text]
    if health_matches:
        score += 1.0
        factors.append(f"Health data/HIPAA ({len(health_matches)} indicators)")

    # Compliance
    compliance_matches = [kw for kw in COMPLIANCE_KEYWORDS if kw in text]
    if compliance_matches:
        score += 0.7
        factors.append(f"Compliance ({', '.join(compliance_matches[:2])})")

    # Confidential/Internal
    confidential_matches = [kw for kw in CONFIDENTIAL_KEYWORDS if kw in text]
    if confidential_matches:
        score += 0.8
        factors.append(f"Confidential/restricted access")

    return score, factors

def analyze_business_function(text: str) -> Tuple[float, str, List[str]]:
    """Determine primary business function"""
    factors = []

    # Count keyword matches for each category
    admin_count = sum(1 for kw in ADMIN_FUNCTION_KEYWORDS if kw in text)
    data_ops_count = sum(1 for kw in DATA_OPS_KEYWORDS if kw in text)
    infra_count = sum(1 for kw in INFRASTRUCTURE_KEYWORDS if kw in text)
    support_count = sum(1 for kw in SUPPORT_KEYWORDS if kw in text)

    # Determine primary function
    if admin_count >= 2:
        return 1.2, "ADMIN", [f"Admin functions ({admin_count} indicators)"]
    elif data_ops_count >= 2:
        return 0.9, "DATA_OPS", [f"Data operations ({data_ops_count} indicators)"]
    elif infra_count >= 2:
        return 1.0, "INFRASTRUCTURE", [f"Infrastructure management ({infra_count} indicators)"]
    elif support_count >= 3:
        return -0.1, "SUPPORT", [f"Support/documentation ({support_count} indicators)"]
    else:
        return 0.0, "UNKNOWN", []

def analyze_application_complexity(html: str) -> Tuple[float, List[str]]:
    """Analyze application complexity from HTML structure"""
    factors = []
    score = 0.0

    # Count forms
    form_count = len(re.findall(r'<form', html, re.IGNORECASE))

    # Count inputs
    input_count = len(re.findall(r'<input', html, re.IGNORECASE))

    # Count AJAX/API calls
    ajax_count = len(re.findall(r'(fetch\(|XMLHttpRequest|axios|$.ajax)', html))

    # Scoring
    if form_count >= 3 or input_count > 20:
        score = 0.4
        factors.append(f"Complex application (forms={form_count}, inputs={input_count})")
    elif ajax_count >= 5:
        score = 0.3
        factors.append(f"API-driven application (AJAX calls={ajax_count})")
    elif form_count <= 1 and input_count < 5:
        score = -0.2
        factors.append(f"Simple content page")

    return score, factors

def calculate_semantic_criticality(html: str) -> Dict:
    """
    Calculate semantic criticality from HTTP response.
    Uses rule-based analysis, no AI.
    """
    if not html or len(html) < 100:
        return {
            'semantic_score': 0.0,
            'context': 'UNKNOWN',
            'function': 'UNKNOWN',
            'factors': ['Insufficient data']
        }

    # Extract text content
    text = extract_text_content(html)

    all_factors = []
    semantic_score = 0.0

    # 1. Operational vs Marketing context
    context_score, context_type, context_factors = analyze_operational_context(html, text)
    semantic_score += context_score
    all_factors.extend(context_factors)

    # 2. Data sensitivity
    sensitivity_score, sensitivity_factors = analyze_data_sensitivity(text)
    semantic_score += sensitivity_score
    all_factors.extend(sensitivity_factors)

    # 3. Business function
    function_score, function_type, function_factors = analyze_business_function(text)
    semantic_score += function_score
    all_factors.extend(function_factors)

    # 4. Application complexity
    complexity_score, complexity_factors = analyze_application_complexity(html)
    semantic_score += complexity_score
    all_factors.extend(complexity_factors)

    return {
        'semantic_score': round(semantic_score, 2),
        'context': context_type,
        'function': function_type,
        'sensitivity_score': round(sensitivity_score, 2),
        'factors': all_factors
    }

def main():
    import sys

    if len(sys.argv) < 2:
        print("Usage: ./semantic-criticality-analysis.py <results-criticality-scores.json>")
        print("\nExample:")
        print("  ./semantic-criticality-analysis.py results/qualys.com/nuclei-results/results-criticality-scores.json")
        sys.exit(1)

    scores_file = sys.argv[1]
    jsonl_file = scores_file.replace('-criticality-scores.json', '.jsonl')

    # Load existing scores
    with open(scores_file, 'r') as f:
        existing_scores = json.load(f)

    # Create domain lookup
    domain_scores = {s['domain']: s for s in existing_scores}

    # Load JSONL for HTML
    domain_html = {}
    print(f"Loading HTML from {jsonl_file}...")
    with open(jsonl_file, 'r') as f:
        for line in f:
            if line.strip():
                entry = json.loads(line)
                domain = entry.get('host')
                html = entry.get('response', '')
                if domain and html:
                    # Keep the one with most HTML content
                    if domain not in domain_html or len(html) > len(domain_html[domain]):
                        domain_html[domain] = html

    print(f"Loaded HTML for {len(domain_html)} domains")
    print()

    # Calculate semantic scores
    results = []
    category_changes = []

    for domain, existing in domain_scores.items():
        html = domain_html.get(domain, '')

        # Calculate semantic criticality
        semantic = calculate_semantic_criticality(html)

        # Combine scores
        old_score = existing['score']
        new_score = max(0.1, min(5.0, round(old_score + semantic['semantic_score'], 2)))

        # Determine new category
        if new_score >= 3.5:
            new_category = "CRITICAL"
        elif new_score >= 2.0:
            new_category = "HIGH"
        elif new_score >= 1.0:
            new_category = "MEDIUM"
        else:
            new_category = "LOW"

        old_category = existing['category']
        category_changed = old_category != new_category

        result = {
            'domain': domain,
            'old_score': old_score,
            'semantic_adjustment': semantic['semantic_score'],
            'new_score': new_score,
            'old_category': old_category,
            'new_category': new_category,
            'category_changed': category_changed,
            'context': semantic['context'],
            'function': semantic['function'],
            'semantic_factors': semantic['factors']
        }

        results.append(result)

        if category_changed:
            category_changes.append(result)

    # Sort by impact
    results.sort(key=lambda x: abs(x['semantic_adjustment']), reverse=True)

    # Print results
    print("=" * 100)
    print("SEMANTIC CRITICALITY ANALYSIS - IMPACT SUMMARY")
    print("=" * 100)
    print()

    print(f"Total domains analyzed: {len(results)}")
    print(f"Category changes: {len(category_changes)} ({len(category_changes)/len(results)*100:.1f}%)")
    print()

    # Show top 20 biggest adjustments
    print("TOP 20 BIGGEST ADJUSTMENTS:")
    print("-" * 100)
    for i, r in enumerate(results[:20], 1):
        change_marker = " ⚠️ CHANGED" if r['category_changed'] else ""
        print(f"{i}. {r['domain']}")
        print(f"   Score: {r['old_score']} → {r['new_score']} (adjustment: {r['semantic_adjustment']:+.2f})")
        print(f"   Category: {r['old_category']} → {r['new_category']}{change_marker}")
        print(f"   Context: {r['context']}, Function: {r['function']}")
        if r['semantic_factors']:
            print(f"   Factors: {', '.join(r['semantic_factors'][:2])}")
        print()

    # Show category changes
    if category_changes:
        print()
        print("=" * 100)
        print(f"CATEGORY CHANGES ({len(category_changes)} domains)")
        print("=" * 100)
        print()

        for r in sorted(category_changes, key=lambda x: (x['old_category'], x['new_category'])):
            print(f"{r['domain']}")
            print(f"  {r['old_category']} → {r['new_category']} (score: {r['old_score']} → {r['new_score']})")
            print(f"  Context: {r['context']}, Function: {r['function']}")
            print()

    # Summary statistics
    print()
    print("=" * 100)
    print("SUMMARY STATISTICS")
    print("=" * 100)
    print()

    # Count by semantic adjustment direction
    positive_adjustments = [r for r in results if r['semantic_adjustment'] > 0]
    negative_adjustments = [r for r in results if r['semantic_adjustment'] < 0]
    no_adjustment = [r for r in results if r['semantic_adjustment'] == 0]

    print(f"Positive adjustments (increased risk): {len(positive_adjustments)} ({len(positive_adjustments)/len(results)*100:.1f}%)")
    print(f"Negative adjustments (decreased risk): {len(negative_adjustments)} ({len(negative_adjustments)/len(results)*100:.1f}%)")
    print(f"No adjustment: {len(no_adjustment)} ({len(no_adjustment)/len(results)*100:.1f}%)")
    print()

    # Average adjustments
    avg_adjustment = sum(r['semantic_adjustment'] for r in results) / len(results)
    avg_abs_adjustment = sum(abs(r['semantic_adjustment']) for r in results) / len(results)

    print(f"Average adjustment: {avg_adjustment:+.2f}")
    print(f"Average absolute adjustment: {avg_abs_adjustment:.2f}")
    print()

    # Context distribution
    contexts = {}
    for r in results:
        ctx = r['context']
        contexts[ctx] = contexts.get(ctx, 0) + 1

    print("Context Distribution:")
    for ctx, count in sorted(contexts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {ctx}: {count} ({count/len(results)*100:.1f}%)")

    # Save updated scores
    output_file = scores_file.replace('.json', '-with-semantic.json')
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print()
    print(f"Results saved to: {output_file}")

if __name__ == '__main__':
    main()
