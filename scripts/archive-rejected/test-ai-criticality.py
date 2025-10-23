#!/usr/bin/env python3
"""
Test AI-based asset criticality detection using local Ollama
"""

import json
import subprocess
import sys

def ask_ollama(prompt, model="llama3.2:3b"):
    """Query Ollama with a prompt"""
    result = subprocess.run(
        ["ollama", "run", model, prompt],
        capture_output=True,
        text=True
    )
    return result.stdout.strip()

def analyze_domain_criticality(domain):
    """Use AI to analyze domain criticality"""

    prompt = f"""You are a security expert analyzing domain names to determine asset criticality.

Domain: {domain}

Analyze this domain and provide:
1. Asset criticality score (0.1 to 5.0 multiplier)
2. Confidence level (low/medium/high)
3. Reasoning

Consider:
- Domain patterns (portal, api, dev, staging, prod, www, admin, etc.)
- Business function indicators
- Production vs non-production indicators
- Customer-facing vs internal indicators

Scoring guide:
- 0.1-0.5: Development/test environments
- 0.5-1.0: Internal tools, low-value assets
- 1.0-2.0: Standard production assets
- 2.0-3.5: Customer portals, APIs, important services
- 3.5-5.0: Payment systems, critical infrastructure

Respond ONLY with valid JSON in this exact format:
{{
  "criticality_score": 1.5,
  "confidence": "medium",
  "reasoning": "Brief explanation here",
  "detected_type": "portal/api/admin/blog/staging/etc"
}}"""

    response = ask_ollama(prompt)

    # Try to extract JSON from response
    try:
        # Sometimes LLM adds explanation before/after JSON
        # Try to find JSON block
        start = response.find('{')
        end = response.rfind('}') + 1
        if start >= 0 and end > start:
            json_str = response[start:end]
            return json.loads(json_str)
        else:
            # Fallback: return raw response
            return {
                "criticality_score": 1.0,
                "confidence": "low",
                "reasoning": f"Failed to parse JSON. Raw: {response[:100]}",
                "detected_type": "unknown"
            }
    except json.JSONDecodeError as e:
        return {
            "criticality_score": 1.0,
            "confidence": "low",
            "reasoning": f"JSON parse error: {e}. Raw: {response[:100]}",
            "detected_type": "unknown"
        }

def rule_based_score(domain):
    """Simple rule-based scoring for comparison"""
    score = 1.0
    domain_lower = domain.lower()

    # Production indicators
    if any(x in domain_lower for x in ['portal', 'customer', 'client']):
        score += 0.6
    if any(x in domain_lower for x in ['www', 'app']):
        score += 0.4
    if any(x in domain_lower for x in ['pay', 'payment', 'checkout', 'billing']):
        score += 0.8
    if any(x in domain_lower for x in ['api', 'gateway']):
        score += 0.3
    if any(x in domain_lower for x in ['admin', 'dashboard']):
        score += 0.4

    # Development indicators
    if any(x in domain_lower for x in ['dev', 'develop', 'development']):
        score -= 0.4
    if any(x in domain_lower for x in ['test', 'testing', 'qa']):
        score -= 0.4
    if any(x in domain_lower for x in ['staging', 'stage', 'uat']):
        score -= 0.3
    if any(x in domain_lower for x in ['sandbox', 'demo']):
        score -= 0.3

    # Internal indicators
    if any(x in domain_lower for x in ['internal', '.local', 'intranet']):
        score -= 0.2

    # Apply bounds
    score = max(0.1, min(5.0, score))

    return round(score, 2)

def test_domains(domains):
    """Test both AI and rule-based approaches"""

    results = []

    for domain in domains:
        print(f"\n{'='*60}")
        print(f"Testing: {domain}")
        print(f"{'='*60}")

        # AI analysis
        print("AI Analysis (Ollama)...")
        ai_result = analyze_domain_criticality(domain)

        # Rule-based analysis
        rule_score = rule_based_score(domain)

        result = {
            'domain': domain,
            'ai': ai_result,
            'rule_based': rule_score,
            'difference': abs(ai_result.get('criticality_score', 1.0) - rule_score)
        }
        results.append(result)

        # Display
        print(f"\nAI Score: {ai_result.get('criticality_score', 'N/A')}")
        print(f"AI Confidence: {ai_result.get('confidence', 'N/A')}")
        print(f"AI Type: {ai_result.get('detected_type', 'N/A')}")
        print(f"AI Reasoning: {ai_result.get('reasoning', 'N/A')}")
        print(f"\nRule-based Score: {rule_score}")
        print(f"Difference: {result['difference']:.2f}")

    return results

def main():
    # Test domains from qualys.com
    test_domains_list = [
        # Production portals (should be high)
        "portal.qg3.apps.qualys.com",
        "portal.qualys.com",

        # APIs (should be medium-high)
        "qualysapi.qg2.apps.qualys.com",
        "api.qualys.com",

        # Blogs (should be medium)
        "blog.qualys.com",

        # Payment (should be very high)
        "pay.qualys.com",
        "checkout.example.com",

        # Development (should be low)
        "dev.staging.qualys.com",
        "test-api.qualys.com",
        "sandbox.qualys.com",

        # Admin (should be medium-high)
        "admin.qualys.com",
        "dashboard.qualys.com",

        # Generic (should be medium)
        "www.qualys.com",
    ]

    print("Testing AI-based criticality detection with Ollama")
    print(f"Model: llama3.2:3b")
    print(f"Test domains: {len(test_domains_list)}")

    results = test_domains(test_domains_list)

    # Summary
    print(f"\n\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}\n")

    print(f"{'Domain':<40} {'AI':<8} {'Rule':<8} {'Diff':<8}")
    print(f"{'-'*40} {'-'*8} {'-'*8} {'-'*8}")

    for r in results:
        ai_score = r['ai'].get('criticality_score', 0)
        print(f"{r['domain']:<40} {ai_score:<8.2f} {r['rule_based']:<8.2f} {r['difference']:<8.2f}")

    # Calculate accuracy metrics
    avg_diff = sum(r['difference'] for r in results) / len(results)
    print(f"\nAverage difference: {avg_diff:.2f}")

    # Check agreement (within 0.5)
    agreement = sum(1 for r in results if r['difference'] <= 0.5) / len(results) * 100
    print(f"Agreement (within 0.5): {agreement:.1f}%")

    # Save results
    with open('/Users/vajoshi/Work/web-exposure-detection/scripts/ai-criticality-test-results.json', 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to: scripts/ai-criticality-test-results.json")

if __name__ == "__main__":
    main()
