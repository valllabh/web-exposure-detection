#!/usr/bin/env python3
"""
Test multiple AI models for asset criticality detection
"""

import json
import subprocess
import sys

def ask_ollama(prompt, model):
    """Query Ollama with a prompt"""
    result = subprocess.run(
        ["ollama", "run", model, prompt],
        capture_output=True,
        text=True,
        timeout=30
    )
    return result.stdout.strip()

def analyze_domain_criticality(domain, model):
    """Use AI to analyze domain criticality"""

    prompt = f"""Analyze domain criticality. Respond ONLY with valid JSON, nothing else.

Domain: {domain}

Scoring guide:
- 0.1-0.5: Dev/test (dev, staging, test, sandbox)
- 0.5-1.0: Internal tools
- 1.0-2.0: Standard production
- 2.0-3.5: Customer portals, APIs
- 3.5-5.0: Payment systems, critical

JSON format:
{{"score": 1.5, "type": "portal", "reason": "brief explanation"}}"""

    try:
        response = ask_ollama(prompt, model)

        # Extract JSON
        start = response.find('{')
        end = response.rfind('}') + 1
        if start >= 0 and end > start:
            json_str = response[start:end]
            data = json.loads(json_str)
            return {
                "score": data.get("score", 1.0),
                "type": data.get("type", "unknown"),
                "reason": data.get("reason", "")[:100],
                "success": True
            }
        else:
            return {"score": 1.0, "type": "unknown", "reason": f"No JSON: {response[:50]}", "success": False}
    except json.JSONDecodeError as e:
        return {"score": 1.0, "type": "unknown", "reason": f"Parse error: {response[:50]}", "success": False}
    except Exception as e:
        return {"score": 1.0, "type": "unknown", "reason": f"Error: {str(e)[:50]}", "success": False}

def rule_based_score(domain):
    """Simple rule-based scoring"""
    score = 1.0
    d = domain.lower()

    # Production
    if any(x in d for x in ['portal', 'customer', 'client']): score += 0.6
    if any(x in d for x in ['www', 'app']): score += 0.4
    if any(x in d for x in ['pay', 'payment', 'checkout', 'billing']): score += 0.8
    if any(x in d for x in ['api', 'gateway']): score += 0.3
    if any(x in d for x in ['admin', 'dashboard']): score += 0.4

    # Development
    if any(x in d for x in ['dev', 'develop']): score -= 0.4
    if any(x in d for x in ['test', 'testing', 'qa']): score -= 0.4
    if any(x in d for x in ['staging', 'stage', 'uat']): score -= 0.3
    if any(x in d for x in ['sandbox', 'demo']): score -= 0.3

    # Internal
    if any(x in d for x in ['internal', '.local']): score -= 0.2

    return max(0.1, min(5.0, round(score, 2)))

def test_models():
    """Test available models"""

    # Get available models
    result = subprocess.run(["ollama", "list"], capture_output=True, text=True)
    available_models = []
    for line in result.stdout.strip().split('\n')[1:]:  # Skip header
        parts = line.split()
        if parts:
            available_models.append(parts[0])

    print(f"Available models: {', '.join(available_models)}\n")

    # Test domains
    domains = [
        "portal.qualys.com",          # Should be high (2.0+)
        "api.qualys.com",              # Should be medium-high (1.5-2.5)
        "pay.qualys.com",              # Should be very high (3.5+)
        "dev.staging.qualys.com",      # Should be very low (0.1-0.5)
        "test-api.qualys.com",         # Should be low (0.5-1.0)
        "admin.qualys.com",            # Should be high (2.5-3.5)
    ]

    results = {}

    for model in available_models:
        print(f"{'='*60}")
        print(f"Testing: {model}")
        print(f"{'='*60}\n")

        model_results = []
        success_count = 0

        for domain in domains:
            print(f"  {domain}...", end=' ', flush=True)
            ai_result = analyze_domain_criticality(domain, model)
            rule_score = rule_based_score(domain)

            if ai_result['success']:
                success_count += 1
                print(f"✓ {ai_result['score']} (rule: {rule_score})")
            else:
                print(f"✗ FAILED (rule: {rule_score})")

            model_results.append({
                'domain': domain,
                'ai': ai_result,
                'rule': rule_score,
                'diff': abs(ai_result['score'] - rule_score) if ai_result['success'] else None
            })

        results[model] = {
            'results': model_results,
            'success_rate': success_count / len(domains) * 100,
            'success_count': success_count
        }

        print(f"\n  Success rate: {success_count}/{len(domains)} ({results[model]['success_rate']:.0f}%)\n")

    # Summary comparison
    print(f"\n{'='*60}")
    print("MODEL COMPARISON")
    print(f"{'='*60}\n")

    print(f"{'Model':<20} {'Success Rate':<15} {'Avg Diff':<12}")
    print(f"{'-'*20} {'-'*15} {'-'*12}")

    for model, data in results.items():
        diffs = [r['diff'] for r in data['results'] if r['diff'] is not None]
        avg_diff = sum(diffs) / len(diffs) if diffs else 0
        print(f"{model:<20} {data['success_count']}/{len(domains)} ({data['success_rate']:.0f}%){'':<5} {avg_diff:.2f}")

    # Detailed results
    print(f"\n{'='*60}")
    print("DETAILED RESULTS")
    print(f"{'='*60}\n")

    for domain in domains:
        print(f"\n{domain}:")
        print(f"  Rule-based: {rule_based_score(domain)}")
        for model, data in results.items():
            result = next(r for r in data['results'] if r['domain'] == domain)
            if result['ai']['success']:
                print(f"  {model}: {result['ai']['score']} ({result['ai']['type']}) - {result['ai']['reason'][:50]}")
            else:
                print(f"  {model}: FAILED - {result['ai']['reason'][:50]}")

    # Save results
    output_file = '/Users/vajoshi/Work/web-exposure-detection/scripts/multi-model-test-results.json'
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n\nResults saved to: {output_file}")

if __name__ == "__main__":
    test_models()
