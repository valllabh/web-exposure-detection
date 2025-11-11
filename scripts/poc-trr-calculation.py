#!/usr/bin/env python3
"""
Proof of Concept: True Risk Range (TRR) Calculation

Calculates TRR for domains from scan results using updated findings.json.
No changes to main codebase - pure PoC script.
"""

import json
import sys
from typing import Dict, List, Tuple, Any
from datetime import datetime

# Environmental multiplier factors (min, max)
ENVIRONMENTAL_FACTORS = {
    'internet_facing': (1.2, 1.4),      # Always true for external discovery
    'high_value_industry': (1.1, 1.3),  # Finance, healthcare, government
    'waf_protection': (0.7, 0.8),       # Cloudflare, Akamai detected
    'api_exposure': (1.1, 1.2),         # API endpoints detected
    'ai_systems': (1.0, 1.15),          # AI classification present
    'poor_security_headers': (1.1, 1.3), # Headers grade < B
    'enterprise_auth': (0.8, 0.9),      # SAML, SSO detected
    'payment_processing': (1.2, 1.4),   # Payment indicators
    'pci_dss': (0.8, 0.9),              # PCI DSS compliance indicators
    'high_kev_count': (1.15, 1.25),     # 5+ KEV vulnerabilities
}

# Industry high value mapping
HIGH_VALUE_INDUSTRIES = ['finance', 'banking', 'healthcare', 'insurance', 'government']

class TRRCalculator:
    def __init__(self, findings_json_path: str):
        """Initialize with findings.json metadata"""
        with open(findings_json_path, 'r') as f:
            self.findings_metadata = json.load(f)

    def get_finding_metadata(self, slug: str) -> Dict[str, Any]:
        """Get metadata for a finding slug"""
        return self.findings_metadata.get(slug, {})

    def aggregate_technology_scores(self, findings: List[Dict]) -> Tuple[float, List[Dict], int]:
        """
        Aggregate technology severity scores from detected findings

        Returns: (avg_severity_score, contributors, total_kev)
        """
        total_weighted_score = 0.0
        total_weight = 0.0
        contributors = []
        total_kev = 0

        for finding in findings:
            slug = finding.get('slug', '')
            metadata = self.get_finding_metadata(slug)

            # Only process findings with weighted_severity_score > 0
            weighted_severity_score = metadata.get('weighted_severity_score', 0)
            if weighted_severity_score == 0:
                continue

            technology_weight = metadata.get('technology_weight', 2.0)

            # Calculate contribution
            contribution = weighted_severity_score * technology_weight
            total_weighted_score += contribution
            total_weight += technology_weight

            # Track KEV count
            security = metadata.get('security', {})
            if security:
                cve = security.get('cve', {})
                if cve:
                    stats = cve.get('stats', {})
                    kev = stats.get('kev', 0)
                    total_kev += kev

            # Add contributor
            contributors.append({
                'slug': slug,
                'display_name': metadata.get('display_name', slug),
                'technology_weight': technology_weight,
                'weighted_severity_score': weighted_severity_score,
                'contribution': contribution,
                'kev_count': metadata.get('security', {}).get('cve', {}).get('stats', {}).get('kev', 0)
            })

        # Calculate average
        if total_weight > 0:
            avg_severity_score = total_weighted_score / total_weight
        else:
            avg_severity_score = 0.0

        return avg_severity_score, contributors, total_kev

    def calculate_environmental_multipliers(
        self,
        findings: List[Dict],
        criticality_score: int,
        industry: str = None
    ) -> Tuple[float, float, List[str]]:
        """
        Calculate environmental multipliers (min, max)

        Returns: (min_multiplier, max_multiplier, factors_applied)
        """
        min_mult = 1.0
        max_mult = 1.0
        factors_applied = []

        # Always internet facing
        min_mult *= ENVIRONMENTAL_FACTORS['internet_facing'][0]
        max_mult *= ENVIRONMENTAL_FACTORS['internet_facing'][1]
        factors_applied.append('Internet Facing')

        # Check industry
        if industry and any(hv in industry.lower() for hv in HIGH_VALUE_INDUSTRIES):
            min_mult *= ENVIRONMENTAL_FACTORS['high_value_industry'][0]
            max_mult *= ENVIRONMENTAL_FACTORS['high_value_industry'][1]
            factors_applied.append(f'High Value Industry ({industry})')

        # Check findings for environmental signals
        finding_slugs = [f.get('slug', '') for f in findings]

        # WAF/CDN protection
        if any('cloudflare' in slug or 'cdn' in slug for slug in finding_slugs):
            min_mult *= ENVIRONMENTAL_FACTORS['waf_protection'][0]
            max_mult *= ENVIRONMENTAL_FACTORS['waf_protection'][1]
            factors_applied.append('WAF/CDN Protection')

        # API exposure
        if any('api' in slug for slug in finding_slugs):
            min_mult *= ENVIRONMENTAL_FACTORS['api_exposure'][0]
            max_mult *= ENVIRONMENTAL_FACTORS['api_exposure'][1]
            factors_applied.append('API Exposure')

        # AI systems
        if any('ai' in slug for slug in finding_slugs):
            min_mult *= ENVIRONMENTAL_FACTORS['ai_systems'][0]
            max_mult *= ENVIRONMENTAL_FACTORS['ai_systems'][1]
            factors_applied.append('AI Systems')

        # Enterprise auth (SAML, SSO)
        if any('saml' in slug or 'sso' in slug for slug in finding_slugs):
            min_mult *= ENVIRONMENTAL_FACTORS['enterprise_auth'][0]
            max_mult *= ENVIRONMENTAL_FACTORS['enterprise_auth'][1]
            factors_applied.append('Enterprise Auth')

        # Payment processing
        if any('payment' in slug for slug in finding_slugs):
            min_mult *= ENVIRONMENTAL_FACTORS['payment_processing'][0]
            max_mult *= ENVIRONMENTAL_FACTORS['payment_processing'][1]
            factors_applied.append('Payment Processing')

        # TODO: Add security headers check when available

        return min_mult, max_mult, factors_applied

    def calculate_trr(
        self,
        domain: str,
        findings: List[Dict],
        criticality_score: int,
        industry: str = None
    ) -> Dict[str, Any]:
        """
        Calculate True Risk Range for a domain

        Returns: TRR result dictionary
        """
        # Step 1: Aggregate technology scores
        avg_severity_score, tech_contributors, total_kev = self.aggregate_technology_scores(findings)

        # Handle case where no CVE data available
        # Use baseline score from asset criticality and findings count
        has_cve_data = avg_severity_score > 0
        if not has_cve_data:
            # Baseline threat from just being exposed with findings
            finding_count = len(findings)
            baseline_score = min(20 + (finding_count * 5), 50)  # 20-50 range
            avg_severity_score = baseline_score

        # Apply KEV multiplier based on KEV count (stronger impact)
        # KEV is a strong signal of real exploitation risk
        kev_multiplier_min = 1.0
        kev_multiplier_max = 1.0
        if total_kev >= 10:
            kev_multiplier_min = 1.4
            kev_multiplier_max = 1.8
        elif total_kev >= 5:
            kev_multiplier_min = 1.3
            kev_multiplier_max = 1.6
        elif total_kev >= 2:
            kev_multiplier_min = 1.15
            kev_multiplier_max = 1.3

        # Step 2: Calculate environmental multipliers
        env_min, env_max, env_factors = self.calculate_environmental_multipliers(
            findings, criticality_score, industry
        )

        # Combine with KEV multiplier
        env_min *= kev_multiplier_min
        env_max *= kev_multiplier_max
        if total_kev >= 10:
            env_factors.append(f'Very High KEV Count ({total_kev}) [1.4-1.8×]')
        elif total_kev >= 5:
            env_factors.append(f'High KEV Count ({total_kev}) [1.3-1.6×]')
        elif total_kev >= 2:
            env_factors.append(f'Moderate KEV Count ({total_kev}) [1.15-1.3×]')

        # Step 3: Calculate TRR
        acs = criticality_score  # Already on 1-5 scale

        trr_min_raw = acs * avg_severity_score * env_min
        trr_max_raw = acs * avg_severity_score * env_max

        # Cap at 1000
        trr_min = min(int(trr_min_raw), 1000)
        trr_max = min(int(trr_max_raw), 1000)

        # Normalize if both hit cap (show variability)
        if trr_min >= 1000 and trr_max >= 1000:
            # Scale down to show range
            if trr_min_raw > trr_max_raw * 0.85:
                trr_min = 850
            else:
                trr_min = int(trr_min_raw * (850.0 / trr_max_raw))

        # Determine category
        category = self.determine_category(trr_max)

        # Determine confidence based on range width
        range_width = trr_max - trr_min
        if range_width < 150:
            confidence = 'High'
        elif range_width < 300:
            confidence = 'Medium'
        else:
            confidence = 'Low'

        return {
            'domain': domain,
            'trr_min': trr_min,
            'trr_max': trr_max,
            'category': category,
            'confidence': confidence,
            'acs': acs,
            'avg_severity_score': round(avg_severity_score, 2),
            'has_cve_data': has_cve_data,
            'total_kev': total_kev,
            'env_multiplier_min': round(env_min, 3),
            'env_multiplier_max': round(env_max, 3),
            'env_factors': env_factors,
            'tech_contributors': tech_contributors,
            'calculated': datetime.utcnow().isoformat() + 'Z'
        }

    def determine_category(self, trr_max: int) -> str:
        """Determine risk category from TRR max score"""
        if trr_max >= 850:
            return 'CRITICAL'
        elif trr_max >= 650:
            return 'HIGH'
        elif trr_max >= 400:
            return 'MEDIUM'
        elif trr_max >= 200:
            return 'LOW'
        else:
            return 'MINIMAL'

def format_trr_report(results: List[Dict[str, Any]]) -> str:
    """Format TRR results as a readable report"""
    report = []
    report.append("=" * 80)
    report.append("TRUE RISK RANGE (TRR) CALCULATION - PROOF OF CONCEPT")
    report.append("=" * 80)
    report.append("")

    for idx, result in enumerate(results, 1):
        report.append(f"{'=' * 80}")
        report.append(f"DOMAIN {idx}: {result['domain']}")
        report.append(f"{'=' * 80}")
        report.append("")

        # TRR Score
        report.append(f"TRUE RISK RANGE: {result['trr_min']} - {result['trr_max']}")
        report.append(f"CATEGORY: {result['category']}")
        report.append(f"CONFIDENCE: {result['confidence']}")
        if not result.get('has_cve_data', True):
            report.append(f"NOTE: Baseline score (no CVE data available for detected technologies)")
        report.append("")

        # Calculation Components
        report.append("CALCULATION BREAKDOWN:")
        report.append(f"  Asset Criticality Score (ACS): {result['acs']}")
        report.append(f"  Average Severity Score: {result['avg_severity_score']}")
        report.append(f"  Environmental Multiplier: {result['env_multiplier_min']} - {result['env_multiplier_max']}")
        report.append(f"  Total KEV Count: {result['total_kev']}")
        report.append("")

        # Formula
        report.append("FORMULA:")
        report.append(f"  TRR_Min = MIN({result['acs']} × {result['avg_severity_score']} × {result['env_multiplier_min']}, 1000)")
        report.append(f"          = MIN({result['acs'] * result['avg_severity_score'] * result['env_multiplier_min']:.2f}, 1000)")
        report.append(f"          = {result['trr_min']}")
        report.append("")
        report.append(f"  TRR_Max = MIN({result['acs']} × {result['avg_severity_score']} × {result['env_multiplier_max']}, 1000)")
        report.append(f"          = MIN({result['acs'] * result['avg_severity_score'] * result['env_multiplier_max']:.2f}, 1000)")
        report.append(f"          = {result['trr_max']}")
        report.append("")

        # Environmental Factors
        report.append("ENVIRONMENTAL FACTORS APPLIED:")
        for factor in result['env_factors']:
            report.append(f"  - {factor}")
        report.append("")

        # Technology Contributors
        if result['tech_contributors']:
            report.append("TECHNOLOGY RISK CONTRIBUTORS:")
            for tech in sorted(result['tech_contributors'], key=lambda x: x['contribution'], reverse=True):
                kev_indicator = f" [KEV: {tech['kev_count']}]" if tech['kev_count'] > 0 else ""
                report.append(f"  - {tech['display_name']}{kev_indicator}")
                report.append(f"    Weight: {tech['technology_weight']}, Severity Score: {tech['weighted_severity_score']}, Contribution: {tech['contribution']:.2f}")
        elif not result.get('has_cve_data', True):
            report.append("TECHNOLOGY RISK CONTRIBUTORS: Baseline score based on asset exposure")
            report.append(f"  - {len([f for f in result.get('env_factors', []) if 'KEV' not in f])} findings detected (auth, patterns, etc.)")
        else:
            report.append("TECHNOLOGY RISK CONTRIBUTORS: None")

        report.append("")

    report.append("=" * 80)
    report.append("LEGEND:")
    report.append("  CRITICAL: 850-1000 (Imminent risk, immediate action)")
    report.append("  HIGH: 650-849 (Significant risk, prioritize)")
    report.append("  MEDIUM: 400-649 (Moderate risk, plan remediation)")
    report.append("  LOW: 200-399 (Minimal risk, monitor)")
    report.append("  MINIMAL: 0-199 (Very low risk)")
    report.append("=" * 80)

    return '\n'.join(report)

def main():
    """Main PoC execution"""

    # Paths
    findings_json = 'pkg/webexposure/findings/findings.json'
    results_json = 'results/statestreet.com/web-exposure-result.json'

    # Check if custom paths provided
    if len(sys.argv) > 1:
        results_json = sys.argv[1]

    print(f"Loading findings metadata from: {findings_json}")
    calculator = TRRCalculator(findings_json)

    print(f"Loading scan results from: {results_json}")
    with open(results_json, 'r') as f:
        scan_results = json.load(f)

    # Get industry classification if available
    industry = None
    try:
        with open('results/statestreet.com/industry-classification.json', 'r') as f:
            industry_data = json.load(f)
            industry = industry_data.get('industry', {}).get('primary', None)
    except:
        pass

    # Select domains with technology detections for meaningful TRR calculations
    sample_domains = []
    target_domains = [
        'careers.statestreet.com',      # Vue.js (frontend)
        'api.statestreet.com',          # Drupal (backend CMS)
        'developer.statestreet.com',    # Drupal (backend CMS)
        'comms.statestreet.com',        # Cloudflare (gateway)
        'ssp.statestreet.com'           # Auth heavy but no tech detection
    ]

    # Find these domains in results
    all_domains = scan_results.get('web_applications_found', []) + scan_results.get('api_servers', [])
    for target in target_domains:
        for domain_data in all_domains:
            if domain_data['domain'] == target:
                sample_domains.append(domain_data)
                break

    print(f"\nCalculating TRR for {len(sample_domains)} sample domains from State Street...")
    print()

    # Calculate TRR for each domain
    trr_results = []
    for domain_data in sample_domains:
        domain = domain_data['domain']
        findings = domain_data.get('findings', [])
        criticality = domain_data.get('criticality', {})
        criticality_score = criticality.get('score', 3)

        print(f"Processing: {domain}")
        trr_result = calculator.calculate_trr(domain, findings, criticality_score, industry)
        trr_results.append(trr_result)

    # Generate report
    report = format_trr_report(trr_results)
    print("\n" + report)

    # Save report
    output_path = 'results/statestreet.com/trr-poc-report.txt'
    with open(output_path, 'w') as f:
        f.write(report)
    print(f"\nReport saved to: {output_path}")

    # Save JSON
    json_output_path = 'results/statestreet.com/trr-poc-results.json'
    with open(json_output_path, 'w') as f:
        json.dump(trr_results, f, indent=2)
    print(f"JSON results saved to: {json_output_path}")

if __name__ == '__main__':
    main()
