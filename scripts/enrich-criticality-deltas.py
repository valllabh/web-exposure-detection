#!/usr/bin/env python3
"""
Enrich findings.json with criticality_delta values from rule-based scoring
"""
import json

# Criticality delta mappings from docs/research/rule-based-criticality-scoring.md
CRITICALITY_DELTAS = {
    # Authentication Mechanisms (+0.2 to +0.6)
    "auth.enterprise.saml_sso": 0.6,
    "auth.enterprise.okta": 0.5,
    "auth.enterprise.auth0": 0.5,
    "auth.enterprise.microsoft": 0.5,
    "auth.enterprise.onelogin": 0.5,
    "auth.enterprise.keycloak": 0.4,
    "auth.enterprise.adfs": 0.4,
    "auth.mfa": 0.5,
    "auth.traditional.registration": 0.4,
    "auth.traditional.password_recovery": 0.3,
    "auth.traditional.basic_auth": 0.2,

    # Backend Frameworks (+0.3)
    "backend.framework.rails": 0.3,
    "backend.framework.django": 0.3,
    "backend.framework.spring": 0.3,
    "backend.framework.laravel": 0.3,

    # CMS (+0.3)
    "backend.cms.wordpress": 0.3,
    "backend.cms.drupal": 0.3,

    # Frontend Frameworks (+0.2)
    "frontend.react": 0.2,
    "frontend.angular": 0.2,
    "frontend.vuejs": 0.2,

    # CDN/WAF (+0.2 to +0.3)
    "gateway.cloudflare": 0.2,
    "gateway.akamai": 0.3,

    # API Patterns (+0.3 to +0.4)
    "api.domain_pattern": 0.4,
    "api.spec.openapi": 0.3,
    "api.spec.swagger": 0.3,

    # API Backend Frameworks (+0.3)
    "api.server.fastapi": 0.3,
    "api.server.flask": 0.3,
    "api.server.gin": 0.3,
    "api.server.koa": 0.3,
    "api.server.nestjs": 0.3,
    "backend.framework.express": 0.3,

    # API Detection (+0.2)
    "api.server.json": 0.2,
    "api.server.xml": 0.2,

    # API Gateways (+0.2 to +0.3)
    "gateway.nginx": 0.2,
    "gateway.envoy": 0.2,
    "gateway.kong": 0.3,
    "gateway.traefik": 0.2,
    "gateway.haproxy": 0.2,
    "gateway.zuul": 0.3,
    "gateway.apigee": 0.3,
}

def main():
    # Read findings.json
    with open("pkg/webexposure/findings.json", "r") as f:
        findings = json.load(f)

    # Update criticality_delta for matching findings
    updated_count = 0
    for slug, delta in CRITICALITY_DELTAS.items():
        if slug in findings:
            findings[slug]["criticality_delta"] = delta
            updated_count += 1
            print(f"✓ {slug}: {delta:+.1f}")
        else:
            print(f"✗ {slug}: NOT FOUND")

    # Write back to findings.json
    with open("pkg/webexposure/findings.json", "w") as f:
        json.dump(findings, f, indent=2)

    print(f"\n✓ Updated {updated_count} findings with criticality_delta values")

if __name__ == "__main__":
    main()
