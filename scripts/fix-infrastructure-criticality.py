#!/usr/bin/env python3
"""
Remove criticality_delta from basic infrastructure that shouldn't affect criticality
"""
import json

# Infrastructure that should NOT increase criticality (too generic)
REMOVE_CRITICALITY = [
    "gateway.nginx",
    "gateway.envoy", 
    "gateway.haproxy",
    "gateway.traefik",
]

def main():
    # Read findings.json
    with open("pkg/webexposure/findings.json", "r") as f:
        findings = json.load(f)

    # Remove criticality_delta from basic infrastructure
    removed_count = 0
    for slug in REMOVE_CRITICALITY:
        if slug in findings and "criticality_delta" in findings[slug]:
            del findings[slug]["criticality_delta"]
            removed_count += 1
            print(f"✓ Removed criticality_delta from {slug}")
        else:
            print(f"✗ {slug}: No criticality_delta to remove")

    # Write back to findings.json
    with open("pkg/webexposure/findings.json", "w") as f:
        json.dump(findings, f, indent=2)

    print(f"\n✓ Removed criticality_delta from {removed_count} basic infrastructure findings")
    print("\nKept criticality_delta for:")
    print("  - gateway.cloudflare (+0.2): DDoS protection/WAF")
    print("  - gateway.akamai (+0.3): Enterprise CDN")
    print("  - gateway.kong (+0.3): API management platform")
    print("  - gateway.zuul (+0.3): API gateway")
    print("  - gateway.apigee (+0.3): Enterprise API platform")

if __name__ == "__main__":
    main()
