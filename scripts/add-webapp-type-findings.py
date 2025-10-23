#!/usr/bin/env python3
"""
Add webapp.type findings to findings.json with proper metadata
"""
import json

# Webapp type findings with metadata and criticality deltas
WEBAPP_TYPES = {
    "webapp.type.payment_processing": {
        "slug": "webapp.type.payment_processing",
        "display_name": "Payment Processing",
        "icon": "payment-processing.svg",
        "show_in_tech": False,
        "classification": ["webapp"],
        "description": "Web applications handling payment transactions, billing, and financial data processing.",
        "labels": ["Business Function", "Payment", "Financial"],
        "criticality_delta": 1.0
    },
    "webapp.type.admin_panel": {
        "slug": "webapp.type.admin_panel",
        "display_name": "Admin Panel",
        "icon": "admin-panel.svg",
        "show_in_tech": False,
        "classification": ["webapp"],
        "description": "Administrative control panels providing privileged access to system management and configuration.",
        "labels": ["Business Function", "Administration"],
        "criticality_delta": 0.7
    },
    "webapp.type.customer_portal": {
        "slug": "webapp.type.customer_portal",
        "display_name": "Customer Portal",
        "icon": "customer-portal.svg",
        "show_in_tech": False,
        "classification": ["webapp"],
        "description": "Self-service portals for customers to manage accounts, view data, and interact with services.",
        "labels": ["Business Function", "Customer Service"],
        "criticality_delta": 0.5
    },
    "webapp.type.saas_dashboard": {
        "slug": "webapp.type.saas_dashboard",
        "display_name": "SaaS Dashboard",
        "icon": "saas-dashboard.svg",
        "show_in_tech": False,
        "classification": ["webapp"],
        "description": "Software-as-a-Service dashboard applications providing analytics, monitoring, and control interfaces.",
        "labels": ["Business Function", "SaaS", "Dashboard"],
        "criticality_delta": 0.4
    },
    "webapp.type.developer_portal": {
        "slug": "webapp.type.developer_portal",
        "display_name": "Developer Portal",
        "icon": "developer-portal.svg",
        "show_in_tech": False,
        "classification": ["webapp"],
        "description": "Developer-focused portals providing API documentation, SDK downloads, and integration resources.",
        "labels": ["Business Function", "Developer Tools"],
        "criticality_delta": 0.3
    },
    "webapp.type.ecommerce": {
        "slug": "webapp.type.ecommerce",
        "display_name": "E-commerce",
        "icon": "ecommerce.svg",
        "show_in_tech": False,
        "classification": ["webapp"],
        "description": "Online shopping platforms handling product catalogs, shopping carts, and checkout processes.",
        "labels": ["Business Function", "E-commerce", "Retail"],
        "criticality_delta": 0.3
    },
    "webapp.type.corporate": {
        "slug": "webapp.type.corporate",
        "display_name": "Corporate Website",
        "icon": "corporate-website.svg",
        "show_in_tech": False,
        "classification": ["webapp"],
        "description": "Corporate websites providing company information, investor relations, and brand presence.",
        "labels": ["Business Function", "Corporate"],
        "criticality_delta": 0.1
    },
    "webapp.type.marketing": {
        "slug": "webapp.type.marketing",
        "display_name": "Marketing Website",
        "icon": "marketing-website.svg",
        "show_in_tech": False,
        "classification": ["webapp"],
        "description": "Marketing-focused websites designed for lead generation, product promotion, and campaigns.",
        "labels": ["Business Function", "Marketing"],
        "criticality_delta": 0.1
    },
    "webapp.type.blog": {
        "slug": "webapp.type.blog",
        "display_name": "Blog",
        "icon": "blog.svg",
        "show_in_tech": False,
        "classification": ["webapp"],
        "description": "Blog websites publishing articles, news, and content for readers and subscribers.",
        "labels": ["Business Function", "Content"],
        "criticality_delta": 0.1
    },
    "webapp.type.documentation": {
        "slug": "webapp.type.documentation",
        "display_name": "Documentation Site",
        "icon": "documentation-site.svg",
        "show_in_tech": False,
        "classification": ["webapp"],
        "description": "Documentation websites providing technical guides, API references, and user manuals.",
        "labels": ["Business Function", "Documentation"],
        "criticality_delta": 0.0
    },
    "webapp.type.landing_page": {
        "slug": "webapp.type.landing_page",
        "display_name": "Landing Page",
        "icon": "landing-page.svg",
        "show_in_tech": False,
        "classification": ["webapp"],
        "description": "Single-page websites focused on specific campaigns, products, or conversion goals.",
        "labels": ["Business Function", "Marketing"],
        "criticality_delta": 0.0
    }
}

def main():
    # Read findings.json
    with open("pkg/webexposure/findings.json", "r") as f:
        findings = json.load(f)

    # Add webapp type findings
    added_count = 0
    for slug, metadata in WEBAPP_TYPES.items():
        if slug not in findings:
            findings[slug] = metadata
            added_count += 1
            print(f"✓ Added {slug}: {metadata['display_name']} (delta: {metadata['criticality_delta']:+.1f})")
        else:
            print(f"✗ {slug}: ALREADY EXISTS")

    # Write back to findings.json
    with open("pkg/webexposure/findings.json", "w") as f:
        json.dump(findings, f, indent=2)

    print(f"\n✓ Added {added_count} webapp.type findings to findings.json")

if __name__ == "__main__":
    main()
