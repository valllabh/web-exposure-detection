#!/usr/bin/env python3
"""
Merge corporate website into marketing website category
"""
import json

def main():
    # Read findings.json
    with open("pkg/webexposure/findings.json", "r") as f:
        findings = json.load(f)

    # Remove corporate website (will be merged into marketing)
    if "webapp.type.corporate" in findings:
        del findings["webapp.type.corporate"]
        print("✓ Removed webapp.type.corporate")
    else:
        print("✗ webapp.type.corporate not found")

    # Update marketing website description to include corporate aspects
    if "webapp.type.marketing" in findings:
        findings["webapp.type.marketing"]["description"] = "Marketing and corporate websites for company information, brand presence, lead generation, and campaigns."
        findings["webapp.type.marketing"]["labels"] = ["Business Function", "Marketing", "Corporate"]
        print("✓ Updated webapp.type.marketing to include corporate aspects")
    
    # Write back to findings.json
    with open("pkg/webexposure/findings.json", "w") as f:
        json.dump(findings, f, indent=2)

    print("\n✓ Merged corporate into marketing category")

if __name__ == "__main__":
    main()
