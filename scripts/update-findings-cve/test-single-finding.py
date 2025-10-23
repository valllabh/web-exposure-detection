#!/usr/bin/env python3

"""
Test script to verify vulnx integration with a single finding.
Tests the get_cve_stats function without modifying findings.json.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(__file__))

from datetime import datetime, timezone
import subprocess
import json

def generate_search_key(display_name):
    """Generate a search key for vulnx queries."""
    import re
    name = display_name.lower()
    name = re.sub(r'\.js$', '', name, flags=re.IGNORECASE)
    name = name.replace(' ', '_')
    return name.strip()

def test_vulnx_query(product_name):
    """Test vulnx query for a product."""
    print(f"\n{'='*60}")
    print(f"Testing: {product_name}")
    print(f"{'='*60}")

    search_key = generate_search_key(product_name)
    print(f"Search key: {search_key}")

    try:
        # Query vulnx
        result = subprocess.run(
            ["vulnx", "search", search_key, "--json", "--silent", "--limit", "50"],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.stdout.strip():
            data = json.loads(result.stdout)
            results = data.get('results', [])

            if results:
                # Count by severity
                critical = sum(1 for cve in results if cve.get('severity') == 'critical')
                high = sum(1 for cve in results if cve.get('severity') == 'high')
                medium = sum(1 for cve in results if cve.get('severity') == 'medium')
                low = sum(1 for cve in results if cve.get('severity') == 'low')
                total = len(results)
                kev = sum(1 for cve in results if cve.get('is_kev') == True)

                print(f"✅ Found {total} CVEs:")
                print(f"   Critical: {critical}")
                print(f"   High: {high}")
                print(f"   Medium: {medium}")
                print(f"   Low: {low}")
                print(f"   KEV: {kev}")

                # Show sample KEV CVE if available
                if kev > 0:
                    print(f"\n   Sample KEV CVEs:")
                    for cve in results[:3]:
                        if cve.get('is_kev'):
                            print(f"   - {cve.get('cve_id')}: {cve.get('severity')}")
            else:
                print("✅ No CVEs found")
        else:
            print("✅ No CVEs found (empty response)")

    except subprocess.TimeoutExpired:
        print("❌ Query timed out")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == '__main__':
    print("Testing vulnx integration with sample findings...")

    # Test a few products
    test_vulnx_query("React.js")
    test_vulnx_query("Nginx")
    test_vulnx_query("WordPress")

    print(f"\n{'='*60}")
    print("Test complete!")
