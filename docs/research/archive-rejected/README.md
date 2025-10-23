# Archive - Rejected Approaches

**Status:** NOT FOR IMPLEMENTATION
**Purpose:** Historical record of approaches we tested and rejected

## Contents

This directory contains research documentation for approaches that were **tested and rejected** after implementation and validation.

### Rejected: AI/LLM Approach

**Files:**
- `ai-vs-rule-based-criticality.md` - First AI test (llama3.2:3b)
- `multi-model-ai-test-results.md` - Multi-model comparison

**Why rejected:**
- 0% dev/test detection accuracy (scored dev.staging.qualys.com as 4.0/5.0)
- 46% JSON parsing failures
- 2,000-5,000ms per domain (vs <10ms for rules)
- Non-deterministic results
- Hallucinated reasoning

**Verdict:** Rule-based approach is 100x faster and 100% accurate

### Rejected: HTTP Response Semantic Analysis

**Files:**
- `semantic-criticality-from-http-response.md` - Design doc
- `using-http-response-for-criticality.md` - Implementation guide
- `asset-criticality-from-http.md` - HTTP data extraction

**Why rejected:**
- False positives from privacy policies (PII keywords in cookie banners)
- Footer links trigger "admin" detection
- Marketing sites scored HIGHER instead of lower (www.qualys.com: 3.6 → 5.0)
- 90% of adjustments were increases (wrong direction)
- Duplicates what Nuclei templates already detect

**Verdict:** Domain patterns + page title + Nuclei findings are sufficient

### Research/Parking Lot

**Files:**
- `probability-approaches.md` - 6 different breach probability approaches (decision pending)
- `exploitability-scoring.md` - EPSS/KEV/CVSS research (future work)
- `domain-compromise-prediction.md` - Initial research (superseded)

**Status:** May revisit for future enhancements

## What We Actually Use

See parent directory for approved approach:
- `rule-based-criticality-scoring.md` - Domain + title + findings
- `complete-risk-implementation-plan.md` - Full implementation
- `why-not-http-semantic-analysis.md` - Explanation of rejection

## DO NOT USE

Files in this archive are for **reference only** to avoid repeating failed experiments.

**Date Archived:** October 17, 2025
