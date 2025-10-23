# Archive - Rejected Implementation Scripts

**Status:** NOT FOR USE
**Purpose:** Historical record of failed experiments

## Contents

Scripts that implement **rejected approaches** - kept for reference only.

### AI/LLM Testing Scripts

- `test-ai-criticality.py` - Single model test (llama3.2:3b)
- `test-ai-criticality-multi.py` - Multi-model comparison
- `ai-criticality-test-results.json` - Test results

**Result:** All AI models failed with 0% dev/test detection accuracy

### Semantic Analysis Scripts

- `semantic-criticality-analysis.py` - HTTP body text analysis

**Result:** 90% false positives from privacy policies and footer links

## Use Instead

**Production scripts:**
- `calculate-criticality-from-jsonl.py` - Rule-based scoring (APPROVED)
- `analyze-single-domain.py` - Single domain analysis (APPROVED)
- `calculate-criticality-rules.py` - Test data scoring (APPROVED)

## DO NOT USE

Scripts in this archive are **experiments that failed**. Do not use in production.

**Date Archived:** October 17, 2025
