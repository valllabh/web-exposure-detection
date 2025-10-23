# Research Documentation

**Status:** Active - Criticality Scoring & Financial Risk Quantification

## Quick Start

**Implementation Ready:** See `complete-risk-implementation-plan.md` for full design

## Active Research

### Criticality Scoring (Stage 3)

**Status:** Design Complete - Ready for Go Implementation

**Key Documents:**
- **`complete-risk-implementation-plan.md`** - Complete implementation guide (START HERE)
- `criticality-integration-plan.md` - Go code integration details
- `criticality-scoring-final-recommendation.md` - Final design decision
- `rule-based-criticality-scoring.md` - Algorithm specification
- `rule-scoring-test-results.md` - Validation on real data
- `poc-rule-based-criticality-results.md` - POC results (11 test domains)
- `jsonl-criticality-scoring-implementation.md` - JSONL processing guide
- `test-data-for-rules.json` - Test dataset
- `README-criticality-scoring.md` - Quick reference

**Approach:** Rule-based scoring using domain patterns + page titles + Nuclei findings

**Results:** 100% dev/test detection accuracy, <10ms per domain

### Financial Risk Quantification (Stage 4)

**Status:** Design Complete - Ready for Implementation

**Key Documents:**
- `financial-risk-quantification.md` - EAL calculation model
- `asset-value-determination.md` - Asset value methodology
- `POC-qualys-financial-risk.md` - Real POC calculations on qualys.com
- `README-financial-risk.md` - Quick reference

**Formula:** `EAL = Compromise_Probability × Breach_Cost × Asset_Multiplier`

**Industry Costs:** Healthcare $10.93M, Financial $5.90M, Technology $4.88M

### Web Application Classification (New)

**Status:** Research Complete - Ready for Template Development

**Key Documents:**
- `webapp-classification-patterns.md` - Comprehensive webapp type detection patterns

**Purpose:** Enhance criticality scoring with business function context

**Webapp Types Identified:**
- E-commerce (HIGH: +1.3)
- SaaS Dashboard (HIGH: +1.2)
- Admin Panel (CRITICAL: +1.8)
- Customer Portal (HIGH: +0.9)
- Developer Portal (MEDIUM: +0.7)
- Payment Processing (CRITICAL: +2.0)
- Auth Service (CRITICAL: +1.5)
- DevOps Infrastructure (CRITICAL: +1.5)
- Blog/Corporate/Landing (LOW: +0.0 to +0.1)
- Documentation (LOW: +0.1)

**Detection Methods:** HTTP headers, HTML keywords, meta tags, URL patterns, tech stack fingerprints

**Multi-Classification:** Supported (e.g., e-commerce + blog + corporate)

**Next Steps:** Create webapp-type-detection.yaml Nuclei template

### Industry Classification (New)

**Status:** OpenRouter Integration Complete - Workflow Integration Pending

**Key Documents:**
- `industry-detection-api.md` - API provider research and integration design
- `industry-classification-prompt.md` - OpenRouter preset prompt specification

**Purpose:** Classify domains by industry vertical for enhanced criticality scoring and compliance detection

**Implementation:**
- `pkg/webexposure/industry_types.go` - IndustryClassifier interface
- `pkg/webexposure/industry_api.go` - OpenRouter integration
- `.web-exposure-detection.yaml.example` - Config file template

**Supported Features:**
- 20 fixed industry categories (Healthcare, Financial Services, Technology, etc.)
- Sub-industry classification (specific business niche)
- Compliance framework detection (HIPAA, PCI DSS, GDPR, SOC 2)
- Structured JSON output via OpenRouter preset

**API Provider:** OpenRouter with llama-3.2-3b-instruct (cost effective)

**CLI Command:**
```bash
# Test industry classification
export OPENROUTER_API_KEY="sk-or-v1-..."
./bin/web-exposure-detection classify example.com
```

**Next Steps:**
1. Integrate into scan workflow
2. Add industry findings to findings.json
3. Update report types and generation
4. Add caching support

### Important Reference

- `why-not-http-semantic-analysis.md` - Why we rejected HTTP body text analysis
- `webapp-classification-patterns.md` - Webapp type detection for criticality scoring

## Archived Research

**`archive-rejected/`** - Rejected approaches (DO NOT USE)

**Contents:**
- AI/LLM approaches (0% accuracy, 2,000-5,000ms per domain)
- HTTP semantic analysis (90% false positives)
- Probability approaches (parking lot)
- Initial domain prediction research

**See:** `archive-rejected/README.md` for details

## Implementation Timeline

**Week 1-2:** Criticality scoring (Stage 3)
- Create `pkg/webexposure/criticality.go`
- Integrate into report processing
- Unit tests

**Week 3-4:** Financial risk (Stage 4)
- Create `pkg/webexposure/financial_risk.go`
- Add `--industry` CLI flag
- Integration tests

**Week 5:** Reporting
- Update HTML templates
- Add risk visualizations
- CSS for badges

**Week 6:** Testing & documentation

## Python POC Scripts

**Production Ready:**
- `scripts/calculate-criticality-from-jsonl.py` - Bulk domain scoring
- `scripts/analyze-single-domain.py` - Single domain analysis
- `scripts/calculate-criticality-rules.py` - Test data validation

**Archived (Rejected):**
- `scripts/archive-rejected/` - Failed experiments (AI, semantic analysis)

## Usage Example

```bash
# Scan with criticality + financial risk
./bin/web-exposure-detection scan example.com --industry healthcare

# Output includes:
# - Criticality score (0.1-5.0) per domain
# - Expected Annual Loss (EAL) in dollars
# - Portfolio total risk
# - Risk-based prioritization
```

## Research Status

| Feature | Status | Files |
|---------|--------|-------|
| Criticality Scoring | ✅ Design Complete | complete-risk-implementation-plan.md |
| Financial Risk | ✅ Design Complete | complete-risk-implementation-plan.md |
| Go Implementation | 🟡 Pending | criticality-integration-plan.md |
| AI Approaches | ❌ Rejected | archive-rejected/ |
| Semantic Analysis | ❌ Rejected | archive-rejected/ |

## Decision Records

**What Works:**
- ✅ Domain name patterns (100% dev/test detection)
- ✅ Page title keywords (reliable indicator)
- ✅ Nuclei findings (comprehensive, no duplication)
- ✅ Rule-based approach (fast, accurate, explainable)

**What Doesn't Work:**
- ❌ AI/LLM models (0% accuracy, slow, non-deterministic)
- ❌ HTTP body text analysis (false positives from privacy policies)
- ❌ Semantic keyword matching (conflicting signals)

## Contributing

When adding research:
1. Create descriptive filename
2. Include executive summary
3. Document alternatives
4. Provide clear recommendations
5. Update this README

## References

- IBM Cost of Data Breach Report 2024
- qualys.com scan results (295 domains)
- Test validation on 11 sample domains

---

**Last Updated:** October 17, 2025
**Next Step:** Go implementation (Week 1-6 timeline)
