# Dependabot Vulnerability Status

## Summary

This document tracks the status of Dependabot security alerts and explains why some cannot be immediately resolved.

## Resolved Alerts

### ✅ Alert #5: nwaples/rardecode/v2 DoS (Medium)
- **Status**: Mitigated
- **Action**: Forced upgrade to v2.0.0+ via go.mod replace directive
- **Impact**: DoS vulnerability in RAR decompression patched

## Unresolved Alerts (Cannot Fix)

### ⚠️ Alert #3: mholt/archiver Path Traversal (High)
- **Status**: Cannot fix - deprecated package
- **Package**: github.com/mholt/archiver v3.1.1
- **Reason**:
  - Transitive dependency from projectdiscovery/nuclei SDK
  - Package deprecated by maintainer (no patches available)
  - Nuclei SDK has not migrated to maintained alternatives
- **Risk Assessment**: **LOW**
  - This tool does not use archive extraction features
  - Nuclei SDK uses it internally for template packaging only
  - No user-controlled archive processing
  - Path traversal requires malicious archive files (not applicable)
- **Mitigation**: Archive functionality not exposed in API surface

### ⚠️ Alert #2: mholt/archiver Path Traversal (Medium)
- **Status**: Cannot fix - same as #3
- **Duplicate of Alert #3**

### ⚠️ Alert #1: mholt/archiver Path Traversal (Medium)
- **Status**: Cannot fix - same as #3
- **Patched version**: v3.3.2 incompatible with current codebase
- **Note**: Even v3.3.2 is still vulnerable (alerts #2 and #3)

### ⚠️ Alert #4: go-pg/pg SQL Injection (Medium)
- **Status**: Cannot fix - deprecated package
- **Package**: github.com/go-pg/pg v8.0.7
- **Reason**:
  - Transitive dependency from projectdiscovery libraries
  - Package deprecated (maintainer moved to v10+, breaking API changes)
  - No patch available for v8.x line
- **Risk Assessment**: **NONE**
  - This tool does not use any database functionality
  - SQL operations not exposed in usage
  - go-pg pulled transitively but never invoked
- **Mitigation**: SQL functionality not used

## Upstream Dependency Issues

These vulnerabilities exist in the projectdiscovery/nuclei SDK v3.3.5 dependencies:
- `github.com/projectdiscovery/asnmap` → mholt/archiver/v3
- `github.com/projectdiscovery/cdncheck` → mholt/archiver/v3
- `github.com/projectdiscovery/chaos-client` → mholt/archiver/v3
- `github.com/projectdiscovery/dnsx` → mholt/archiver/v3
- `github.com/projectdiscovery/httpx` → mholt/archiver/v3
- `github.com/projectdiscovery/interactsh` → mholt/archiver/v3

**Waiting for**: ProjectDiscovery to migrate to maintained alternatives like:
- github.com/mholt/archives (replacement for archiver)
- Modern archive libraries with active maintenance

## Actions Taken

1. ✅ Upgraded nwaples/rardecode/v2 to patched version
2. ✅ Documented vulnerability scope and risk assessment
3. ✅ Confirmed vulnerable code paths not used
4. ✅ Monitored upstream for fixes

## Monitoring

- **GitHub Security Advisory**: Enabled
- **Dependabot**: Active (weekly checks)
- **OSSF Scorecard**: Tracking security posture
- **Action**: Will update immediately when upstream fixes available

## Risk Mitigation Strategy

Since vulnerable packages are:
1. Not directly used by this codebase
2. Only transitively included via nuclei SDK
3. Their vulnerable functionality not exposed
4. No user input processed by vulnerable code paths

**Overall Risk**: **LOW to NEGLIGIBLE**

We are monitoring:
- ProjectDiscovery nuclei repository for dependency updates
- Security advisories for new vulnerabilities
- Alternative SDK options if issues persist

## References

- Dependabot Alerts: https://github.com/valllabh/web-exposure-detection/security/dependabot
- mholt/archiver deprecation: https://github.com/mholt/archiver/issues/328
- go-pg migration guide: https://github.com/go-pg/pg#status
- ProjectDiscovery nuclei: https://github.com/projectdiscovery/nuclei

## Last Updated

2025-10-15 - Initial assessment
