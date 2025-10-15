# SLSA Supply Chain Security

This project implements SLSA (Supply-chain Levels for Software Artifacts) Level 3 compliance for enhanced supply chain security.

## Overview

SLSA is a security framework developed by Google to ensure the integrity of software artifacts throughout the supply chain. This project achieves SLSA Level 3 through:

1. **Build Provenance** - Cryptographic attestation of build process
2. **Source Integrity** - Verification of source code authenticity
3. **Build Isolation** - Builds run in ephemeral, isolated environments
4. **Artifact Signing** - All releases signed with cosign

## Components

### 1. SBOM (Software Bill of Materials)

Generated in two formats:
- **SPDX** (`sbom.spdx.json`) - ISO/IEC 5962:2021 standard
- **CycloneDX** (`sbom.cyclonedx.json`) - OWASP standard

Includes complete dependency tree with:
- Package names and versions
- License information
- Package relationships
- Vulnerability data

### 2. VEX (Vulnerability Exploitability eXchange)

OpenVEX document (`.vex.yaml`) provides:
- Vulnerability impact assessments
- Exploitability analysis
- Justification for not affected vulnerabilities
- Mitigation statements

Generated automatically and attached to releases.

### 3. SLSA Build Workflow

`.github/workflows/slsa.yml` - Generates SLSA provenance for releases:
- Uses official SLSA GitHub Generator
- Creates provenance attestation (`.intoto.jsonl`)
- Multi-platform builds (Linux, macOS, Windows)
- Automatic upload to GitHub releases

### 2. OpenSSF Scorecard

`.github/workflows/scorecard.yml` - Monitors security best practices:
- Weekly security posture assessment
- Results uploaded to GitHub Security tab
- Tracks 18+ security checks
- Public badge available

### 3. Artifact Signing

GoReleaser configuration includes:
- **cosign** for artifact signing
- **SBOM** generation (SPDX format)
- SHA256 checksums for all artifacts
- Certificate transparency logs

## Verification

### Verify SLSA Provenance

1. Download release artifacts and provenance:
```bash
# Download binary
wget https://github.com/valllabh/web-exposure-detection/releases/download/v1.0.0/web-exposure-detection_Linux_x86_64.tar.gz

# Download provenance
wget https://github.com/valllabh/web-exposure-detection/releases/download/v1.0.0/multiple.intoto.jsonl
```

2. Install SLSA verifier:
```bash
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest
```

3. Verify the artifact:
```bash
slsa-verifier verify-artifact \
  web-exposure-detection_Linux_x86_64.tar.gz \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/valllabh/web-exposure-detection \
  --source-tag v1.0.0
```

### Verify Cosign Signature

1. Install cosign:
```bash
# macOS
brew install cosign

# Linux
wget https://github.com/sigstore/cosign/releases/download/v2.2.0/cosign-linux-amd64
chmod +x cosign-linux-amd64
sudo mv cosign-linux-amd64 /usr/local/bin/cosign
```

2. Verify signature:
```bash
cosign verify-blob \
  --certificate web-exposure-detection_Linux_x86_64.tar.gz.pem \
  --signature web-exposure-detection_Linux_x86_64.tar.gz.sig \
  --certificate-identity-regexp="^https://github.com/valllabh/web-exposure-detection" \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  web-exposure-detection_Linux_x86_64.tar.gz
```

### Verify Checksums

```bash
# Download checksums
wget https://github.com/valllabh/web-exposure-detection/releases/download/v1.0.0/checksums.txt

# Verify
sha256sum --check checksums.txt
```

## SLSA Level 3 Requirements

✅ **Build Requirements**
- Scripted build process (GoReleaser)
- Build service (GitHub Actions)
- Build as code (version controlled workflows)
- Ephemeral environment (GitHub-hosted runners)
- Isolated builds (separate jobs)

✅ **Provenance Requirements**
- Available provenance (uploaded to releases)
- Authenticated provenance (signed with Sigstore)
- Service-generated provenance (SLSA generator)
- Non-falsifiable provenance (immutable logs)
- Dependencies complete (SBOM included)

✅ **Common Requirements**
- Security policy documented
- Access controls enforced
- Superusers controlled (branch protection)

## OpenSSF Scorecard

View the security scorecard:
```bash
# Install scorecard CLI
go install github.com/ossf/scorecard/v5/cmd/scorecard@latest

# Run locally
scorecard --repo=github.com/valllabh/web-exposure-detection
```

Or view online: `https://scorecard.dev/viewer/?uri=github.com/valllabh/web-exposure-detection`

### Key Checks

The scorecard evaluates:
- **Branch Protection** - Required reviews, status checks
- **Code Review** - PRs reviewed before merge
- **Dependency Update** - Dependabot enabled
- **Signed Releases** - Artifacts signed with cosign
- **Security Policy** - SECURITY.md present
- **Vulnerabilities** - No known critical vulnerabilities
- **CI Tests** - Tests run in CI
- **Fuzzing** - Fuzz testing (if applicable)
- **Binary Artifacts** - No committed binaries
- **Dangerous Workflow** - Secure workflow patterns
- **License** - Valid open source license
- **Maintained** - Recent commits
- **Packaging** - Published packages
- **Pinned Dependencies** - Pinned action versions
- **SAST** - Static analysis enabled
- **Token Permissions** - Minimal permissions

## Supply Chain Attack Prevention

### Build Environment
- All builds run on GitHub-hosted runners
- Fresh environment for each build
- No persistent state between builds
- Network isolation enforced

### Dependency Management
- `go.mod` with exact versions
- Dependabot for security updates
- Nancy scans for vulnerable dependencies
- Trivy scans for container vulnerabilities

### Source Code
- Required code reviews for merges
- Branch protection on main branch
- Signed commits (optional but recommended)
- No direct pushes to main

### Release Process
1. Tag creation triggers release workflow
2. Build in isolated GitHub Actions runner
3. SLSA provenance generated automatically
4. Artifacts signed with cosign
5. SBOM generated (SPDX format)
6. All uploaded to GitHub release

## Integration with CI/CD

### For Consumers

If you're consuming this tool in your CI/CD:

```yaml
- name: Download and verify
  run: |
    # Download binary and provenance
    VERSION=v1.0.0
    wget https://github.com/valllabh/web-exposure-detection/releases/download/${VERSION}/web-exposure-detection_Linux_x86_64.tar.gz
    wget https://github.com/valllabh/web-exposure-detection/releases/download/${VERSION}/multiple.intoto.jsonl

    # Verify with SLSA verifier
    slsa-verifier verify-artifact \
      web-exposure-detection_Linux_x86_64.tar.gz \
      --provenance-path multiple.intoto.jsonl \
      --source-uri github.com/valllabh/web-exposure-detection \
      --source-tag ${VERSION}

    # Extract and use
    tar xzf web-exposure-detection_Linux_x86_64.tar.gz
    ./web-exposure-detection --version
```

## Continuous Improvement

### Current Status: SLSA Level 3

Future enhancements for Level 4:
- Two-person review required for releases
- Hermetic builds with zero network access
- Reproducible builds across environments
- Extended retention of provenance data

## Resources

- [SLSA Framework](https://slsa.dev/)
- [SLSA GitHub Generator](https://github.com/slsa-framework/slsa-github-generator)
- [OpenSSF Scorecard](https://github.com/ossf/scorecard)
- [Sigstore Cosign](https://github.com/sigstore/cosign)
- [SPDX SBOM](https://spdx.dev/)
- [in-toto Attestations](https://in-toto.io/)

## Support

For questions or issues with SLSA verification:
- Open an issue on GitHub
- Tag with `supply-chain` or `security`
- Include verification output and error messages
