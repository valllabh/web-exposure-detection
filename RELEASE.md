# Release Process

This document describes the release process for web-exposure-detection using GoReleaser and GitHub Actions.

## Automated Release Process

### 1. Create a Release

```bash
# Create and push a new tag
git tag v1.0.0
git push origin v1.0.0
```

### 2. GitHub Actions Workflow

The release workflow (`.github/workflows/release.yml`) will automatically:

1. **Build** binaries for:
   - Linux (amd64, arm64)
   - macOS (amd64, arm64, universal binary)

2. **Create** a GitHub release with:
   - Changelog generation
   - Binary assets
   - Checksums for verification

3. **Publish** the release on GitHub

## Supported Platforms

| OS | Architecture | Binary Name |
|---|---|---|
| Linux | x86_64 | `web-exposure-detection_Linux_x86_64.tar.gz` |
| Linux | arm64 | `web-exposure-detection_Linux_arm64.tar.gz` |
| macOS | x86_64 | `web-exposure-detection_Darwin_x86_64.tar.gz` |
| macOS | arm64 | `web-exposure-detection_Darwin_arm64.tar.gz` |
| macOS | universal | `web-exposure-detection_Darwin_universal.tar.gz` |

## Local Testing

Test the release configuration locally before pushing:

```bash
# Test GoReleaser configuration
./scripts/test-release.sh

# Or manually:
goreleaser check
goreleaser release --snapshot --clean
```

## Installation Instructions

### Linux
```bash
# Download and install
curl -sL https://github.com/valllabh/web-exposure-detection/releases/latest/download/web-exposure-detection_Linux_x86_64.tar.gz | tar xz
sudo mv web-exposure-detection /usr/local/bin/
```

### macOS
```bash
# Download and install
curl -sL https://github.com/valllabh/web-exposure-detection/releases/latest/download/web-exposure-detection_Darwin_universal.tar.gz | tar xz
sudo mv web-exposure-detection /usr/local/bin/
```

### Verify Installation
```bash
web-exposure-detection --help
```

## Release Features

- ✅ **Cross-platform builds** (Linux, macOS)
- ✅ **Multiple architectures** (x86_64, arm64)
- ✅ **Universal macOS binaries**
- ✅ **Embedded dependencies** (no external files needed)
- ✅ **Automated changelog generation**
- ✅ **Checksum verification**
- ✅ **Semantic versioning**

## Troubleshooting

### Build Issues

1. **Check Go version compatibility**
   ```bash
   go version  # Should be 1.21+
   ```

2. **Verify all dependencies are embedded**
   ```bash
   make build
   ./bin/web-exposure-detection scan --help  # Should work without external files
   ```

3. **Test locally before release**
   ```bash
   ./scripts/test-release.sh
   ```

### Release Issues

1. **Check GitHub Actions logs**
   - Go to: https://github.com/valllabh/web-exposure-detection/actions

2. **Verify tag format**
   ```bash
   git tag --list | grep v1  # Should show tags like v1.0.0
   ```

3. **Check GoReleaser config**
   ```bash
   goreleaser check
   ```

## Version Schema

We follow [Semantic Versioning](https://semver.org/):

- **v1.0.0** - Major release
- **v1.1.0** - Minor release (new features)
- **v1.0.1** - Patch release (bug fixes)

## Changelog

Automatic changelog generation includes:
- ✅ Features (`feat:`)
- ✅ Bug fixes (`fix:` or `bug:`)
- ✅ Enhancements (`enhance:`, `improve:`)
- ❌ Excluded: `docs:`, `test:`, `chore:`, `ci:`