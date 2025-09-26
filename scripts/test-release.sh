#!/bin/bash
set -e

echo "🧪 Testing GoReleaser configuration..."

# Check if goreleaser is installed
if ! command -v goreleaser &> /dev/null; then
    echo "📦 Installing GoReleaser..."
    go install github.com/goreleaser/goreleaser@latest
fi

# Test the configuration without releasing
echo "🔧 Testing GoReleaser config..."
goreleaser check

# Build a snapshot (local test build)
echo "🏗️ Building snapshot release..."
goreleaser release --snapshot --clean

echo "✅ Test release completed!"
echo "📁 Check dist/ directory for built binaries"
echo ""
echo "Built binaries:"
find dist/ -name "web-exposure-detection*" -type f | head -10

echo ""
echo "To create a real release:"
echo "1. git tag v0.1.0"
echo "2. git push origin v0.1.0"
echo "3. GitHub Actions will automatically build and release"