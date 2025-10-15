# Development Guide

## Prerequisites

- Go 1.21 or later
- Make (for build automation)

## Development Commands

All development tasks are managed through the Makefile. Reference it for available commands:

- `make build` - Build the binary
- `make test` - Run tests
- `make clean` - Clean build artifacts
- `make deps` - Install/update dependencies
- `make lint` - Run linters

## Running Locally

Use `go run .` to run the entire package (not `go run main.go`):

```bash
# Run help
go run . --help

# Run scan command
go run . scan example.com

# Run with options
go run . scan example.com --domain-keywords additional,keywords --force
```

**Important**: Always run the entire package with `go run .` to ensure all package files are included.

## Project Structure

```
.
├── cmd/              # CLI commands (Cobra)
├── pkg/
│   └── webexposure/  # SDK public API
├── internal/         # Private implementation
├── scan-templates/   # Nuclei templates (embedded)
├── templates/        # Report templates (embedded)
├── docs/             # Documentation
├── ref/              # Reference bash implementation
└── embed.go          # Embedded file systems
```

## Testing

```bash
# Run all tests
make test

# Run with coverage
go test -cover ./...

# Run specific package
go test ./pkg/webexposure
```

## Updating CVE Statistics

Update CVE data for findings:

```bash
make update-cve-stats
```

See [how-to-write-nuclei-template.md](./how-to-write-nuclei-template.md#cve-statistics) for details.

## Adding Features

1. Implement in SDK (`pkg/webexposure`) first
2. Add CLI facade in `cmd/`
3. Update relevant docs in `docs/`
4. Add tests
5. Update CLAUDE.md references if needed

## Embedded Resources

When adding/modifying embedded resources:

1. Add files to appropriate directory (`scan-templates/`, `templates/`)
2. Verify `embed.go` includes the path
3. Rebuild to embed new files

## Code Style

- Follow standard Go conventions
- Use `make lint` before committing
- Keep SDK and CLI concerns separated
- Document exported functions
