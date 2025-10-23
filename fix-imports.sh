#!/bin/bash

# Script to add missing imports to all packages

# criticality package - needs webexposure for GetLogger, findings for NewFindingItem
cat > pkg/webexposure/criticality/init.go <<'EOF'
package criticality

import (
	"github.com/valllabh/web-exposure-detection/pkg/webexposure/findings"
	"github.com/projectdiscovery/gologger"
)

// GetLogger returns the shared logger instance
func GetLogger() *gologger.Logger {
	return gologger.DefaultLogger
}

// NewFindingItem creates a new finding item (re-export from findings package)
var NewFindingItem = findings.NewFindingItem
EOF

# findings package - needs webexposure for GetLogger
cat > pkg/webexposure/findings/init.go <<'EOF'
package findings

import (
	"github.com/projectdiscovery/gologger"
)

// GetLogger returns the shared logger instance
func GetLogger() *gologger.Logger {
	return gologger.DefaultLogger
}
EOF

# industry package - needs webexposure for GetLogger
cat > pkg/webexposure/industry/init.go <<'EOF'
package industry

import (
	"github.com/projectdiscovery/gologger"
)

// GetLogger returns the shared logger instance
func GetLogger() *gologger.Logger {
	return gologger.DefaultLogger
}
EOF

# dsl package - needs webexposure for GetLogger
cat > pkg/webexposure/dsl/init.go <<'EOF'
package dsl

import (
	"github.com/projectdiscovery/gologger"
)

// GetLogger returns the shared logger instance
func GetLogger() *gologger.Logger {
	return gologger.DefaultLogger
}
EOF

# nuclei package - needs webexposure for GetLogger
cat > pkg/webexposure/nuclei/init.go <<'EOF'
package nuclei

import (
	"github.com/projectdiscovery/gologger"
)

// GetLogger returns the shared logger instance
func GetLogger() *gologger.Logger {
	return gologger.DefaultLogger
}
EOF

# pdf package - needs webexposure for GetLogger
cat > pkg/webexposure/report/pdf/init.go <<'EOF'
package pdf

import (
	"github.com/projectdiscovery/gologger"
)

// GetLogger returns the shared logger instance
func GetLogger() *gologger.Logger {
	return gologger.DefaultLogger
}
EOF

echo "Import helpers created"
