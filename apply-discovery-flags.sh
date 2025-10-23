#!/bin/bash
set -e

echo "Applying discovery flags implementation..."

# File 1: Update pkg/webexposure/scanner/discovery.go - Update DiscoverDomains signature
echo "1. Updating discovery.go DiscoverDomains function..."
cat > /tmp/discovery_patch1.txt << 'EOF'
// DiscoverDomains discovers subdomains using domain-scan SDK
func (s *scanner) DiscoverDomains(domains []string, keywords []string, skipPassive bool, skipCertificate bool) ([]string, error) {
	log := logger.GetLogger()
	log.Debug().Msgf("DiscoverDomains called: domains=%v, keywords=%v, skipPassive=%v, skipCertificate=%v", domains, keywords, skipPassive, skipCertificate)
EOF

sed -i.bak '20s/.*/func (s *scanner) DiscoverDomains(domains []string, keywords []string, skipPassive bool, skipCertificate bool) ([]string, error) {/' pkg/webexposure/scanner/discovery.go
sed -i.bak '22s/.*/	log.Debug().Msgf("DiscoverDomains called: domains=%v, keywords=%v, skipPassive=%v, skipCertificate=%v", domains, keywords, skipPassive, skipCertificate)/' pkg/webexposure/scanner/discovery.go

# File 1: Update discovery.go - Configure domain-scan SDK with skip flags
echo "2. Updating discovery.go SDK configuration..."
sed -i.bak '/config.Keywords = keywords/a\
\
	// Apply discovery skip flags\
	config.Discovery.EnablePassive = !skipPassive\
	config.Discovery.EnableCertificate = !skipCertificate\
\
	log.Debug().Msgf("Discovery config: passive=%v, certificate=%v", config.Discovery.EnablePassive, config.Discovery.EnableCertificate)
' pkg/webexposure/scanner/discovery.go

# File 2: Update pkg/webexposure/scanner/discovery.go - DiscoverDomainsWithProtocol signature
echo "3. Updating DiscoverDomainsWithProtocol function..."
sed -i.bak 's/func (s \*scanner) DiscoverDomainsWithProtocol(domains \[\]string, keywords \[\]string)/func (s *scanner) DiscoverDomainsWithProtocol(domains []string, keywords []string, skipPassive bool, skipCertificate bool)/' pkg/webexposure/scanner/discovery.go

# Find line with "return s.DiscoverDomains(domains, keywords)" and add skip params
sed -i.bak 's/return s.DiscoverDomains(domains, keywords)/return s.DiscoverDomains(domains, keywords, skipPassive, skipCertificate)/' pkg/webexposure/scanner/discovery.go

# File 3: Update pkg/webexposure/scanner/scanner.go - ScanWithPreset signature
echo "4. Updating scanner.go ScanWithPreset function..."
sed -i.bak 's/func (s \*scanner) ScanWithPreset(domains \[\]string, keywords \[\]string, templates \[\]string, force bool, preset common.ScanPreset, skipDiscovery bool)/func (s *scanner) ScanWithPreset(domains []string, keywords []string, templates []string, force bool, preset common.ScanPreset, skipDiscoveryAll bool, skipDiscoveryPassive bool, skipDiscoveryCertificate bool)/' pkg/webexposure/scanner/scanner.go

# File 3: Update scanner.go - Update skipDiscovery logic
echo "5. Updating scanner.go discovery skip logic..."
cat > /tmp/scanner_discovery_logic.txt << 'EOF'
	// Handle discovery based on skip flags
	var discoveredDomains map[string]*domainscan.DomainEntry
	var err error

	if skipDiscoveryAll {
		// Skip all discovery - use only provided domains
		log.Info().Msg("Skipping domain discovery (--skip-discovery-all enabled)")
		discoveredDomains = make(map[string]*domainscan.DomainEntry)
		for _, domain := range domains {
			httpsURL := "https://" + domain
			discoveredDomains[httpsURL] = &domainscan.DomainEntry{
				Domain:   domain,
				Protocol: "https",
			}
		}
	} else if skipDiscoveryPassive && skipDiscoveryCertificate {
		// Both passive and certificate skipped - equivalent to skip-all
		log.Info().Msg("Skipping domain discovery (both passive and certificate disabled)")
		discoveredDomains = make(map[string]*domainscan.DomainEntry)
		for _, domain := range domains {
			httpsURL := "https://" + domain
			discoveredDomains[httpsURL] = &domainscan.DomainEntry{
				Domain:   domain,
				Protocol: "https",
			}
		}
	} else {
		// Run discovery with selected methods
		log.Info().Msgf("Running domain discovery (passive=%v, certificate=%v)", !skipDiscoveryPassive, !skipDiscoveryCertificate)
		discoveredDomains, err = s.DiscoverDomainsWithProtocol(domains, keywords, skipDiscoveryPassive, skipDiscoveryCertificate)
		if err != nil {
			return fmt.Errorf("domain discovery failed: %w", err)
		}
	}
EOF

# This is complex, so we'll provide manual instructions for this part
echo ""
echo "⚠️  MANUAL STEP REQUIRED:"
echo "In pkg/webexposure/scanner/scanner.go, find the section that checks 'if skipDiscovery'"
echo "Replace it with the logic from /tmp/scanner_discovery_logic.txt"
echo ""
echo "Search for: 'if skipDiscovery {'"
echo "And replace the entire if-else block with the content of /tmp/scanner_discovery_logic.txt"
echo ""

# File 4: Update pkg/webexposure/scanner/scanner.go - Update Scan() method
echo "6. Updating Scan() method to pass skip flags..."
echo "⚠️  MANUAL STEP: In Scan() method, update the call:"
echo "    return s.ScanWithPreset(domains, keywords, nil, false, common.PresetSlow, false, false, false)"
echo ""

# File 5: Update pkg/webexposure/scanner/scanner.go - Update ScanWithOptions() method
echo "7. Updating ScanWithOptions() method to pass skip flags..."
echo "⚠️  MANUAL STEP: In ScanWithOptions() method, update the call:"
echo "    return s.ScanWithPreset(domains, keywords, templates, force, common.PresetSlow, false, false, false)"
echo ""

# File 6: Update pkg/webexposure/scanner/scanner.go - Update RunDiscoveryOnly() method
echo "8. Updating RunDiscoveryOnly() method..."
echo "⚠️  MANUAL STEP: In RunDiscoveryOnly() method, update the call:"
echo "    Change: discoveredDomains, err := s.DiscoverDomainsWithProtocol(domains, keywords)"
echo "    To:     discoveredDomains, err := s.DiscoverDomainsWithProtocol(domains, keywords, false, false)"
echo ""

echo "Automated changes complete. Please review the manual steps above."
echo ""
echo "Backup files created with .bak extension"
