# How Qualys TotalAppSec External Application Discovery Works

Discover what attackers can see about your organization's web presence.

## Comprehensive Web Asset Discovery

Qualys TotalAppSec External Application Discovery automatically identifies your organization's publicly exposed web applications and APIs, providing complete visibility into your external attack surface. Our advanced discovery engine reveals the same assets that attackers can find, helping you stay one step ahead of potential threats.

## The Three-Step Discovery Process

### Step 1: Comprehensive Subdomain Discovery

Our discovery engine uses three powerful methods to map your complete web footprint:

**Passive Discovery**
- Queries 20+ passive intelligence sources including DNS records and certificate transparency logs
- Finds subdomains from past DNS queries and SSL certificates
- No direct contact with your systems

**SSL Certificate Analysis**
- Examines Subject Alternative Names (SANs) in SSL certificates
- Discovers additional subdomains not found through DNS
- Uses keyword filtering to focus on your organization (e.g., only keeps subdomains containing "company-name" when scanning company.com)

**Live Service Verification**
- Tests discovered subdomains to confirm they're actually running
- Checks multiple ports (HTTP/HTTPS) to verify accessibility
- Returns only active, reachable services

### Step 2: Advanced Application and API Scanning

With your live assets identified, our security engine analyzes each service to discover external footprints that attackers can see:

**Web Applications**
- Login pages and admin panels
- E-commerce platforms
- Content management systems
- Customer portals

**API Endpoints**
- REST APIs serving JSON/XML
- API documentation (Swagger, OpenAPI)
- Legacy SOAP services
- API gateways

**Technology Footprints**
- Web servers (nginx, Apache)
- Programming frameworks (React, Angular, WordPress)
- CDNs and security tools

### Step 3: Intelligent Classification and Risk Assessment

Our classification engine looks at the signals and intelligently categorizes each discovered asset:

**Confirmed API Endpoint** (Red Circle)
- Actively serving JSON/XML data
- High confidence this is an API

**Potential API Endpoint** (Yellow Circle)
- Has API documentation or API-related URLs
- Shows API characteristics but not confirmed

**Web Application**
- Traditional websites with forms, content, or user interfaces
- May use APIs internally

## Conclusion

Qualys TotalAppSec External Application Discovery provides comprehensive visibility into your organization's external attack surface by systematically discovering and analyzing all publicly exposed web assets. Our intelligent discovery engine reveals the same information that attackers can find, enabling you to proactively secure your web presence. With detailed classification and technology footprinting, you gain the insights needed to reduce risk and strengthen your security posture.

