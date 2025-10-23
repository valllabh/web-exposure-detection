# Web Application Classification Patterns for Asset Criticality Scoring

**Purpose**: Comprehensive research on webapp type detection patterns to enhance asset criticality scoring in defensive security tool.

**Date**: 2025-10-18

**Status**: Research Complete

## Executive Summary

Web applications can be classified into distinct types based on detectable patterns in HTTP headers, HTML content, meta tags, URL structures, and technology stacks. This classification enhances asset criticality scoring by identifying business function and risk context.

**Key Finding**: Multi-classification is common (e.g., e-commerce + blog). Detection should support multiple simultaneous webapp types per domain.

## 1. Web Application Type Taxonomy

### 1.1 Primary Categories (Hierarchical)

```
WEBAPP TYPES
├── E-COMMERCE
│   ├── B2C Retail (Shopify, WooCommerce)
│   ├── B2B Marketplace
│   ├── Digital Products
│   └── Subscription Commerce
│
├── SAAS APPLICATION
│   ├── Productivity Tools
│   ├── Project Management
│   ├── CRM/Sales
│   ├── Analytics Platform
│   └── Collaboration Tools
│
├── PORTAL/DASHBOARD
│   ├── Admin Panel
│   ├── Customer Portal
│   ├── Developer Portal
│   ├── Partner Portal
│   └── Employee Portal
│
├── AUTHENTICATION SERVICE
│   ├── SSO/SAML Provider
│   ├── OAuth/OIDC Server
│   ├── Identity Provider (IdP)
│   └── Login Gateway
│
├── PAYMENT PROCESSING
│   ├── Payment Gateway
│   ├── Checkout System
│   ├── Billing Portal
│   └── Subscription Management
│
├── CONTENT SITES
│   ├── Corporate Website
│   ├── Marketing Landing Page
│   ├── Blog/Publication
│   ├── Documentation Site
│   └── Knowledge Base
│
├── API/DEVELOPER
│   ├── REST API Endpoint
│   ├── GraphQL API
│   ├── Developer Console
│   └── API Documentation
│
├── INFRASTRUCTURE
│   ├── DevOps Tools (Jenkins, GitLab, ArgoCD)
│   ├── Container Registry
│   ├── Artifact Repository
│   └── CI/CD Pipeline
│
├── SECURITY
│   ├── VPN Gateway
│   ├── Vault/Secrets Manager
│   └── Security Gateway
│
└── MOBILE/PWA
    ├── Mobile Web App
    ├── Progressive Web App
    └── Mobile API Backend
```

### 1.2 Classification Dimensions

Each webapp can be classified across multiple dimensions:

1. **Business Function**: E-commerce, SaaS, Portal, Content, etc.
2. **User Audience**: Public, Customer, Partner, Employee, Developer, Admin
3. **Interaction Model**: Transactional, Informational, Service-based
4. **Data Sensitivity**: Public content, PII, Financial, Corporate confidential
5. **Environment**: Production, Staging, Dev, Test, UAT, Preview, Beta, Demo

## 2. Detection Patterns by Webapp Type

### 2.1 E-COMMERCE

**Criticality Impact**: HIGH to CRITICAL (handles payments, customer PII, transactions)

#### HTTP Headers
```
X-Shopify-Stage: production
X-Wc-Store-Api: true
X-Ecommerce-Platform: WooCommerce|Shopify|Magento
```

#### HTML Body Keywords
```
High Confidence:
- "add to cart", "shopping cart", "checkout", "buy now"
- "product-grid", "cart-summary", "order-total"
- class="product-card", class="cart-items"
- id="checkout-form", id="payment-method"

Medium Confidence:
- "price", "$", "€", "£" (with product context)
- "quantity", "size", "color" (variant selectors)
- "shipping", "delivery"
- "my orders", "order history"
```

#### Meta Tags
```html
<meta property="og:type" content="product">
<meta name="product:price:amount">
<meta name="product:availability">
<meta name="shopify-checkout-api-token">
```

#### URL Patterns
```
/cart, /checkout, /products/*, /shop/*, /store/*
/my-account/orders, /order-tracking
/payment, /billing
```

#### Technology Stack Fingerprints
```
Shopify: window.Shopify, cdn.shopify.com
WooCommerce: woocommerce.js, wc-cart-fragments
Magento: Mage.Cookies, mage/cookies
Stripe: js.stripe.com, pk_live_*, pk_test_*
PayPal: paypal.com/sdk/js, paypal-button
```

#### JSON-LD Schema
```json
{
  "@type": "Product",
  "offers": {
    "@type": "Offer",
    "price": "29.99",
    "priceCurrency": "USD"
  }
}
```

### 2.2 SAAS APPLICATION / DASHBOARD

**Criticality Impact**: HIGH to CRITICAL (business operations, data access, user accounts)

#### HTML Body Keywords
```
High Confidence:
- "dashboard", "account settings", "user profile"
- class="sidebar-nav", class="main-dashboard"
- "subscription", "billing plan", "upgrade account"
- "team members", "invite user", "permissions"
- data-controller="dashboard", data-nav="app"

Medium Confidence:
- "workspace", "project", "activity feed"
- "notifications", "recent activity"
- user dropdown with logout, settings, profile
```

#### Navigation Patterns
```html
<!-- Sidebar with app sections -->
<nav class="app-sidebar">
  <a href="/dashboard">Dashboard</a>
  <a href="/projects">Projects</a>
  <a href="/settings">Settings</a>
  <a href="/billing">Billing</a>
</nav>

<!-- User dropdown -->
<div class="user-menu">
  <button>user@example.com</button>
  <ul>
    <li>Account Settings</li>
    <li>Billing</li>
    <li>Logout</li>
  </ul>
</div>
```

#### Technology Stack
```
React Admin Frameworks: react-admin, refine, admin-bro
Vue Dashboards: vue-element-admin, vuetify
Chart Libraries: chart.js, d3.js, recharts
State Management: redux, zustand, pinia
```

#### URL Patterns
```
/dashboard, /app/*, /console/*
/settings/*, /account/*, /profile/*
/billing, /subscription, /usage
/team/*, /workspace/*
```

### 2.3 ADMIN PANEL / CONSOLE

**Criticality Impact**: CRITICAL (privileged access, system configuration, sensitive operations)

#### HTML Body Keywords
```
High Confidence:
- "admin panel", "administration", "control panel"
- "users management", "role management", "permissions"
- "system settings", "configuration", "advanced settings"
- "logs", "audit trail", "activity log"
- class="admin-wrapper", id="admin-console"

Critical Indicators:
- "database", "SQL", "query"
- "server status", "services", "monitoring"
- "backup", "restore", "maintenance mode"
- "API keys", "webhooks", "integrations"
```

#### URL Patterns
```
/admin/*, /administrator/*, /console/*
/wp-admin/*, /cpanel/*, /phpmyadmin/*
/manage/*, /control-panel/*
/system/*, /config/*
```

#### Common Admin Frameworks
```
WordPress: wp-admin, adminimize
Django Admin: /admin/, .field-box
Laravel Nova: /nova/, nova-resource
Flask-Admin: admin.static
phpMyAdmin: pma_*, phpMyAdmin
```

#### Detection via Login Form
```html
<form action="/admin/login">
  <input name="username" type="text">
  <input name="password" type="password">
  <label>Administrator Login</label>
</form>
```

### 2.4 CUSTOMER PORTAL

**Criticality Impact**: HIGH (customer PII, account access, support tickets, documents)

#### HTML Body Keywords
```
High Confidence:
- "customer portal", "my account", "account overview"
- "support tickets", "ticket history", "submit ticket"
- "documents", "invoices", "download invoice"
- "account details", "update profile", "change password"

Medium Confidence:
- "order history", "track order", "returns"
- "support center", "help center", "knowledge base"
- "contact support", "live chat", "raise issue"
```

#### URL Patterns
```
/customer/*, /portal/*, /my/*, /account/*
/support/tickets/*, /help-center/*
/documents/*, /invoices/*
```

#### Technology Stack
```
Zendesk: assets.zendesk.com, zd-widget
Freshdesk: freshdesk.com, freshwidget
Salesforce: force.com, salesforce.com/identity
ServiceNow: service-now.com, NOW.user
```

### 2.5 DEVELOPER PORTAL / API DOCUMENTATION

**Criticality Impact**: MEDIUM to HIGH (API access, developer credentials, OAuth apps)

#### HTML Body Keywords
```
High Confidence:
- "API Reference", "API Documentation", "API Endpoint"
- "Getting Started", "Quick Start", "Developer Guide"
- "Authentication", "OAuth", "API Key", "Access Token"
- "SDK", "Code Examples", "Sample Code"
- class="code-block", class="endpoint-path"
- "REST API", "GraphQL", "WebSocket"

Medium Confidence:
- "request", "response", "parameters"
- "rate limits", "quotas", "usage"
- "changelog", "API versioning", "deprecation"
```

#### Code Block Detection
```html
<pre><code class="language-*">
<div class="highlight">
<code data-lang="python|javascript|curl">
```

#### Navigation Structure
```
Sidebar sections:
- Getting Started
- API Reference
- Authentication
- SDKs & Libraries
- Webhooks
- Changelog
```

#### URL Patterns
```
/docs/*, /api/*, /developers/*
/reference/*, /api-reference/*
/guides/*, /tutorials/*
/sdk/*, /libraries/*
```

#### Technology Stack
```
Swagger/OpenAPI: swagger-ui, openapi.json
Redoc: redoc.standalone.js
ReadTheDocs: readthedocs.io
Docusaurus: docusaurus.io
GitBook: gitbook.io
```

### 2.6 BLOG / PUBLICATION

**Criticality Impact**: LOW to MEDIUM (content site, typically public)

#### HTML Body Keywords
```
High Confidence:
- class="post", class="article", class="blog-post"
- "published on", "posted by", "author"
- "comments", "comment section", "leave a reply"
- "categories", "tags", "related posts"
- "read more", "continue reading"

Medium Confidence:
- date formats: "Jan 15, 2025", "2025-01-15"
- "subscribe", "newsletter", "RSS feed"
- "share", social sharing buttons
```

#### Meta Tags
```html
<meta property="og:type" content="article">
<meta property="article:published_time" content="2025-01-15">
<meta property="article:author" content="...">
<meta name="twitter:card" content="summary_large_image">
```

#### RSS Feed Patterns
```
WordPress: /feed/, /rss/
Medium: /feed/@username
Tumblr: /rss
Blogger: /feeds/posts/default
Ghost: /rss/
```

#### URL Patterns
```
/blog/*, /articles/*, /posts/*
/YYYY/MM/DD/post-title
/category/*, /tag/*
/author/*
```

#### Technology Stack
```
WordPress: wp-content, wp-includes
Ghost: ghost.min.js, casper theme
Medium: medium.com/_/graphql
Substack: substackcdn.com
```

### 2.7 CORPORATE WEBSITE

**Criticality Impact**: LOW (marketing/branding, mostly public content)

#### HTML Body Keywords
```
High Confidence:
- "About Us", "Our Team", "Company"
- "Careers", "Jobs", "Join Us", "We're Hiring"
- "Contact Us", "Get in Touch", "Reach Out"
- "Investors", "Press Releases", "News Room"
- "Leadership Team", "Executive Team"

Medium Confidence:
- "Our Mission", "Our Vision", "Our Values"
- "Case Studies", "Customer Stories", "Success Stories"
- "Partners", "Customers", "Testimonials"
```

#### Navigation Structure
```
Typical sections:
- About / Company
- Products / Solutions
- Customers / Case Studies
- Resources / Blog
- Careers
- Contact
- Investors (for public companies)
- Press / Media
```

#### URL Patterns
```
/about-us, /about, /company
/careers, /jobs
/contact, /contact-us
/investors, /press, /newsroom
/leadership, /team
```

### 2.8 LANDING PAGE / LEAD CAPTURE

**Criticality Impact**: LOW to MEDIUM (marketing, lead generation)

#### HTML Body Keywords
```
High Confidence:
- "Sign Up", "Get Started", "Start Free Trial"
- "Subscribe", "Join Now", "Request Demo"
- "Limited Time Offer", "Early Access"
- Lead capture form fields: email, phone, company
- class="cta-button", class="lead-form"

Medium Confidence:
- "No Credit Card Required", "Free Forever"
- "Join 10,000+ customers", social proof
- "Download", "Get the Guide", "Free Resource"
- Countdown timers, urgency indicators
```

#### Form Patterns
```html
<form class="lead-capture">
  <input type="email" placeholder="Email address">
  <input type="text" placeholder="Company name">
  <button>Get Started Free</button>
</form>

<!-- CTA buttons -->
<button class="cta-primary">Sign Up Now</button>
<a class="hero-cta">Request Demo</a>
```

#### Technology Stack
```
Landing Page Builders:
- Unbounce: ubembed.com
- Leadpages: leadpages.net
- Instapage: instapage.com
- Webflow: webflow.io

Marketing Automation:
- HubSpot: hs-scripts.com, hsforms.net
- Marketo: marketo.net, munchkin.js
- Mailchimp: list-manage.com
```

### 2.9 DOCUMENTATION SITE / KNOWLEDGE BASE

**Criticality Impact**: LOW to MEDIUM (support content, typically public)

#### HTML Body Keywords
```
High Confidence:
- "Documentation", "Docs", "Knowledge Base"
- "User Guide", "Manual", "Help Center"
- "Table of Contents", "Navigation", "On this page"
- "Search documentation", "Search docs"
- class="doc-content", class="article-body"
- Breadcrumbs: Home > Docs > Section > Article

Code Elements:
- Syntax highlighting
- Copy code button
- Language tabs (Python, JavaScript, etc.)
```

#### Navigation Patterns
```
Sidebar structure:
- Getting Started
- Guides
- Reference
- API
- Troubleshooting
- FAQ

Search bar prominently placed
Breadcrumb navigation
Table of contents for current page
```

#### Technology Stack
```
Documentation Platforms:
- ReadTheDocs: readthedocs.io, rtd-*
- GitBook: gitbook.io
- Docusaurus: docusaurus.io
- MkDocs: mkdocs.org
- Sphinx: sphinx-doc.org
- Confluence: atlassian.net/wiki
```

#### URL Patterns
```
/docs/*, /documentation/*
/help/*, /support/*, /kb/*
/wiki/*, /guides/*
/faq, /troubleshooting
```

### 2.10 PAYMENT PROCESSING / CHECKOUT

**Criticality Impact**: CRITICAL (handles payment information, financial transactions)

#### HTML Body Keywords
```
High Confidence:
- "payment method", "credit card", "debit card"
- "card number", "expiry date", "CVV", "CVC"
- "billing address", "shipping address"
- "order summary", "total amount", "tax"
- "secure checkout", "SSL", "encrypted"
- iframe from payment provider

Security Indicators:
- "PCI compliant", "secure payment"
- Padlock icons, security badges
- "256-bit encryption", "SSL certificate"
```

#### Payment Gateway Iframes
```html
<iframe src="https://js.stripe.com/..."></iframe>
<iframe src="https://www.paypal.com/..."></iframe>
<iframe src="https://checkout.square.com/..."></iframe>
```

#### Technology Stack Fingerprints
```
Stripe:
- js.stripe.com/v3/
- pk_live_*, pk_test_*
- stripe.createToken()

PayPal:
- paypal.com/sdk/js
- paypal-button-container
- data-paypal-button

Square:
- squareup.com/checkout
- sq-payment-form

Braintree:
- js.braintreegateway.com
- braintree-web

Adyen:
- adyen.com/hpp
- adyen-checkout
```

#### URL Patterns
```
/checkout/*, /payment/*, /pay/*
/billing/*, /order/complete
/secure/checkout, /cart/payment
```

### 2.11 AUTHENTICATION SERVICE (SSO/OAuth/SAML)

**Criticality Impact**: CRITICAL (identity provider, access control, session management)

#### HTML Body Keywords
```
High Confidence:
- "Single Sign-On", "SSO", "SAML", "OAuth", "OIDC"
- "Sign in with", "Continue with Google/Microsoft/etc"
- "Identity Provider", "Authentication", "Authorization"
- "Access Token", "Refresh Token", "ID Token"
- "Federation", "Trust Relationship"

Login Forms:
- "Email or username", "Password"
- "Remember me", "Forgot password"
- "Two-factor authentication", "MFA", "2FA"
- "Verify your identity", "Enter code"
```

#### URL Patterns
```
/auth/*, /oauth/*, /saml/*
/login/*, /signin/*, /sso/*
/authorize, /token, /callback
/idp/*, /identity/*
/.well-known/openid-configuration
```

#### Technology Stack
```
Auth Providers:
- Okta: okta.com, oktacdn.com
- Auth0: auth0.com, auth0-lock
- Keycloak: keycloak.js
- Azure AD: login.microsoftonline.com
- Google: accounts.google.com/gsi
- Cognito: cognito-identity.amazonaws.com

OAuth/OIDC Endpoints:
- /authorize, /token, /userinfo
- /.well-known/jwks.json
```

#### Detection Patterns
```html
<!-- OAuth consent screen -->
<div class="oauth-consent">
  <p>App name wants to access your:</p>
  <ul>
    <li>Email address</li>
    <li>Basic profile</li>
  </ul>
  <button>Allow</button>
  <button>Deny</button>
</div>

<!-- SAML login -->
<form method="post" action="/saml/sso">
  <input type="hidden" name="SAMLRequest">
  <input type="hidden" name="RelayState">
</form>
```

### 2.12 DEVOPS INFRASTRUCTURE

**Criticality Impact**: CRITICAL (CI/CD, source code, artifacts, deployment)

#### HTML Body Keywords
```
High Confidence:
- "Build Pipeline", "CI/CD", "Deployment"
- "Artifacts", "Registry", "Repository"
- "Containers", "Images", "Docker"
- "Jobs", "Builds", "Stages"
- Jenkins, GitLab, GitHub, ArgoCD, Nexus

Platform-specific:
Jenkins: "Build History", "Console Output", "Configure"
GitLab: "Merge Request", "CI/CD", "Pipelines"
GitHub: "Actions", "Workflows", "Packages"
ArgoCD: "Applications", "Sync Status"
```

#### URL Patterns
```
Jenkins: /job/*, /build/*, /configure
GitLab: /ci/cd/*, /pipelines/*, /-/jobs/*
GitHub: /actions/*, /packages/*, /workflows/*
ArgoCD: /applications/*, /settings/*
Nexus: /repository/*, /artifacts/*
Artifactory: /artifactory/*, /webapp/*
```

#### Technology Detection
```
Jenkins:
- X-Hudson, X-Jenkins
- jenkins-*.js, hudson-*.js

GitLab:
- X-GitLab-*
- gitlab.com, gitlab-*.js

GitHub:
- github.com, githubusercontent.com
- octicons, github-*.js

Docker Registry:
- /v2/, /v2/_catalog
- Docker-Distribution-Api-Version

ArgoCD:
- argocd.argoproj.io
- applications.argoproj.io
```

## 3. Multi-Classification Examples

### 3.1 E-commerce + Blog
**Example**: shopify.com, bigcommerce.com

**Detection**:
- E-commerce: product catalog, shopping cart, checkout
- Blog: /blog/*, article structure, RSS feed
- Corporate: about us, careers, press

**Criticality**: HIGH (primary function: e-commerce transactions)

### 3.2 SaaS + Documentation + Developer Portal
**Example**: stripe.com, twilio.com

**Detection**:
- SaaS: dashboard, account settings, billing
- Documentation: /docs/*, API reference, guides
- Developer Portal: API keys, webhooks, OAuth apps

**Criticality**: CRITICAL (developer credentials, API access, payment processing)

### 3.3 Corporate + Blog + Careers
**Example**: Most corporate websites

**Detection**:
- Corporate: about us, leadership, investors
- Blog: /blog/*, articles, thought leadership
- Careers: /jobs/*, applicant portal

**Criticality**: LOW to MEDIUM (marketing/branding focus)

### 3.4 Customer Portal + Support + Documentation
**Example**: support.example.com

**Detection**:
- Customer Portal: account, tickets, invoices
- Support: knowledge base, live chat
- Documentation: help articles, FAQs

**Criticality**: HIGH (customer PII, support tickets)

## 4. Criticality Scoring Matrix

### 4.1 Webapp Type Score Deltas

Based on Qualys methodology (1-5 scale, baseline 3.0 for production):

| Webapp Type | Delta | Rationale |
|------------|-------|-----------|
| **CRITICAL (+1.5 to +2.0)** |
| Payment Processing | +2.0 | Direct financial transactions, PCI compliance required |
| Admin Panel | +1.8 | Privileged access, system configuration |
| Authentication Service | +1.5 | Identity provider, SSO, session management |
| DevOps Infrastructure | +1.5 | Source code access, deployment control |
| Vault/Secrets | +1.5 | Credential storage, encryption keys |
| **HIGH (+0.8 to +1.4)** |
| E-commerce | +1.3 | Customer PII, payment data, orders |
| SaaS Dashboard | +1.2 | Business operations, user data |
| Customer Portal | +0.9 | Account access, personal information |
| VPN Gateway | +0.8 | Network access control |
| **MEDIUM (+0.3 to +0.7)** |
| Developer Portal | +0.7 | API credentials, OAuth apps |
| API Endpoint | +0.5 | Data access, integration point |
| Mobile Backend | +0.4 | App data, user sessions |
| Gateway Service | +0.3 | Traffic routing, load balancing |
| **LOW (+0.0 to +0.2)** |
| Corporate Website | +0.0 | Public marketing content |
| Blog | +0.0 | Public articles, low sensitivity |
| Documentation | +0.1 | Public help content |
| Landing Page | +0.0 | Lead capture, marketing |
| **ENVIRONMENT ADJUSTMENTS** |
| Production (baseline) | +0.0 | Default for internet-exposed |
| Staging | -1.5 | Pre-production testing |
| UAT | -1.5 | User acceptance testing |
| Dev | -2.0 | Development environment |
| Test | -2.0 | Testing environment |
| Demo | -1.5 | Demonstration instance |
| Sandbox | -2.0 | Isolated testing |

### 4.2 Combined Score Example

**Scenario**: auth.company.com (Production SSO with MFA)

```
Base Score:              3.0  (Production baseline)
+ Auth Service:         +1.5  (SSO/SAML provider)
+ Enterprise Auth:      +0.4  (SAML/SSO enterprise)
+ MFA Enabled:          +0.3  (Multi-factor auth)
+ Gateway (Cloudflare): +0.3  (WAF/DDoS protection)
────────────────────────────
Final Score:            5.0  (CRITICAL - clamped to max)
Category:               CRITICAL
```

**Scenario**: docs.company.com (Documentation site)

```
Base Score:             3.0  (Production baseline)
+ Documentation:       +0.1  (Public docs)
────────────────────────────
Final Score:            3.1  (MEDIUM)
Category:               MEDIUM
```

**Scenario**: dev-api.company.com (Development API)

```
Base Score:             3.0  (Production baseline)
+ API Endpoint:        +0.5  (REST API)
+ Dev Environment:     -2.0  (Development)
────────────────────────────
Final Score:            1.5  (LOW - clamped to min)
Category:               LOW
```

## 5. Detection Implementation Strategy

### 5.1 Headless Browser Template (Nuclei DSL)

Create webapp classification template: `scan-templates/webapp-type-detection.yaml`

```yaml
id: webapp-type-detection
info:
  name: Web Application Type Classification
  author: Vallabh
  severity: info
  description: Detects webapp types for criticality scoring
  tags: exposure,criticality,webapp-classification

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    redirects: true
    max-redirects: 10

    extractors:
      # E-COMMERCE DETECTION
      - type: regex
        name: check_ecommerce_keywords
        internal: true
        part: body
        regex:
          - '(?i)(add to cart|shopping cart|checkout|buy now|product-grid|cart-summary)'

      - type: dsl
        name: check_ecommerce_tech
        internal: true
        dsl:
          - 'contains(body, "Shopify") || contains(body, "woocommerce") || contains(body, "magento")'

      - type: dsl
        dsl:
          - '(check_ecommerce_keywords || check_ecommerce_tech) ? to_value_group("webapp.type.ecommerce", host) : ""'

      # SAAS DASHBOARD DETECTION
      - type: regex
        name: check_dashboard_keywords
        internal: true
        part: body
        regex:
          - '(?i)(dashboard|account settings|user profile|subscription|billing plan|team members)'

      - type: dsl
        name: check_nav_structure
        internal: true
        dsl:
          - 'contains(body, "sidebar-nav") || contains(body, "app-sidebar") || contains(body, "main-dashboard")'

      - type: dsl
        dsl:
          - '(check_dashboard_keywords || check_nav_structure) ? to_value_group("webapp.type.saas_dashboard", host) : ""'

      # ADMIN PANEL DETECTION
      - type: regex
        name: check_admin_keywords
        internal: true
        part: body
        regex:
          - '(?i)(admin panel|administration|control panel|users management|system settings|audit trail)'

      - type: dsl
        name: check_admin_path
        internal: true
        dsl:
          - 'contains(path, "/admin") || contains(path, "/wp-admin") || contains(path, "/administrator")'

      - type: dsl
        dsl:
          - '(check_admin_keywords || check_admin_path) ? to_value_group("webapp.type.admin_panel", host) : ""'

      # CUSTOMER PORTAL DETECTION
      - type: regex
        name: check_portal_keywords
        internal: true
        part: body
        regex:
          - '(?i)(customer portal|my account|support tickets|ticket history|download invoice)'

      - type: dsl
        dsl:
          - 'check_portal_keywords ? to_value_group("webapp.type.customer_portal", host) : ""'

      # DEVELOPER PORTAL / API DOCS DETECTION
      - type: regex
        name: check_api_docs_keywords
        internal: true
        part: body
        regex:
          - '(?i)(API Reference|API Documentation|Getting Started|OAuth|API Key|SDK|Code Examples|REST API|GraphQL)'

      - type: dsl
        name: check_code_blocks
        internal: true
        dsl:
          - 'contains(body, "<pre><code") || contains(body, "class=\"highlight\"") || contains(body, "language-python")'

      - type: dsl
        dsl:
          - '(check_api_docs_keywords || check_code_blocks) ? to_value_group("webapp.type.developer_portal", host) : ""'

      # BLOG DETECTION
      - type: regex
        name: check_blog_keywords
        internal: true
        part: body
        regex:
          - '(?i)(class="post"|class="article"|published on|posted by|comments|comment section|RSS feed)'

      - type: regex
        name: check_blog_meta
        internal: true
        part: header
        regex:
          - 'og:type.*article'

      - type: dsl
        dsl:
          - '(check_blog_keywords || check_blog_meta) ? to_value_group("webapp.type.blog", host) : ""'

      # CORPORATE WEBSITE DETECTION
      - type: regex
        name: check_corporate_keywords
        internal: true
        part: body
        regex:
          - '(?i)(About Us|Our Team|Careers|Jobs|Contact Us|Investors|Press Release|Leadership Team)'

      - type: dsl
        dsl:
          - 'check_corporate_keywords ? to_value_group("webapp.type.corporate", host) : ""'

      # LANDING PAGE DETECTION
      - type: regex
        name: check_landing_keywords
        internal: true
        part: body
        regex:
          - '(?i)(Sign Up|Get Started|Start Free Trial|Request Demo|Lead.?capture|CTA.?button)'

      - type: dsl
        dsl:
          - 'check_landing_keywords ? to_value_group("webapp.type.landing_page", host) : ""'

      # DOCUMENTATION SITE DETECTION
      - type: regex
        name: check_docs_keywords
        internal: true
        part: body
        regex:
          - '(?i)(Documentation|User Guide|Help Center|Table of Contents|Search documentation|Knowledge Base)'

      - type: dsl
        name: check_docs_tech
        internal: true
        dsl:
          - 'contains(body, "readthedocs") || contains(body, "docusaurus") || contains(body, "gitbook")'

      - type: dsl
        dsl:
          - '(check_docs_keywords || check_docs_tech) ? to_value_group("webapp.type.documentation", host) : ""'

      # PAYMENT/CHECKOUT DETECTION
      - type: regex
        name: check_payment_keywords
        internal: true
        part: body
        regex:
          - '(?i)(payment method|credit card|card number|CVV|CVC|billing address|secure checkout|PCI compliant)'

      - type: dsl
        name: check_payment_iframe
        internal: true
        dsl:
          - 'contains(body, "stripe.com") || contains(body, "paypal.com/sdk") || contains(body, "squareup.com")'

      - type: dsl
        dsl:
          - '(check_payment_keywords || check_payment_iframe) ? to_value_group("webapp.type.payment_processing", host) : ""'

      # AUTHENTICATION SERVICE DETECTION
      - type: regex
        name: check_auth_keywords
        internal: true
        part: body
        regex:
          - '(?i)(Single Sign-On|SSO|SAML|OAuth|OIDC|Identity Provider|Two-factor|MFA|2FA)'

      - type: dsl
        name: check_auth_tech
        internal: true
        dsl:
          - 'contains(body, "okta") || contains(body, "auth0") || contains(body, "keycloak") || contains(host, "auth.") || contains(host, "sso.")'

      - type: dsl
        dsl:
          - '(check_auth_keywords || check_auth_tech) ? to_value_group("webapp.type.auth_service", host) : ""'

      # DEVOPS INFRASTRUCTURE DETECTION
      - type: regex
        name: check_devops_keywords
        internal: true
        part: body
        regex:
          - '(?i)(Build Pipeline|CI/CD|Deployment|Artifacts|Registry|Containers|Docker|Jenkins|GitLab)'

      - type: dsl
        name: check_devops_headers
        internal: true
        dsl:
          - 'contains(all_headers, "X-Jenkins") || contains(all_headers, "X-GitLab") || contains(all_headers, "X-GitHub")'

      - type: dsl
        dsl:
          - '(check_devops_keywords || check_devops_headers) ? to_value_group("webapp.type.devops_infra", host) : ""'
```

### 5.2 Findings.json Integration

Add webapp type findings to `/Users/vajoshi/Work/web-exposure-detection/pkg/webexposure/findings.json`:

```json
{
  "webapp.type.ecommerce": {
    "slug": "webapp.type.ecommerce",
    "display_name": "E-commerce Website",
    "icon": "shopping-cart.svg",
    "show_in_tech": true,
    "classification": ["webapp", "ecommerce"],
    "description": "Online store with product catalog, shopping cart, and checkout functionality",
    "labels": ["E-commerce", "Transactional"],
    "criticality_delta": 1.3
  },
  "webapp.type.saas_dashboard": {
    "slug": "webapp.type.saas_dashboard",
    "display_name": "SaaS Dashboard",
    "icon": "dashboard.svg",
    "show_in_tech": true,
    "classification": ["webapp", "saas"],
    "description": "Software-as-a-Service application dashboard with account management",
    "labels": ["SaaS", "Application"],
    "criticality_delta": 1.2
  },
  "webapp.type.admin_panel": {
    "slug": "webapp.type.admin_panel",
    "display_name": "Admin Panel",
    "icon": "admin.svg",
    "show_in_tech": true,
    "classification": ["webapp", "admin"],
    "description": "Administrative control panel with privileged access",
    "labels": ["Admin", "Privileged"],
    "criticality_delta": 1.8
  },
  "webapp.type.customer_portal": {
    "slug": "webapp.type.customer_portal",
    "display_name": "Customer Portal",
    "icon": "portal.svg",
    "show_in_tech": true,
    "classification": ["webapp", "portal"],
    "description": "Customer self-service portal with account and support features",
    "labels": ["Portal", "Customer"],
    "criticality_delta": 0.9
  },
  "webapp.type.developer_portal": {
    "slug": "webapp.type.developer_portal",
    "display_name": "Developer Portal",
    "icon": "code.svg",
    "show_in_tech": true,
    "classification": ["webapp", "api", "developer"],
    "description": "Developer documentation, API reference, and SDK resources",
    "labels": ["Developer", "API Docs"],
    "criticality_delta": 0.7
  },
  "webapp.type.blog": {
    "slug": "webapp.type.blog",
    "display_name": "Blog/Publication",
    "icon": "blog.svg",
    "show_in_tech": true,
    "classification": ["webapp", "content"],
    "description": "Blog or publication site with articles and posts",
    "labels": ["Content", "Blog"],
    "criticality_delta": 0.0
  },
  "webapp.type.corporate": {
    "slug": "webapp.type.corporate",
    "display_name": "Corporate Website",
    "icon": "building.svg",
    "show_in_tech": true,
    "classification": ["webapp", "marketing"],
    "description": "Corporate marketing website with company information",
    "labels": ["Corporate", "Marketing"],
    "criticality_delta": 0.0
  },
  "webapp.type.landing_page": {
    "slug": "webapp.type.landing_page",
    "display_name": "Landing Page",
    "icon": "rocket.svg",
    "show_in_tech": true,
    "classification": ["webapp", "marketing"],
    "description": "Marketing landing page with lead capture forms",
    "labels": ["Marketing", "Lead Gen"],
    "criticality_delta": 0.0
  },
  "webapp.type.documentation": {
    "slug": "webapp.type.documentation",
    "display_name": "Documentation Site",
    "icon": "book.svg",
    "show_in_tech": true,
    "classification": ["webapp", "content"],
    "description": "Product documentation, help center, or knowledge base",
    "labels": ["Documentation", "Support"],
    "criticality_delta": 0.1
  },
  "webapp.type.payment_processing": {
    "slug": "webapp.type.payment_processing",
    "display_name": "Payment Processing",
    "icon": "credit-card.svg",
    "show_in_tech": true,
    "classification": ["webapp", "payment"],
    "description": "Payment gateway or checkout system handling financial transactions",
    "labels": ["Payment", "Financial"],
    "criticality_delta": 2.0
  },
  "webapp.type.auth_service": {
    "slug": "webapp.type.auth_service",
    "display_name": "Authentication Service",
    "icon": "shield.svg",
    "show_in_tech": true,
    "classification": ["webapp", "auth"],
    "description": "Single Sign-On, OAuth, or SAML authentication service",
    "labels": ["Authentication", "Identity"],
    "criticality_delta": 1.5
  },
  "webapp.type.devops_infra": {
    "slug": "webapp.type.devops_infra",
    "display_name": "DevOps Infrastructure",
    "icon": "server.svg",
    "show_in_tech": true,
    "classification": ["webapp", "infrastructure"],
    "description": "CI/CD pipeline, container registry, or artifact repository",
    "labels": ["DevOps", "Infrastructure"],
    "criticality_delta": 1.5
  }
}
```

### 5.3 Processing Logic

Update `/Users/vajoshi/Work/web-exposure-detection/pkg/webexposure/criticality.go`:

```go
// CalculateCriticality now processes:
// 1. Domain patterns (auth., admin., api., etc.)
// 2. Environment (dev, staging, prod)
// 3. Infrastructure (Cloudflare, AWS)
// 4. Authentication methods (SAML, OAuth, MFA)
// 5. Webapp types (e-commerce, SaaS, admin, etc.) ← NEW

// Multi-classification supported:
// - Same domain can be webapp.type.ecommerce + webapp.type.blog
// - All applicable criticality_delta values are summed
// - Final score clamped to 1.0-5.0 range
```

## 6. Benefits for Criticality Scoring

### 6.1 Enhanced Context

**Before webapp classification**:
- api.company.com = 3.5 (base + API function)

**After webapp classification**:
- api.company.com (e-commerce backend) = 4.8 (base + API + e-commerce)
- api.company.com (blog CMS) = 3.6 (base + API + blog)

### 6.2 Better Prioritization

Enables triage based on business function:

1. **CRITICAL**: payment.company.com (payment processing detected)
2. **HIGH**: app.company.com (SaaS dashboard detected)
3. **MEDIUM**: docs.company.com (documentation site detected)
4. **LOW**: blog.company.com (blog + corporate site detected)

### 6.3 Multi-Layer Detection

Combining signals provides higher confidence:

```
Stripe.com analysis:
├── Domain: api.stripe.com → API function (+0.5)
├── Tech: Payment gateway (Stripe) → Payment processing (+2.0)
├── Webapp: Developer portal → API docs (+0.7)
├── Auth: OAuth provider → Auth service (+1.5)
└── Final: 5.0 (CRITICAL) - multiple high-value functions
```

### 6.4 False Positive Reduction

Webapp classification helps disambiguate:

- test.company.com with admin panel → Still marked TEST environment (-2.0)
- demo.company.com with e-commerce → Demo instance (-1.5), not production
- blog.company.com with checkout → E-commerce + blog hybrid (accurate score)

## 7. Research Sources

### 7.1 Web Application Taxonomy
- ClaySys Technologies: 8 Types of Web Applications
- Netguru: 10 Web Application Types
- Imaginary Cloud: 10 Web App Types for 2026
- AllCode: Different Types of Web Application Development

### 7.2 Detection Patterns
- Pentest-Tools: Website Recon & Tech Stack Detection
- OWASP: HTTP Headers Cheat Sheet
- Webshrinker: Website Categorization
- BuiltWith: Technology Detection Methods

### 7.3 E-commerce Patterns
- Salesforce: E-commerce Checkout Best Practices
- Google Analytics: E-commerce Event Tracking
- Avada: E-commerce Platform Detection
- SecurityMetrics: Shopping Cart Monitor

### 7.4 Admin Panel Security
- Recorded Future: Dangers of Exposed Login Panels
- RedHunt Labs: Security Issues in Login Functionalities
- ThreatNG: Exposed Admin Panels
- Cobalt: Admin Panel Publicly Accessible

### 7.5 SaaS & Portal Detection
- ChartMogul: Subscription Analytics
- HubSpot: Customer Portal
- Freshdesk: Customer Portal Overview
- Salesforce: Customer Self-Service Portal

### 7.6 Developer Portals
- Box Developer Documentation
- Microsoft Azure API Management
- Okta Developer Portal
- Google Cloud Apigee

### 7.7 Structured Data
- Schema.org: Structured Data Standards
- OpenGraph Protocol
- Google: JSON-LD Support

### 7.8 Asset Criticality
- Tenable: Asset Criticality Rating (ACR)
- IBM: Common Vulnerability Scoring System (CVSS)
- Wiz: Vulnerability Prioritization
- NIST IR 8179: Criticality Analysis Process Model

## 8. Implementation Recommendations

### 8.1 Phased Rollout

**Phase 1**: Core webapp types (COMPLETED in current system)
- Admin panel detection (domain.function.admin)
- API detection (domain.function.api)
- Auth service detection (domain.function.auth)

**Phase 2**: Transactional types (RECOMMENDED NEXT)
- E-commerce detection
- Payment processing detection
- Customer portal detection
- SaaS dashboard detection

**Phase 3**: Content types (LOWER PRIORITY)
- Blog detection
- Documentation detection
- Corporate website detection
- Landing page detection

**Phase 4**: Infrastructure types (ADVANCED)
- DevOps infrastructure detection
- Developer portal detection
- Container registry detection

### 8.2 Confidence Scoring

Implement confidence levels for multi-signal detection:

```go
type WebappTypeDetection struct {
    Type       string  // "ecommerce", "saas_dashboard", etc.
    Confidence float64 // 0.0-1.0
    Signals    []string // ["keywords", "tech_stack", "url_pattern"]
}

// High confidence: 3+ signals match
// Medium confidence: 2 signals match
// Low confidence: 1 signal matches
```

### 8.3 Template Organization

Create modular templates:

```
scan-templates/
├── domain-criticality-detection.yaml (EXISTING)
├── webapp-type-detection.yaml (NEW - core types)
├── webapp-ecommerce-detection.yaml (NEW - detailed e-commerce)
├── webapp-saas-detection.yaml (NEW - detailed SaaS)
└── webapp-admin-detection.yaml (NEW - detailed admin)
```

### 8.4 Testing Strategy

Validate detection accuracy:

```bash
# Test domains
- shopify.com → ecommerce, saas_dashboard, developer_portal, blog
- stripe.com → payment_processing, developer_portal, saas_dashboard
- wordpress.com → blog, saas_dashboard, corporate
- github.com → devops_infra, developer_portal, corporate
- docs.aws.amazon.com → documentation, developer_portal
```

## 9. Limitations & Considerations

### 9.1 Dynamic Content

Single-page applications (SPAs) require JavaScript execution:
- Use headless browser mode (Nuclei supports this)
- May need delay for content rendering
- Performance impact on large scans

### 9.2 Authentication-Gated Content

Some webapp types only visible after login:
- Admin panels often behind auth
- SaaS dashboards require credentials
- Customer portals need account access

**Mitigation**: Use domain patterns and login page indicators

### 9.3 False Positives

Keywords can be ambiguous:
- "Dashboard" in blog post ≠ actual dashboard
- "Cart" in documentation ≠ shopping cart

**Mitigation**: Require multiple signals for high-confidence detection

### 9.4 Regional Variations

E-commerce keywords vary by language:
- "Add to cart" (English)
- "Ajouter au panier" (French)
- "In den Warenkorb" (German)

**Future Enhancement**: Multi-language keyword support

## 10. Next Steps

1. **Review** this research with stakeholders
2. **Prioritize** webapp types for implementation (recommend Phase 2: transactional types)
3. **Create** webapp-type-detection.yaml template
4. **Update** findings.json with webapp type entries
5. **Test** detection accuracy on diverse domains
6. **Document** webapp classification in user docs
7. **Iterate** based on real-world scan results

## Appendix A: Quick Reference Tables

### A.1 Webapp Type Quick Lookup

| Webapp Type | Primary Keywords | URL Patterns | Criticality |
|-------------|-----------------|--------------|-------------|
| E-commerce | cart, checkout, buy now | /cart, /checkout, /products | HIGH |
| SaaS Dashboard | dashboard, account settings | /dashboard, /app | HIGH |
| Admin Panel | admin panel, users management | /admin, /wp-admin | CRITICAL |
| Customer Portal | my account, support tickets | /portal, /customer | HIGH |
| Developer Portal | API reference, OAuth | /docs/api, /developers | MEDIUM |
| Blog | article, published on | /blog, /posts | LOW |
| Corporate | about us, careers | /about, /contact | LOW |
| Documentation | user guide, help center | /docs, /help | LOW |
| Payment | payment method, CVV | /payment, /checkout | CRITICAL |
| Auth Service | SSO, OAuth, SAML | /auth, /sso, /oauth | CRITICAL |
| DevOps | CI/CD, pipeline | /build, /pipelines | CRITICAL |

### A.2 Technology Stack Detection

| Technology | Detection Pattern | Webapp Type Hint |
|------------|------------------|------------------|
| Shopify | window.Shopify, cdn.shopify.com | E-commerce |
| Stripe | js.stripe.com, pk_live_ | Payment |
| WordPress | wp-content, wp-admin | Blog, CMS |
| React Admin | react-admin, refine | SaaS Dashboard |
| Swagger | swagger-ui, openapi.json | Developer Portal |
| Okta | okta.com, oktacdn.com | Auth Service |
| Jenkins | X-Jenkins, hudson-*.js | DevOps |
| GitLab | X-GitLab, gitlab.com | DevOps |
| Zendesk | zendesk.com, zd-widget | Customer Portal |

---

**Document Version**: 1.0
**Last Updated**: 2025-10-18
**Author**: Research compiled for web-exposure-detection tool
**Target Audience**: Security engineers, DevOps, Product team
