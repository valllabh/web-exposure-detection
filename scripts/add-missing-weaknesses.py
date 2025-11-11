#!/usr/bin/env python3
"""
Script to add missing CWE weaknesses to findings.json based on security analysis.
"""
import json
from datetime import datetime, timezone

# Map of finding slugs to their recommended CWE weaknesses
WEAKNESS_RECOMMENDATIONS = {
    # E-Commerce Platforms
    "backend.ecommerce.shopify": [
        {"id": "CWE-79", "name": "Cross-Site Scripting (XSS)", "count": 5},
        {"id": "CWE-89", "name": "SQL Injection", "count": 4},
        {"id": "CWE-285", "name": "Improper Authorization", "count": 4},
        {"id": "CWE-20", "name": "Improper Input Validation", "count": 4},
        {"id": "CWE-22", "name": "Path Traversal", "count": 3}
    ],
    "backend.ecommerce.bigcommerce": [
        {"id": "CWE-79", "name": "Cross-Site Scripting (XSS)", "count": 5},
        {"id": "CWE-89", "name": "SQL Injection", "count": 4},
        {"id": "CWE-285", "name": "Improper Authorization", "count": 4},
        {"id": "CWE-20", "name": "Improper Input Validation", "count": 4},
        {"id": "CWE-22", "name": "Path Traversal", "count": 3}
    ],

    # Site Builders
    "backend.sitebuilder.wix": [
        {"id": "CWE-79", "name": "Cross-Site Scripting (XSS)", "count": 5},
        {"id": "CWE-20", "name": "Improper Input Validation", "count": 4},
        {"id": "CWE-601", "name": "URL Redirection to Untrusted Site", "count": 3},
        {"id": "CWE-1021", "name": "Improper Restriction of Rendered UI Layers", "count": 3}
    ],
    "backend.sitebuilder.squarespace": [
        {"id": "CWE-79", "name": "Cross-Site Scripting (XSS)", "count": 5},
        {"id": "CWE-20", "name": "Improper Input Validation", "count": 4},
        {"id": "CWE-601", "name": "URL Redirection to Untrusted Site", "count": 3},
        {"id": "CWE-1021", "name": "Improper Restriction of Rendered UI Layers", "count": 3}
    ],

    # Authentication Systems - Traditional
    "auth.traditional.basic_auth": [
        {"id": "CWE-287", "name": "Improper Authentication", "count": 5},
        {"id": "CWE-522", "name": "Insufficiently Protected Credentials", "count": 5},
        {"id": "CWE-319", "name": "Cleartext Transmission of Sensitive Information", "count": 4},
        {"id": "CWE-798", "name": "Use of Hard-coded Credentials", "count": 3},
        {"id": "CWE-307", "name": "Improper Restriction of Excessive Authentication Attempts", "count": 4}
    ],
    "auth.traditional.registration": [
        {"id": "CWE-521", "name": "Weak Password Requirements", "count": 5},
        {"id": "CWE-640", "name": "Weak Password Recovery Mechanism for Forgotten Password", "count": 4},
        {"id": "CWE-307", "name": "Improper Restriction of Excessive Authentication Attempts", "count": 4},
        {"id": "CWE-799", "name": "Improper Control of Interaction Frequency", "count": 3},
        {"id": "CWE-916", "name": "Use of Password Hash With Insufficient Computational Effort", "count": 4}
    ],
    "auth.traditional.password_recovery": [
        {"id": "CWE-640", "name": "Weak Password Recovery Mechanism for Forgotten Password", "count": 5},
        {"id": "CWE-307", "name": "Improper Restriction of Excessive Authentication Attempts", "count": 4},
        {"id": "CWE-285", "name": "Improper Authorization", "count": 3}
    ],

    # Authentication Systems - Enterprise
    "auth.enterprise.saml_sso": [
        {"id": "CWE-347", "name": "Improper Verification of Cryptographic Signature", "count": 5},
        {"id": "CWE-611", "name": "Improper Restriction of XML External Entity Reference", "count": 4},
        {"id": "CWE-776", "name": "Improper Restriction of Recursive Entity References in DTDs", "count": 3},
        {"id": "CWE-290", "name": "Authentication Bypass by Spoofing", "count": 4},
        {"id": "CWE-345", "name": "Insufficient Verification of Data Authenticity", "count": 4}
    ],
    "auth.enterprise.microsoft": [
        {"id": "CWE-601", "name": "URL Redirection to Untrusted Site", "count": 5},
        {"id": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)", "count": 4},
        {"id": "CWE-346", "name": "Origin Validation Error", "count": 4},
        {"id": "CWE-287", "name": "Improper Authentication", "count": 4},
        {"id": "CWE-384", "name": "Session Fixation", "count": 3}
    ],
    "auth.enterprise.okta": [
        {"id": "CWE-601", "name": "URL Redirection to Untrusted Site", "count": 5},
        {"id": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)", "count": 4},
        {"id": "CWE-346", "name": "Origin Validation Error", "count": 4},
        {"id": "CWE-287", "name": "Improper Authentication", "count": 4},
        {"id": "CWE-384", "name": "Session Fixation", "count": 3}
    ],
    "auth.enterprise.auth0": [
        {"id": "CWE-601", "name": "URL Redirection to Untrusted Site", "count": 5},
        {"id": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)", "count": 4},
        {"id": "CWE-346", "name": "Origin Validation Error", "count": 4},
        {"id": "CWE-287", "name": "Improper Authentication", "count": 4},
        {"id": "CWE-384", "name": "Session Fixation", "count": 3}
    ],
    "auth.enterprise.onelogin": [
        {"id": "CWE-601", "name": "URL Redirection to Untrusted Site", "count": 5},
        {"id": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)", "count": 4},
        {"id": "CWE-346", "name": "Origin Validation Error", "count": 4},
        {"id": "CWE-287", "name": "Improper Authentication", "count": 4},
        {"id": "CWE-347", "name": "Improper Verification of Cryptographic Signature", "count": 3}
    ],
    "auth.enterprise.keycloak": [
        {"id": "CWE-601", "name": "URL Redirection to Untrusted Site", "count": 5},
        {"id": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)", "count": 4},
        {"id": "CWE-346", "name": "Origin Validation Error", "count": 4},
        {"id": "CWE-287", "name": "Improper Authentication", "count": 4},
        {"id": "CWE-384", "name": "Session Fixation", "count": 3}
    ],
    "auth.enterprise.adfs": [
        {"id": "CWE-347", "name": "Improper Verification of Cryptographic Signature", "count": 5},
        {"id": "CWE-290", "name": "Authentication Bypass by Spoofing", "count": 4},
        {"id": "CWE-345", "name": "Insufficient Verification of Data Authenticity", "count": 4},
        {"id": "CWE-601", "name": "URL Redirection to Untrusted Site", "count": 3},
        {"id": "CWE-384", "name": "Session Fixation", "count": 3}
    ],

    # Authentication Systems - Social
    "auth.social.google": [
        {"id": "CWE-601", "name": "URL Redirection to Untrusted Site", "count": 5},
        {"id": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)", "count": 4},
        {"id": "CWE-346", "name": "Origin Validation Error", "count": 4},
        {"id": "CWE-287", "name": "Improper Authentication", "count": 4},
        {"id": "CWE-384", "name": "Session Fixation", "count": 3}
    ],
    "auth.social.facebook": [
        {"id": "CWE-601", "name": "URL Redirection to Untrusted Site", "count": 5},
        {"id": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)", "count": 4},
        {"id": "CWE-346", "name": "Origin Validation Error", "count": 4},
        {"id": "CWE-287", "name": "Improper Authentication", "count": 4},
        {"id": "CWE-384", "name": "Session Fixation", "count": 3}
    ],
    "auth.social.twitter": [
        {"id": "CWE-601", "name": "URL Redirection to Untrusted Site", "count": 5},
        {"id": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)", "count": 4},
        {"id": "CWE-346", "name": "Origin Validation Error", "count": 4},
        {"id": "CWE-287", "name": "Improper Authentication", "count": 4},
        {"id": "CWE-384", "name": "Session Fixation", "count": 3}
    ],
    "auth.social.linkedin": [
        {"id": "CWE-601", "name": "URL Redirection to Untrusted Site", "count": 5},
        {"id": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)", "count": 4},
        {"id": "CWE-346", "name": "Origin Validation Error", "count": 4},
        {"id": "CWE-287", "name": "Improper Authentication", "count": 4},
        {"id": "CWE-384", "name": "Session Fixation", "count": 3}
    ],
    "auth.social.github": [
        {"id": "CWE-601", "name": "URL Redirection to Untrusted Site", "count": 5},
        {"id": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)", "count": 4},
        {"id": "CWE-346", "name": "Origin Validation Error", "count": 4},
        {"id": "CWE-287", "name": "Improper Authentication", "count": 4},
        {"id": "CWE-384", "name": "Session Fixation", "count": 3}
    ],
    "auth.social.apple": [
        {"id": "CWE-601", "name": "URL Redirection to Untrusted Site", "count": 5},
        {"id": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)", "count": 4},
        {"id": "CWE-346", "name": "Origin Validation Error", "count": 4},
        {"id": "CWE-287", "name": "Improper Authentication", "count": 4},
        {"id": "CWE-347", "name": "Improper Verification of Cryptographic Signature", "count": 3}
    ],

    # Authentication Systems - MFA & Passwordless
    "auth.mfa": [
        {"id": "CWE-288", "name": "Authentication Bypass Using an Alternate Path or Channel", "count": 5},
        {"id": "CWE-306", "name": "Missing Authentication for Critical Function", "count": 4},
        {"id": "CWE-287", "name": "Improper Authentication", "count": 4},
        {"id": "CWE-640", "name": "Weak Password Recovery Mechanism for Forgotten Password", "count": 3},
        {"id": "CWE-384", "name": "Session Fixation", "count": 3}
    ],
    "auth.passwordless": [
        {"id": "CWE-290", "name": "Authentication Bypass by Spoofing", "count": 5},
        {"id": "CWE-346", "name": "Origin Validation Error", "count": 4},
        {"id": "CWE-384", "name": "Session Fixation", "count": 4},
        {"id": "CWE-640", "name": "Weak Password Recovery Mechanism for Forgotten Password", "count": 3},
        {"id": "CWE-601", "name": "URL Redirection to Untrusted Site", "count": 3}
    ],

    # API Detection & Specifications
    "api.domain_pattern": [
        {"id": "CWE-200", "name": "Exposure of Sensitive Information to an Unauthorized Actor", "count": 5},
        {"id": "CWE-548", "name": "Exposure of Information Through Directory Listing", "count": 4},
        {"id": "CWE-16", "name": "Configuration", "count": 3}
    ],
    "api.spec.openapi": [
        {"id": "CWE-200", "name": "Exposure of Sensitive Information to an Unauthorized Actor", "count": 5},
        {"id": "CWE-548", "name": "Exposure of Information Through Directory Listing", "count": 4},
        {"id": "CWE-862", "name": "Missing Authorization", "count": 4},
        {"id": "CWE-285", "name": "Improper Authorization", "count": 4},
        {"id": "CWE-639", "name": "Authorization Bypass Through User-Controlled Key", "count": 3}
    ],
    "api.spec.swagger": [
        {"id": "CWE-200", "name": "Exposure of Sensitive Information to an Unauthorized Actor", "count": 5},
        {"id": "CWE-548", "name": "Exposure of Information Through Directory Listing", "count": 4},
        {"id": "CWE-862", "name": "Missing Authorization", "count": 4},
        {"id": "CWE-285", "name": "Improper Authorization", "count": 4},
        {"id": "CWE-639", "name": "Authorization Bypass Through User-Controlled Key", "count": 3}
    ],
    "api.spec.postman": [
        {"id": "CWE-200", "name": "Exposure of Sensitive Information to an Unauthorized Actor", "count": 5},
        {"id": "CWE-522", "name": "Insufficiently Protected Credentials", "count": 5},
        {"id": "CWE-798", "name": "Use of Hard-coded Credentials", "count": 4},
        {"id": "CWE-540", "name": "Inclusion of Sensitive Information in Source Code", "count": 4}
    ],
    "api.spec.wadl": [
        {"id": "CWE-200", "name": "Exposure of Sensitive Information to an Unauthorized Actor", "count": 5},
        {"id": "CWE-548", "name": "Exposure of Information Through Directory Listing", "count": 4},
        {"id": "CWE-862", "name": "Missing Authorization", "count": 3},
        {"id": "CWE-611", "name": "Improper Restriction of XML External Entity Reference", "count": 4}
    ],
    "api.spec.wsdl": [
        {"id": "CWE-200", "name": "Exposure of Sensitive Information to an Unauthorized Actor", "count": 5},
        {"id": "CWE-548", "name": "Exposure of Information Through Directory Listing", "count": 4},
        {"id": "CWE-611", "name": "Improper Restriction of XML External Entity Reference", "count": 4},
        {"id": "CWE-776", "name": "Improper Restriction of Recursive Entity References in DTDs", "count": 3},
        {"id": "CWE-91", "name": "XML Injection", "count": 3}
    ],
    "api.server.json": [
        {"id": "CWE-200", "name": "Exposure of Sensitive Information to an Unauthorized Actor", "count": 5},
        {"id": "CWE-285", "name": "Improper Authorization", "count": 4},
        {"id": "CWE-287", "name": "Improper Authentication", "count": 4},
        {"id": "CWE-918", "name": "Server-Side Request Forgery (SSRF)", "count": 4},
        {"id": "CWE-20", "name": "Improper Input Validation", "count": 4}
    ],
    "api.server.xml": [
        {"id": "CWE-611", "name": "Improper Restriction of XML External Entity Reference", "count": 5},
        {"id": "CWE-776", "name": "Improper Restriction of Recursive Entity References in DTDs", "count": 4},
        {"id": "CWE-91", "name": "XML Injection", "count": 4},
        {"id": "CWE-285", "name": "Improper Authorization", "count": 4},
        {"id": "CWE-20", "name": "Improper Input Validation", "count": 4}
    ],

    # AI Services
    "api.ai.openai_endpoint": [
        {"id": "CWE-522", "name": "Insufficiently Protected Credentials", "count": 5},
        {"id": "CWE-200", "name": "Exposure of Sensitive Information to an Unauthorized Actor", "count": 5},
        {"id": "CWE-77", "name": "Command Injection", "count": 4},
        {"id": "CWE-20", "name": "Improper Input Validation", "count": 4},
        {"id": "CWE-770", "name": "Allocation of Resources Without Limits or Throttling", "count": 3}
    ],
    "api.ai.anthropic_endpoint": [
        {"id": "CWE-522", "name": "Insufficiently Protected Credentials", "count": 5},
        {"id": "CWE-200", "name": "Exposure of Sensitive Information to an Unauthorized Actor", "count": 5},
        {"id": "CWE-77", "name": "Command Injection", "count": 4},
        {"id": "CWE-20", "name": "Improper Input Validation", "count": 4},
        {"id": "CWE-770", "name": "Allocation of Resources Without Limits or Throttling", "count": 3}
    ],
    "api.ai.vector_db.pinecone": [
        {"id": "CWE-77", "name": "Command Injection", "count": 5},
        {"id": "CWE-200", "name": "Exposure of Sensitive Information to an Unauthorized Actor", "count": 5},
        {"id": "CWE-306", "name": "Missing Authentication for Critical Function", "count": 4},
        {"id": "CWE-502", "name": "Deserialization of Untrusted Data", "count": 4},
        {"id": "CWE-284", "name": "Improper Access Control", "count": 4}
    ],

    # Gateways & CDNs
    "gateway.cloudflare": [
        {"id": "CWE-16", "name": "Configuration", "count": 5},
        {"id": "CWE-693", "name": "Protection Mechanism Failure", "count": 4},
        {"id": "CWE-668", "name": "Exposure of Resource to Wrong Sphere", "count": 4},
        {"id": "CWE-200", "name": "Exposure of Sensitive Information to an Unauthorized Actor", "count": 3}
    ],
    "gateway.akamai": [
        {"id": "CWE-16", "name": "Configuration", "count": 5},
        {"id": "CWE-693", "name": "Protection Mechanism Failure", "count": 4},
        {"id": "CWE-668", "name": "Exposure of Resource to Wrong Sphere", "count": 4},
        {"id": "CWE-444", "name": "Inconsistent Interpretation of HTTP Requests", "count": 3}
    ],
    "gateway.apigee": [
        {"id": "CWE-16", "name": "Configuration", "count": 5},
        {"id": "CWE-285", "name": "Improper Authorization", "count": 4},
        {"id": "CWE-287", "name": "Improper Authentication", "count": 4},
        {"id": "CWE-918", "name": "Server-Side Request Forgery (SSRF)", "count": 4},
        {"id": "CWE-770", "name": "Allocation of Resources Without Limits or Throttling", "count": 3}
    ],

    # Informational & Metadata
    "page.title": [
        {"id": "CWE-200", "name": "Exposure of Sensitive Information to an Unauthorized Actor", "count": 5},
        {"id": "CWE-209", "name": "Generation of Error Message Containing Sensitive Information", "count": 4}
    ],
    "page.description": [
        {"id": "CWE-200", "name": "Exposure of Sensitive Information to an Unauthorized Actor", "count": 5},
        {"id": "CWE-209", "name": "Generation of Error Message Containing Sensitive Information", "count": 4}
    ],
    "server.blank_root_status": [
        {"id": "CWE-200", "name": "Exposure of Sensitive Information to an Unauthorized Actor", "count": 5},
        {"id": "CWE-548", "name": "Exposure of Information Through Directory Listing", "count": 4},
        {"id": "CWE-16", "name": "Configuration", "count": 3}
    ],

    # Security Headers
    "security.sri_coverage": [
        {"id": "CWE-494", "name": "Download of Code Without Integrity Check", "count": 5},
        {"id": "CWE-829", "name": "Inclusion of Functionality from Untrusted Control Sphere", "count": 4},
        {"id": "CWE-346", "name": "Origin Validation Error", "count": 3}
    ],
    "security.mixed_content": [
        {"id": "CWE-319", "name": "Cleartext Transmission of Sensitive Information", "count": 5},
        {"id": "CWE-311", "name": "Missing Encryption of Sensitive Data", "count": 4},
        {"id": "CWE-300", "name": "Channel Accessible by Non-Endpoint", "count": 3}
    ],
    "security.https_status": [
        {"id": "CWE-319", "name": "Cleartext Transmission of Sensitive Information", "count": 5},
        {"id": "CWE-311", "name": "Missing Encryption of Sensitive Data", "count": 4},
        {"id": "CWE-326", "name": "Inadequate Encryption Strength", "count": 3}
    ],
    "security.form_security": [
        {"id": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)", "count": 5},
        {"id": "CWE-319", "name": "Cleartext Transmission of Sensitive Information", "count": 4},
        {"id": "CWE-640", "name": "Weak Password Recovery Mechanism for Forgotten Password", "count": 3}
    ],
    "security.meta_policies": [
        {"id": "CWE-1021", "name": "Improper Restriction of Rendered UI Layers", "count": 5},
        {"id": "CWE-79", "name": "Cross-Site Scripting (XSS)", "count": 4},
        {"id": "CWE-16", "name": "Configuration", "count": 3}
    ],
    "security.hsts": [
        {"id": "CWE-319", "name": "Cleartext Transmission of Sensitive Information", "count": 5},
        {"id": "CWE-523", "name": "Unprotected Transport of Credentials", "count": 4},
        {"id": "CWE-757", "name": "Selection of Less-Secure Algorithm During Negotiation", "count": 3}
    ],
    "security.csp_header": [
        {"id": "CWE-79", "name": "Cross-Site Scripting (XSS)", "count": 5},
        {"id": "CWE-1021", "name": "Improper Restriction of Rendered UI Layers", "count": 4},
        {"id": "CWE-829", "name": "Inclusion of Functionality from Untrusted Control Sphere", "count": 4},
        {"id": "CWE-494", "name": "Download of Code Without Integrity Check", "count": 3}
    ],
    "security.xfo": [
        {"id": "CWE-1021", "name": "Improper Restriction of Rendered UI Layers", "count": 5},
        {"id": "CWE-451", "name": "User Interface Misrepresentation of Critical Information", "count": 4}
    ],
    "security.xcto": [
        {"id": "CWE-430", "name": "Deployment of Wrong Handler", "count": 5},
        {"id": "CWE-434", "name": "Unrestricted Upload of File with Dangerous Type", "count": 4},
        {"id": "CWE-16", "name": "Configuration", "count": 3}
    ],
    "security.referrer_header": [
        {"id": "CWE-200", "name": "Exposure of Sensitive Information to an Unauthorized Actor", "count": 5},
        {"id": "CWE-359", "name": "Exposure of Private Personal Information to an Unauthorized Actor", "count": 4},
        {"id": "CWE-598", "name": "Use of GET Request Method With Sensitive Query Strings", "count": 3}
    ],
    "security.permissions_policy": [
        {"id": "CWE-250", "name": "Execution with Unnecessary Privileges", "count": 5},
        {"id": "CWE-269", "name": "Improper Privilege Management", "count": 4},
        {"id": "CWE-862", "name": "Missing Authorization", "count": 3}
    ],
    "security.coop": [
        {"id": "CWE-346", "name": "Origin Validation Error", "count": 5},
        {"id": "CWE-942", "name": "Permissive Cross-domain Policy with Untrusted Domains", "count": 4},
        {"id": "CWE-1021", "name": "Improper Restriction of Rendered UI Layers", "count": 3}
    ],
    "security.coep": [
        {"id": "CWE-346", "name": "Origin Validation Error", "count": 5},
        {"id": "CWE-829", "name": "Inclusion of Functionality from Untrusted Control Sphere", "count": 4},
        {"id": "CWE-668", "name": "Exposure of Resource to Wrong Sphere", "count": 3}
    ],
    "security.corp": [
        {"id": "CWE-346", "name": "Origin Validation Error", "count": 5},
        {"id": "CWE-942", "name": "Permissive Cross-domain Policy with Untrusted Domains", "count": 4},
        {"id": "CWE-668", "name": "Exposure of Resource to Wrong Sphere", "count": 3}
    ],
    "security.server_disclosure": [
        {"id": "CWE-200", "name": "Exposure of Sensitive Information to an Unauthorized Actor", "count": 5},
        {"id": "CWE-209", "name": "Generation of Error Message Containing Sensitive Information", "count": 4},
        {"id": "CWE-497", "name": "Exposure of Sensitive System Information to an Unauthorized Control Sphere", "count": 4}
    ],
    "security.powered_by_disclosure": [
        {"id": "CWE-200", "name": "Exposure of Sensitive Information to an Unauthorized Actor", "count": 5},
        {"id": "CWE-209", "name": "Generation of Error Message Containing Sensitive Information", "count": 4},
        {"id": "CWE-497", "name": "Exposure of Sensitive System Information to an Unauthorized Control Sphere", "count": 4}
    ],

    # Connection Status
    "http.reachable": [
        {"id": "CWE-200", "name": "Exposure of Sensitive Information to an Unauthorized Actor", "count": 5},
        {"id": "CWE-668", "name": "Exposure of Resource to Wrong Sphere", "count": 4}
    ],

    # Storage APIs
    "api.storage.file_api": [
        {"id": "CWE-22", "name": "Path Traversal", "count": 5},
        {"id": "CWE-434", "name": "Unrestricted Upload of File with Dangerous Type", "count": 5},
        {"id": "CWE-73", "name": "External Control of File Name or Path", "count": 4},
        {"id": "CWE-284", "name": "Improper Access Control", "count": 4},
        {"id": "CWE-732", "name": "Incorrect Permission Assignment for Critical Resource", "count": 3}
    ],

    # Web Application Types
    "webapp.type.payment_processing": [
        {"id": "CWE-311", "name": "Missing Encryption of Sensitive Data", "count": 5},
        {"id": "CWE-319", "name": "Cleartext Transmission of Sensitive Information", "count": 5},
        {"id": "CWE-522", "name": "Insufficiently Protected Credentials", "count": 4},
        {"id": "CWE-359", "name": "Exposure of Private Personal Information to an Unauthorized Actor", "count": 4},
        {"id": "CWE-209", "name": "Generation of Error Message Containing Sensitive Information", "count": 3}
    ],
    "webapp.type.saas_dashboard": [
        {"id": "CWE-285", "name": "Improper Authorization", "count": 5},
        {"id": "CWE-639", "name": "Authorization Bypass Through User-Controlled Key", "count": 5},
        {"id": "CWE-862", "name": "Missing Authorization", "count": 4},
        {"id": "CWE-384", "name": "Session Fixation", "count": 4},
        {"id": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)", "count": 4}
    ],
    "webapp.type.developer_portal": [
        {"id": "CWE-522", "name": "Insufficiently Protected Credentials", "count": 5},
        {"id": "CWE-798", "name": "Use of Hard-coded Credentials", "count": 4},
        {"id": "CWE-200", "name": "Exposure of Sensitive Information to an Unauthorized Actor", "count": 5},
        {"id": "CWE-284", "name": "Improper Access Control", "count": 4}
    ],
    "webapp.type.marketing": [
        {"id": "CWE-79", "name": "Cross-Site Scripting (XSS)", "count": 5},
        {"id": "CWE-601", "name": "URL Redirection to Untrusted Site", "count": 4},
        {"id": "CWE-1021", "name": "Improper Restriction of Rendered UI Layers", "count": 3},
        {"id": "CWE-200", "name": "Exposure of Sensitive Information to an Unauthorized Actor", "count": 3}
    ],
    "webapp.type.blog": [
        {"id": "CWE-79", "name": "Cross-Site Scripting (XSS)", "count": 5},
        {"id": "CWE-89", "name": "SQL Injection", "count": 4},
        {"id": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)", "count": 4},
        {"id": "CWE-284", "name": "Improper Access Control", "count": 3}
    ],
    "webapp.type.documentation": [
        {"id": "CWE-200", "name": "Exposure of Sensitive Information to an Unauthorized Actor", "count": 5},
        {"id": "CWE-79", "name": "Cross-Site Scripting (XSS)", "count": 4},
        {"id": "CWE-601", "name": "URL Redirection to Untrusted Site", "count": 3}
    ],
    "webapp.type.landing_page": [
        {"id": "CWE-79", "name": "Cross-Site Scripting (XSS)", "count": 5},
        {"id": "CWE-601", "name": "URL Redirection to Untrusted Site", "count": 4},
        {"id": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)", "count": 4},
        {"id": "CWE-1021", "name": "Improper Restriction of Rendered UI Layers", "count": 3}
    ],

    # Domain Functions
    "domain.function.auth": [
        {"id": "CWE-287", "name": "Improper Authentication", "count": 5},
        {"id": "CWE-522", "name": "Insufficiently Protected Credentials", "count": 5},
        {"id": "CWE-307", "name": "Improper Restriction of Excessive Authentication Attempts", "count": 4},
        {"id": "CWE-384", "name": "Session Fixation", "count": 4},
        {"id": "CWE-640", "name": "Weak Password Recovery Mechanism for Forgotten Password", "count": 3}
    ],
    "domain.function.identity": [
        {"id": "CWE-287", "name": "Improper Authentication", "count": 5},
        {"id": "CWE-347", "name": "Improper Verification of Cryptographic Signature", "count": 5},
        {"id": "CWE-290", "name": "Authentication Bypass by Spoofing", "count": 4},
        {"id": "CWE-384", "name": "Session Fixation", "count": 4},
        {"id": "CWE-285", "name": "Improper Authorization", "count": 4}
    ],
    "domain.function.gateway": [
        {"id": "CWE-918", "name": "Server-Side Request Forgery (SSRF)", "count": 5},
        {"id": "CWE-444", "name": "Inconsistent Interpretation of HTTP Requests", "count": 5},
        {"id": "CWE-770", "name": "Allocation of Resources Without Limits or Throttling", "count": 4},
        {"id": "CWE-285", "name": "Improper Authorization", "count": 4},
        {"id": "CWE-16", "name": "Configuration", "count": 3}
    ],
    "domain.function.customer_portal": [
        {"id": "CWE-639", "name": "Authorization Bypass Through User-Controlled Key", "count": 5},
        {"id": "CWE-285", "name": "Improper Authorization", "count": 5},
        {"id": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)", "count": 4},
        {"id": "CWE-384", "name": "Session Fixation", "count": 4},
        {"id": "CWE-359", "name": "Exposure of Private Personal Information to an Unauthorized Actor", "count": 4}
    ],
    "domain.function.api": [
        {"id": "CWE-285", "name": "Improper Authorization", "count": 5},
        {"id": "CWE-287", "name": "Improper Authentication", "count": 5},
        {"id": "CWE-918", "name": "Server-Side Request Forgery (SSRF)", "count": 4},
        {"id": "CWE-770", "name": "Allocation of Resources Without Limits or Throttling", "count": 4},
        {"id": "CWE-200", "name": "Exposure of Sensitive Information to an Unauthorized Actor", "count": 4}
    ],
    "domain.function.mobile": [
        {"id": "CWE-798", "name": "Use of Hard-coded Credentials", "count": 5},
        {"id": "CWE-311", "name": "Missing Encryption of Sensitive Data", "count": 5},
        {"id": "CWE-295", "name": "Improper Certificate Validation", "count": 4},
        {"id": "CWE-749", "name": "Exposed Dangerous Method or Function", "count": 3}
    ],
    "domain.function.secure": [
        {"id": "CWE-285", "name": "Improper Authorization", "count": 5},
        {"id": "CWE-287", "name": "Improper Authentication", "count": 5},
        {"id": "CWE-522", "name": "Insufficiently Protected Credentials", "count": 4},
        {"id": "CWE-384", "name": "Session Fixation", "count": 3}
    ],
    "domain.function.payment": [
        {"id": "CWE-311", "name": "Missing Encryption of Sensitive Data", "count": 5},
        {"id": "CWE-359", "name": "Exposure of Private Personal Information to an Unauthorized Actor", "count": 5},
        {"id": "CWE-522", "name": "Insufficiently Protected Credentials", "count": 4},
        {"id": "CWE-285", "name": "Improper Authorization", "count": 4},
        {"id": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)", "count": 4}
    ],

    # Web Application Types (duplicate customer_portal and ecommerce)
    "webapp.type.ecommerce": [
        {"id": "CWE-639", "name": "Authorization Bypass Through User-Controlled Key", "count": 5},
        {"id": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)", "count": 5},
        {"id": "CWE-89", "name": "SQL Injection", "count": 4},
        {"id": "CWE-79", "name": "Cross-Site Scripting (XSS)", "count": 4},
        {"id": "CWE-311", "name": "Missing Encryption of Sensitive Data", "count": 4}
    ],
    "webapp.type.customer_portal": [
        {"id": "CWE-639", "name": "Authorization Bypass Through User-Controlled Key", "count": 5},
        {"id": "CWE-285", "name": "Improper Authorization", "count": 5},
        {"id": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)", "count": 4},
        {"id": "CWE-384", "name": "Session Fixation", "count": 4},
        {"id": "CWE-359", "name": "Exposure of Private Personal Information to an Unauthorized Actor", "count": 4}
    ]
}


def add_weaknesses_to_findings(findings_file):
    """Add missing weaknesses to findings.json"""

    # Read the findings file
    with open(findings_file, 'r') as f:
        findings = json.load(f)

    updated_count = 0
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Iterate through all findings
    for slug, weakness_list in WEAKNESS_RECOMMENDATIONS.items():
        if slug in findings:
            finding = findings[slug]

            # Check if it needs weaknesses added
            if not finding['security'].get('cwe_applicable', False):
                print(f"Adding weaknesses to: {slug}")

                # Update the security section
                finding['security']['cwe_applicable'] = True
                finding['security']['weaknesses'] = {
                    "stats": {
                        "total": len(weakness_list),
                        "top_categories": weakness_list
                    },
                    "updated": timestamp
                }

                updated_count += 1
            else:
                print(f"Skipping {slug} - already has weaknesses")
        else:
            print(f"Warning: {slug} not found in findings.json")

    # Write the updated findings back to the file
    with open(findings_file, 'w') as f:
        json.dump(findings, f, indent=2)

    print(f"\nCompleted! Updated {updated_count} findings with weaknesses.")
    return updated_count


if __name__ == "__main__":
    findings_file = "/Users/vajoshi/Work/web-exposure-detection/pkg/webexposure/findings/findings.json"
    add_weaknesses_to_findings(findings_file)
