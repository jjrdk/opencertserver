# opencertserver.acme.server

This project provides the ACME server implementation for OpenCertServer, supporting the ACME protocol for automated certificate issuance and management. It exposes endpoints for ACME clients and integrates with certificate authority utilities.

## Functionality
- Implements ACME server endpoints (RFC 8555)
- Handles certificate requests, challenges, and account management
- Integrates with CertesSlim and CA utilities

## Dependencies
- DnsClient (DNS resolution for challenge validation)
- Microsoft.AspNetCore.App (framework reference)
- CertesSlim, opencertserver.acme.abstractions, opencertserver.ca.utils (project references)

Use this project to run an ACME-compliant certificate authority server.
