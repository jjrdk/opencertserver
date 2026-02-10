# opencertserver.est.server

This project provides the EST (Enrollment over Secure Transport, RFC 7030) server implementation for OpenCertServer. It exposes endpoints for secure certificate enrollment and management, supporting both certificate and JWT authentication.

## Functionality
- Implements EST server endpoints for certificate enrollment
- Supports secure authentication and certificate issuance

## Dependencies
- Microsoft.AspNetCore.Authentication.Certificate
- Microsoft.AspNetCore.Authentication.JwtBearer
- Microsoft.Extensions.DependencyInjection.Abstractions
- opencertserver.ca.utils (certificate utilities)

Use this project to deploy an EST-compliant certificate authority server.
