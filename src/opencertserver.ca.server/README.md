# opencertserver.ca.server

This project provides the ASP.NET Core server implementation for the certificate authority (CA) in OpenCertServer. It exposes CA services over HTTP, supporting certificate authentication and JWT-based authentication for secure operations.

## Functionality
- Hosts CA endpoints for certificate issuance and management
- Supports certificate and JWT authentication
- Integrates with the core CA logic

## Dependencies
- Microsoft.AspNetCore.Authentication.Certificate
- Microsoft.AspNetCore.Authentication.JwtBearer
- Microsoft.Extensions.DependencyInjection.Abstractions
- opencertserver.ca (core CA logic)

Use this project to deploy the CA as a web service.
