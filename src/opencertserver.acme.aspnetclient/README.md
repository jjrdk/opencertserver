# opencertserver.acme.aspnetclient

This project implements an ACME client for ASP.NET Core, enabling applications to interact with ACME servers for certificate enrollment and management. It provides integration with ASP.NET Core services and leverages CertesSlim for protocol operations.

## Functionality
- ACME client logic for ASP.NET Core
- Integrates with CertesSlim and OpenCertServer abstractions
- Supports certificate renewal and registration workflows

## Dependencies
- Microsoft.AspNetCore.App (framework reference)
- CertesSlim (ACME protocol client)
- opencertserver.acme.abstractions (shared models)
- opencertserver.ca.utils (certificate utilities)

Use this library to add ACME client capabilities to ASP.NET Core applications.
