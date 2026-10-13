# opencertserver.certserver

> **Deployment and certificate-policy notice:** This cert server is not a hardened, production-ready CA deployment.
> Operators must configure and validate it to meet their own certificate policy, threat model, and operational
> requirements, including organization-specific registration rules.
> We are committed to developing OpenCertServer as a safe and standards-compliant project, and invite users and
> contributors to hold us accountable to that standard and help us uphold it. All contributions toward this shared
> commitment are appreciated.
> However, the project cannot account for every adopting user's custom use case or registration requirements;
> responsibility for adapting and validating a deployment rests with its operator.

This is the main web application for OpenCertServer, hosting the ACME, CA, and EST server endpoints. It provides a unified interface for certificate enrollment, management, and automation, integrating all major server-side components.

## Functionality
- Hosts ACME, CA, and EST endpoints
- Provides unified certificate authority services
- Designed for deployment as a web server

## Dependencies
- opencertserver.acme.server (ACME server)
- opencertserver.ca.server (CA server)
- opencertserver.est.server (EST server)

This is the entry point for running the full OpenCertServer service.
