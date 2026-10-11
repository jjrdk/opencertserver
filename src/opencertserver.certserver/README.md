# opencertserver.certserver

> **Deployment and certificate-policy notice:** This cert server is not a hardened, production-ready CA deployment.
> Operators must configure and validate it to meet their own certificate policy, threat model, and operational
> requirements, including organization-specific registration rules.
> We are committed to developing OpenCertServer as a safe and standards-compliant project, and invite users and
> contributors to hold us accountable to that standard and help us uphold it. All contributions toward this shared
> commitment are appreciated.
> However, the project cannot account for every adopting user's custom use case or registration requirements;
> responsibility for adapting and validating a deployment rests with its operator.

This is the main web application for OpenCertServer, hosting the ACME, CA, EST and SCEP server endpoints. It provides a unified interface for certificate enrollment, management, and automation, integrating all major server-side components.

## Functionality
- Hosts ACME, CA, EST and SCEP endpoints
- Provides unified certificate authority services
- Designed for deployment as a web server

## Dependencies
- opencertserver.acme.server (ACME server)
- opencertserver.ca.server (CA server)
- opencertserver.est.server (EST server)
- opencertserver.scep.server (SCEP server)

This is the entry point for running the full OpenCertServer service.

## SCEP

SCEP (RFC 8894) is served at `/scep` and `/scep/{profileName}`. `GetCACaps` and
`GetCACert` only publish public information. `PKIOperation` issues nothing until a
challenge is configured:

| Setting | Purpose |
|---|---|
| `Scep:Challenge` | Shared challenge password. Set it through the environment (`Scep__Challenge`), not on the command line, where it would show in the process list. Without it, every enrollment is refused. |
| `Scep:DefaultProfile` | CA profile for requests to `/scep` without a profile name. |
| `--scep-ra`, `--scep-ra-key` | PEM files of the RA certificate and its RSA key. Without them, a self-signed RA is created at start-up and changes with every restart. |

A renewal (`RenewalReq`) is signed with the certificate it replaces. It needs no
challenge; the server checks that the certificate was issued by this CA, is valid, is not
revoked and names the same subject, and revokes it once the new one is issued. A
transaction ID is accepted once within `TransactionIdWindow` (24 hours).

