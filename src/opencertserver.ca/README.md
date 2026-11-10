# opencertserver.ca

This project implements the core certificate authority (CA) logic for OpenCertServer. It provides the main services for certificate issuance, validation, and revocation, and is used by both server and utility projects.

## Functionality
- Core CA operations: certificate issuance, validation, and revocation
- Integrates with utility functions for X.509 and PKI operations

## Role in the RA/CA split

The in-process CA core. The standalone ACME, RA and SCEP hosts
(`opencertserver.acme`, `opencertserver.ra.server`, `opencertserver.scep`) and the
monolith's remote issuer (`opencertserver.acme.remote`) delegate issuance, revocation and
published-chain requests to this authority over a trusted HTTPS connection
(`opencertserver.ca.client`); see `docs/architecture-separation.md`. When the CA core is
not hosted in-process, a `RemoteCertificateAuthority` stands in for it, so this project
is the authority the remote hosts call — never the other way around.

## Dependencies
- `opencertserver.ca.protocol` (shared RA/CA wire contract: bindings, claims and paths)
- `opencertserver.ca.utils` (X.509/PKI helpers, `ICertificateAuthority`, `SignCertificateResponse`)
- `Microsoft.Extensions.Logging.Abstractions` (logging)

## OpenTelemetry

Core CA operations publish activities and metrics through the
`opencertserver.ca.core` meter and activity source. The operation label and span name
are fixed values such as `sign_certificate`, `revoke_certificate`, and
`get_revocation_list`. Telemetry does not include certificate requests or contents,
subjects, serial numbers, thumbprints, profile names, or exception messages.
The host must subscribe to this meter and activity source to export the signals.

This project is the foundation for CA-related features in OpenCertServer.
