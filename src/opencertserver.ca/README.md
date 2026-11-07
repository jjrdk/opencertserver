# opencertserver.ca

This project implements the core certificate authority (CA) logic for OpenCertServer. It provides the main services for certificate issuance, validation, and revocation, and is used by both server and utility projects.

## Functionality
- Core CA operations: certificate issuance, validation, and revocation
- Integrates with utility functions for X.509 and PKI operations

## Dependencies
- Microsoft.Extensions.Logging.Abstractions (logging)
- opencertserver.ca.utils (utility functions)

## OpenTelemetry

Core CA operations publish activities and metrics through the
`opencertserver.ca.core` meter and activity source. The operation label and span name
are fixed values such as `sign_certificate`, `revoke_certificate`, and
`get_revocation_list`. Telemetry does not include certificate requests or contents,
subjects, serial numbers, thumbprints, profile names, or exception messages.
The host must subscribe to this meter and activity source to export the signals.

This project is the foundation for CA-related features in OpenCertServer.
