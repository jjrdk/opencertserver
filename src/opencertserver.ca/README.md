# opencertserver.ca

This project implements the core certificate authority (CA) logic for OpenCertServer. It provides the main services for certificate issuance, validation, and revocation, and is used by both server and utility projects.

## Functionality
- Core CA operations: certificate issuance, validation, and revocation
- Integrates with utility functions for X.509 and PKI operations

## Dependencies
- Microsoft.Extensions.Logging.Abstractions (logging)
- opencertserver.ca.utils (utility functions)

This project is the foundation for CA-related features in OpenCertServer.
