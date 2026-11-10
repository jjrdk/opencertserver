# opencertserver.acme.abstractions.tests

This project verifies the ACME abstractions layer used throughout OpenCertServer. It checks the shared models, interfaces, and contracts that define how ACME operations are represented between the client and server.

## Functionality
- Validates the abstractions and contracts used by the ACME stack
- Ensures the shared models remain consistent across server and client integrations
- Acts as a focused test harness for the `opencertserver.acme.abstractions` library

## Dependencies
- `../../src/opencertserver.acme.abstractions/opencertserver.acme.abstractions.csproj`
- `xunit.v3.mtp-v2` as the test framework

This suite is intentionally narrow: it validates the contracts that other ACME components build on.
