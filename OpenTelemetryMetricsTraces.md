# OpenTelemetry Metrics and Traces for OpenCertServer

This document lists OpenTelemetry metrics and traces for OpenCertServer based on implemented protocols (EST RFC 7030/8951/9908, ACME RFC 8555, SCEP RFC 8894, Intune integration, OCSP RFC 6960, CRL RFC 5280) and codebase analysis.

## Naming Strategy
- **Metrics**: `opencertserver.{protocol}.{operation}.{type}` where `type` is `requests` (counter), `successes` (counter), `failures` (counter), `duration` (histogram in seconds), `active` (gauge for ongoing operations).
- **Traces**: Span name `opencertserver.{protocol}.{operation}`, with sub-spans for internal steps like validation, signing, persistence.
- Protocols: `est`, `acme`, `scep`, `intune`, `ocsp`, `crl`, `ca` (for CA endpoints), `cli` (for CLI operations).

**Privacy.** SCEP and Intune metrics and activities contain no request-derived attributes.
Transaction IDs, challenge passwords, CSR or certificate contents, serial numbers, subjects,
user/device identifiers, profile names, and exception messages are not emitted as telemetry.

## EST (RFC 7030)

### Metrics
- `opencertserver.est.cacerts.requests`: Counter for /cacerts requests.
- `opencertserver.est.cacerts.successes`: Counter for successful /cacerts responses.
- `opencertserver.est.cacerts.failures`: Counter for failed /cacerts responses (e.g., internal errors).
- `opencertserver.est.cacerts.duration`: Histogram for request duration.
- `opencertserver.est.simpleenroll.requests`: Counter for /simpleenroll requests.
- `opencertserver.est.simpleenroll.successes`: Counter for successful enrollments.
- `opencertserver.est.simpleenroll.failures`: Counter for enrollment failures (e.g., invalid CSR, auth failure).
- `opencertserver.est.simpleenroll.duration`: Histogram for enrollment duration.
- `opencertserver.est.simplereenroll.requests`: Counter for /simplereenroll requests.
- `opencertserver.est.simplereenroll.successes`: Counter for successful re-enrollments.
- `opencertserver.est.simplereenroll.failures`: Counter for re-enrollment failures.
- `opencertserver.est.simplereenroll.duration`: Histogram for re-enrollment duration.
- `opencertserver.est.csrattrs.requests`: Counter for /csrattrs requests.
- `opencertserver.est.csrattrs.successes`: Counter for successful /csrattrs responses.
- `opencertserver.est.csrattrs.failures`: Counter for /csrattrs failures.
- `opencertserver.est.csrattrs.duration`: Histogram for /csrattrs duration.
- `opencertserver.est.serverkeygen.requests`: Counter for /serverkeygen requests.
- `opencertserver.est.serverkeygen.successes`: Counter for successful key generations.
- `opencertserver.est.serverkeygen.failures`: Counter for key generation failures.
- `opencertserver.est.serverkeygen.duration`: Histogram for key generation duration.

### Traces
- `opencertserver.est.cacerts`: Span for /cacerts request, sub-spans for certificate chain retrieval and response encoding.
- `opencertserver.est.simpleenroll`: Span for enrollment, sub-spans for CSR parsing, validation, signing, certificate issuance.
- `opencertserver.est.simplereenroll`: Span for re-enrollment, sub-spans for authentication, CSR validation, signing.
- `opencertserver.est.csrattrs`: Span for CSR attributes retrieval.
- `opencertserver.est.serverkeygen`: Span for key generation, sub-spans for key pair creation, certificate signing.

**Collection Location**: In `src/opencertserver.est.server/Handlers/` (e.g., `CaCertHandler.cs`, `SimpleEnrollHandler.cs`), wrap `Handle` methods with spans, record metrics at start/end.

## SCEP (RFC 8894)

### Metrics
- `opencertserver.scep.getcacaps.{requests,successes,failures,duration}`: GetCACaps endpoint requests.
- `opencertserver.scep.getcacert.{requests,successes,failures,duration}`: GetCACert endpoint requests.
- `opencertserver.scep.pkioperation.{requests,successes,failures,duration}`: PKIOperation requests; protocol refusal responses count as failures even though SCEP returns them with HTTP 200.
- `opencertserver.scep.unsupported.{requests,successes,failures,duration}`: Unsupported operation requests.

### Traces
- `opencertserver.scep.getcacaps`: GetCACaps request.
- `opencertserver.scep.getcacert`: GetCACert request.
- `opencertserver.scep.pkioperation`: PKIOperation request.
- `opencertserver.scep.unsupported`: Unsupported operation request.

**Collection Location**: `src/opencertserver.scep.server/Handlers/ScepHandler.cs`.

## Intune integration

### Metrics
- `opencertserver.intune.challenge.validation.{requests,successes,failures,duration}`: Intune challenge validation attempts.
- `opencertserver.intune.notification.success.{requests,successes,failures,duration}`: Notifications after certificate issuance.
- `opencertserver.intune.notification.failure.{requests,successes,failures,duration}`: Notifications after CA refusal.
- `opencertserver.intune.revocationsync.{requests,successes,failures,duration}`: Revocation sync runs.

### Traces
- `opencertserver.intune.challenge.validation`: Validation request to Intune.
- `opencertserver.intune.notification.success`: Post-issuance notification.
- `opencertserver.intune.notification.failure`: Post-refusal notification.
- `opencertserver.intune.revocationsync`: Full revocation sync run.

**Collection Location**: `src/opencertserver.contrib.intune/`.

## ACME (RFC 8555)

### Metrics
- `opencertserver.acme.directory.requests`: Counter for /directory requests.
- `opencertserver.acme.directory.successes`: Counter for successful directory responses.
- `opencertserver.acme.directory.failures`: Counter for directory failures.
- `opencertserver.acme.directory.duration`: Histogram for directory duration.
- `opencertserver.acme.newnonce.requests`: Counter for /new-nonce requests.
- `opencertserver.acme.newnonce.successes`: Counter for successful nonce responses.
- `opencertserver.acme.newnonce.failures`: Counter for nonce failures.
- `opencertserver.acme.newnonce.duration`: Histogram for nonce duration.
- `opencertserver.acme.newaccount.requests`: Counter for /new-account requests.
- `opencertserver.acme.newaccount.successes`: Counter for successful account creations.
- `opencertserver.acme.newaccount.failures`: Counter for account creation failures (e.g., invalid JWS).
- `opencertserver.acme.newaccount.duration`: Histogram for account creation duration.
- `opencertserver.acme.neworder.requests`: Counter for /new-order requests.
- `opencertserver.acme.neworder.successes`: Counter for successful order creations.
- `opencertserver.acme.neworder.failures`: Counter for order creation failures.
- `opencertserver.acme.neworder.duration`: Histogram for order creation duration.
- `opencertserver.acme.orderfinalize.requests`: Counter for /order/{id}/finalize requests.
- `opencertserver.acme.orderfinalize.successes`: Counter for successful finalizes.
- `opencertserver.acme.orderfinalize.failures`: Counter for finalize failures.
- `opencertserver.acme.orderfinalize.duration`: Histogram for finalize duration.
- `opencertserver.acme.certificate.requests`: Counter for /order/{id}/certificate requests.
- `opencertserver.acme.certificate.successes`: Counter for successful certificate downloads.
- `opencertserver.acme.certificate.failures`: Counter for certificate download failures.
- `opencertserver.acme.certificate.duration`: Histogram for certificate duration.
- `opencertserver.acme.challengevalidation.requests`: Counter for challenge validation attempts.
- `opencertserver.acme.challengevalidation.successes`: Counter for successful validations.
- `opencertserver.acme.challengevalidation.failures`: Counter for validation failures.
- `opencertserver.acme.challengevalidation.duration`: Histogram for validation duration.
- `opencertserver.acme.challengevalidation.active`: Gauge for active pending challenges.
- `opencertserver.acme.keychange.requests`: Counter for /key-change requests.
- `opencertserver.acme.keychange.successes`: Counter for successful key rollovers.
- `opencertserver.acme.keychange.failures`: Counter for key rollover failures.
- `opencertserver.acme.keychange.duration`: Histogram for key rollover duration.
- `opencertserver.acme.revoke.requests`: Counter for /revoke-cert requests.
- `opencertserver.acme.revoke.successes`: Counter for successful revocations.
- `opencertserver.acme.revoke.failures`: Counter for revocation failures.
- `opencertserver.acme.revoke.duration`: Histogram for revocation duration.

### Traces
- `opencertserver.acme.directory`: Span for directory request.
- `opencertserver.acme.newnonce`: Span for nonce request.
- `opencertserver.acme.newaccount`: Span for account creation, sub-spans for JWS validation, account storage.
- `opencertserver.acme.neworder`: Span for order creation, sub-spans for authorization setup.
- `opencertserver.acme.orderfinalize`: Span for finalize, sub-spans for CSR validation, certificate issuance.
- `opencertserver.acme.certificate`: Span for certificate download.
- `opencertserver.acme.challengevalidation`: Span for validation, sub-spans for HTTP/DNS checks.
- `opencertserver.acme.keychange`: Span for key rollover, sub-spans for signature verification.
- `opencertserver.acme.revoke`: Span for revocation, sub-spans for certificate validation.

**Collection Location**: In `src/opencertserver.acme.server/Endpoints/` (e.g., `AccountEndpoints.cs`, `OrderEndpoints.cs`), wrap endpoint methods with spans, record metrics.

## OCSP (RFC 6960)

### Metrics
- `opencertserver.ocsp.request.requests`: Counter for OCSP requests.
- `opencertserver.ocsp.request.successes`: Counter for successful responses (good/revoked/unknown).
- `opencertserver.ocsp.request.failures`: Counter for failures (malformed, internalError, tryLater).
- `opencertserver.ocsp.request.duration`: Histogram for request processing duration.

### Traces
- `opencertserver.ocsp.request`: Span for OCSP request, sub-spans for request parsing, certificate lookup, response signing.

**Collection Location**: In `src/opencertserver.ca.server/Handlers/OcspHandler.cs`, wrap `Handle` method.

## CRL (RFC 5280)

### Metrics
- `opencertserver.crl.request.requests`: Counter for CRL requests.
- `opencertserver.crl.request.successes`: Counter for successful CRL responses.
- `opencertserver.crl.request.failures`: Counter for CRL failures.
- `opencertserver.crl.request.duration`: Histogram for request duration.
- `opencertserver.crl.generation.requests`: Counter for CRL generation triggers.
- `opencertserver.crl.generation.successes`: Counter for successful generations.
- `opencertserver.crl.generation.failures`: Counter for generation failures.
- `opencertserver.crl.generation.duration`: Histogram for generation duration.

### Traces
- `opencertserver.crl.request`: Span for CRL request.
- `opencertserver.crl.generation`: Span for CRL generation, sub-spans for certificate list building, signing.

**Collection Location**: In CRL handler (likely in `src/opencertserver.ca.server/`), wrap request and generation methods.

## CA Endpoints

### Metrics
- `opencertserver.ca.csr.requests`: Counter for /ca/csr POST requests.
- `opencertserver.ca.csr.successes`: Counter for successful CSR signings.
- `opencertserver.ca.csr.failures`: Counter for CSR signing failures.
- `opencertserver.ca.csr.duration`: Histogram for CSR signing duration.
- `opencertserver.ca.revoke.requests`: Counter for /ca/revoke DELETE requests.
- `opencertserver.ca.revoke.successes`: Counter for successful revocations.
- `opencertserver.ca.revoke.failures`: Counter for revocation failures.
- `opencertserver.ca.revoke.duration`: Histogram for revocation duration.

### Traces
- `opencertserver.ca.csr`: Span for CSR signing, sub-spans for validation, signing.
- `opencertserver.ca.revoke`: Span for revocation, sub-spans for proof verification.

**Collection Location**: In `src/opencertserver.ca.server/`, relevant handlers.

## CA Core

Core CA telemetry is intentionally separate from the CA HTTP handler instruments, which
use `opencertserver.ca`. The core implementation uses the
`opencertserver.ca.core` meter and activity source.

### Metrics
- `opencertserver.ca.core.operations`: Counter for core operations, tagged with a fixed `operation` name.
- `opencertserver.ca.core.successes`: Counter for operations that completed successfully.
- `opencertserver.ca.core.failures`: Counter for failed operations.
- `opencertserver.ca.core.duration`: Histogram in seconds.

### Traces
- Fixed operation spans for certificate signing (PEM and parsed request), revocation,
  root/published certificate retrieval, and CRL generation.

## Relational Data Stores

Shared relational stores use the `opencertserver.data` meter and activity source. Their
operation names are fixed and cover account, order, nonce, external-account-key, and
certificate storage operations.

### Metrics
- `opencertserver.data.store.operations`: Counter tagged with a fixed `operation` name.
- `opencertserver.data.store.successes`: Counter for completed store operations.
- `opencertserver.data.store.failures`: Counter for failed store operations.
- `opencertserver.data.store.duration`: Histogram in seconds.

PostgreSQL-specific atomic operations, certificate paging, and migrations use the
`opencertserver.data.postgresql` meter and activity source. MSSQL equivalents use
`opencertserver.data.mssql`. Each provider meter exposes `operations`, `successes`,
`failures`, and `duration` instruments, with only a fixed `operation` tag.

**Privacy:** CA and data activities contain no request-derived attributes. Metrics use
only fixed operation names; no SQL, connection strings, nonce/token values, account/order
identifiers, certificate contents/subjects/serials/thumbprints, profile names, or exception
messages are recorded.

## CLI Operations

### Metrics
- `opencertserver.cli.generatekeys.requests`: Counter for generate-keys commands.
- `opencertserver.cli.generatekeys.successes`: Counter for successful key generations.
- `opencertserver.cli.generatekeys.failures`: Counter for failures.
- `opencertserver.cli.generatekeys.duration`: Histogram for duration.
- `opencertserver.cli.printcert.requests`: Counter for print-cert commands.
- `opencertserver.cli.printcert.successes`: Counter for successful prints.
- `opencertserver.cli.printcert.failures`: Counter for failures.
- `opencertserver.cli.printcert.duration`: Histogram for duration.
- `opencertserver.cli.createcsr.requests`: Counter for create-csr commands.
- `opencertserver.cli.createcsr.successes`: Counter for successful CSRs.
- `opencertserver.cli.createcsr.failures`: Counter for failures.
- `opencertserver.cli.createcsr.duration`: Histogram for duration.
- `opencertserver.cli.signcsr.requests`: Counter for sign-csr commands.
- `opencertserver.cli.signcsr.successes`: Counter for successful signings.
- `opencertserver.cli.signcsr.failures`: Counter for failures.
- `opencertserver.cli.signcsr.duration`: Histogram for duration.
- `opencertserver.cli.estenroll.requests`: Counter for est-enroll commands.
- `opencertserver.cli.estenroll.successes`: Counter for successful enrollments.
- `opencertserver.cli.estenroll.failures`: Counter for failures.
- `opencertserver.cli.estenroll.duration`: Histogram for duration.
- `opencertserver.cli.estreerenroll.requests`: Counter for est-reenroll commands.
- `opencertserver.cli.estreerenroll.successes`: Counter for successful re-enrollments.
- `opencertserver.cli.estreerenroll.failures`: Counter for failures.
- `opencertserver.cli.estreerenroll.duration`: Histogram for duration.
- `opencertserver.cli.estservercertificates.requests`: Counter for est-server-certificates commands.
- `opencertserver.cli.estservercertificates.successes`: Counter for successful fetches.
- `opencertserver.cli.estservercertificates.failures`: Counter for failures.
- `opencertserver.cli.estservercertificates.duration`: Histogram for duration.

### Traces
- `opencertserver.cli.generatekeys`: Span for key generation.
- `opencertserver.cli.printcert`: Span for certificate printing.
- `opencertserver.cli.createcsr`: Span for CSR creation.
- `opencertserver.cli.signcsr`: Span for CSR signing.
- `opencertserver.cli.estenroll`: Span for EST enrollment, sub-spans for client operations.
- `opencertserver.cli.estreerenroll`: Span for EST re-enrollment.
- `opencertserver.cli.estservercertificates`: Span for CA cert fetch.

**Collection Location**: In `src/opencertserver.cli/`, wrap command handlers.

## Additional Cross-Cutting Metrics
- `opencertserver.auth.failures`: Counter for authentication failures across protocols.
- `opencertserver.tls.errors`: Counter for TLS-related errors.
- `opencertserver.errors.internal`: Counter for internal server errors.

**Collection Location**: In middleware or base handlers.
