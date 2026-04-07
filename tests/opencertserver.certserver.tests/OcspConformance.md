# OCSP conformance status for `OpenCertServer`

This document records the current RFC 6960 server-side OCSP status for the certificate server after implementing and verifying the OCSP conformance feature in `tests/opencertserver.certserver.tests/Features/OcspConformance.feature`.

## Scope

Primary implementation and model files reviewed/used by the OCSP responder:

- `src/opencertserver.ca.server/Extensions.cs`
- `src/opencertserver.ca.server/Handlers/OcspHandler.cs`
- `src/opencertserver.ca.utils/Ca/InMemoryCertificateStore.cs`
- `src/opencertserver.ca.utils/Ocsp/CertId.cs`
- `src/opencertserver.ca.utils/Ocsp/OcspResponse.cs`
- `src/opencertserver.ca.utils/Ocsp/OcspBasicResponse.cs`
- `src/opencertserver.ca.utils/Ocsp/ResponseData.cs`
- `src/opencertserver.ca.utils/Ocsp/SingleResponse.cs`
- `src/opencertserver.ca.utils/Ocsp/RevokedInfo.cs`
- `src/opencertserver.ca.utils/Ocsp/IValidateOcspRequest.cs`

Primary executable coverage:

- `tests/opencertserver.certserver.tests/Features/OcspConformance.feature`
- `tests/opencertserver.certserver.tests/StepDefinitions/OcspConformance.cs`

## Verification status

Focused OCSP conformance verification is green:

- `dotnet test tests/opencertserver.certserver.tests/opencertserver.certserver.tests.csproj --filter "FullyQualifiedName~OcspConformance" --no-restore`
- Result: **36 passed, 0 failed**

This moves the OCSP test coverage from smoke-level checks to an executable RFC 6960-oriented conformance suite.

## Implemented responder behavior

### Endpoint surface and HTTP binding

The CA server now exposes both OCSP bindings under `/ca`:

- `POST /ca/ocsp`
- `GET /ca/ocsp/{requestEncoded}`

Implemented in `src/opencertserver.ca.server/Extensions.cs`.

For accepted requests, `src/opencertserver.ca.server/Handlers/OcspHandler.cs` returns:

- `Content-Type: application/ocsp-response`
- DER-encoded `OcspResponse` bodies

Malformed GET payload encodings are mapped to an OCSP `malformedRequest` response rather than a generic HTTP error body.

### Request parsing and status mapping

`OcspHandler.ProcessRequestAsync(...)` now separates parse failures from processing failures:

- ASN.1/DER parse failures return `OcspResponseStatus.MalformedRequest`
- later unexpected failures return `OcspResponseStatus.InternalError`

The handler also invokes any registered `IValidateOcspRequest` validators and returns the first non-null OCSP error status they produce. This is the mechanism used for conformance scenarios such as:

- `tryLater`
- `sigRequired`
- `unauthorized`

### Multi-request handling

The responder parses the `TBSRequest.requestList` and evaluates every requested `CertID`.

The successful response builds one `SingleResponse` per requested `CertID`, preserving the order-independent status semantics for mixed-state requests.

### Full `CertID` matching behavior

Certificate lookup is still backed by `IStoreCertificates`, but the responder now validates issuer identity before store lookup when a CA profile is available:

- request `issuerNameHash` must match the issuing CA subject name hash
- request `issuerKeyHash` must match the issuing CA public key hash
- request hash algorithm must be one of the supported OCSP hash algorithms

If the issuer hashes do not match the configured CA profile, the responder returns `unknown` for that request.

This validation is implemented in `OcspHandler.GetCertificateStatusWithCaValidation(...)`.

### Correct `CertId` construction

`src/opencertserver.ca.utils/Ocsp/CertId.cs` now includes an overload that takes the issuer certificate:

- `CertId.Create(X509Certificate2 certificate, X509Certificate2 issuerCertificate, HashAlgorithmName hashAlgorithm)`

That overload computes the RFC-correct:

- issuer name hash from the issuer certificate subject
- issuer key hash from the issuer certificate public key

### Successful response structure and signing

Successful OCSP responses are emitted as real `BasicOCSPResponse` values with:

- `responseStatus = successful`
- `responseBytes` present
- `responseType = id-pkix-ocsp-basic`
- populated `tbsResponseData`
- a real cryptographic signature
- the responder signing certificate included in `certs`

`OcspHandler.SignResponseData(...)` currently signs with SHA-256 using the active CA profile key:

- RSA → `sha256WithRSAEncryption`
- ECDSA → `ecdsa-with-SHA256`

The responder ID is emitted as `ResponderIdByKey`, derived from the signer certificate public key hash.

### Authorized responder behavior

For the current test server setup, the issuing CA signs its own OCSP responses directly.

That satisfies the conformance scenarios that require successful responses to be signed by either:

- the issuing CA, or
- a delegated responder certificate authorized by that CA

The executable coverage verifies the signature and ensures the signer can be identified from the response and included certificates.

### Certificate status values

The OCSP responder now exercises and verifies all three primary RFC 6960 status values:

- `good`
- `revoked`
- `unknown`

`InMemoryCertificateStore.GetCertificateStatus(...)` supplies the backing status result, and revoked responses include:

- `revocationTime`
- `revocationReason` when known

### Freshness and time values

Successful basic responses now include:

- `producedAt` in `ResponseData`
- `thisUpdate` on every `SingleResponse`
- optional `nextUpdate`

The responder currently uses a simple freshness window:

- `producedAt = UtcNow`
- `thisUpdate = UtcNow`
- `nextUpdate = UtcNow + 1 hour`

This is enough to satisfy the implemented RFC inventory and keeps `nextUpdate >= thisUpdate`.

### Request and response extensions

The OCSP ASN.1 model now supports the extension fields needed by the conformance scenarios:

- `ResponseData.ResponseExtensions`
- `SingleResponse.SingleExtensions`

The responder currently implements nonce echo behavior:

- request nonce is read from `requestExtensions`
- when present, the same nonce is emitted back in the response extensions

### ASN.1 model corrections

The OCSP utility types now reflect the relevant RFC 6960 encoding requirements used by the tests:

- `SingleResponse` uses the context-specific OCSP `CertStatus` tags for `good`, `revoked`, and `unknown`
- `RevokedInfo.revocationTime` is encoded as `GeneralizedTime`
- `ResponseData.producedAt`, `SingleResponse.thisUpdate`, and `SingleResponse.nextUpdate` are encoded as `GeneralizedTime`
- response and single-response extensions are modeled and encoded

## Executable coverage now in place

The OCSP conformance feature now exercises responder behavior for:

- response media type and DER body encoding
- malformed/internal/temporary/error status handling
- POST and optional GET binding behavior
- request-list parsing and per-`CertID` evaluation
- issuer-name-hash / issuer-key-hash / serial-number matching semantics
- one `SingleResponse` per requested certificate
- request and single-request extension handling expectations
- optional signed-request policy paths
- successful `BasicOCSPResponse` structure and signature verification
- responder ID and included certificate material
- `good` / `revoked` / `unknown` status values
- `producedAt`, `thisUpdate`, and `nextUpdate`
- authorized responder/signer requirements
- nonce echo behavior
- multi-request mixed-status semantics

## Remaining follow-up items

The RFC 6960 inventory covered by `OcspConformance.feature` is now implemented and passing, but there are still some sensible follow-up improvements that are outside the current green OCSP suite:

1. **Implemented:** enforce `application/ocsp-request` for POST request media types if strict HTTP binding validation is desired. Added `StrictOcspHttpBinding` property to `CaConfiguration` and validation in `OcspHandler.Handle`. Tested with scenario "Strict OCSP HTTP binding enforces application/ocsp-request content-type for POST requests" that verifies 400 Bad Request is returned for incorrect content-type when strict binding is enabled.

2. **Implemented:** make responder freshness policy configurable instead of always using `UtcNow` and `UtcNow + 1 hour`. Added `OcspFreshnessWindow` property to `CaProfile` with default of 1 hour. Modified `OcspHandler.ProcessRequestAsync` to use `profile.OcspFreshnessWindow`. Tested with scenario "OCSP responder freshness policy is configurable" that verifies nextUpdate is thisUpdate plus 2 hours when configured.

3. **Implemented:** add a true delegated OCSP signing certificate path, rather than only the issuing-CA signer path used in tests. Added `OcspSigningCertificate` and `OcspSigningKey` properties to `CaProfile`. Modified `OcspHandler` to use delegated cert/key if available, falling back to CA cert/key. This allows production deployments to use dedicated OCSP signing certificates with proper EKU.

4. **Implemented:** extend request-signature verification from policy modeling into a full production authorization flow if signed OCSP requests must be supported operationally. Created `OcspRequestSignatureValidator` that verifies TBSRequest signatures using included certificates. Registered in DI for all CA configurations. Validates RSA/ECDSA signatures and returns `unauthorized` for invalid signatures or missing certs.

## Summary

The OCSP responder is no longer a placeholder implementation. It now has:

- real RFC-shaped OCSP request/response ASN.1 handling,
- full per-request `CertID` evaluation,
- signed successful `BasicOCSPResponse` messages,
- nonce echo support,
- GET and POST endpoint coverage,
- executable RFC 6960 conformance coverage that is currently green.

That is the current OCSP-specific status for the implemented RFC 6960 inventory in this workspace.
