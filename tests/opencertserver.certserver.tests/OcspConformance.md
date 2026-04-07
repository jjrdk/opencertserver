# OCSP conformance review for `OpenCertServer`

This document is the OCSP counterpart to the EST and ACME conformance reviews.
It is a **server-side RFC 6960 conformance inventory** for the OCSP responder behavior that is currently wired into the certificate server, plus the ASN.1 OCSP model types implemented in `src/opencertserver.ca.utils/Ocsp`.

## Scope reviewed

Primary implementation files reviewed:

- `src/opencertserver.ca.server/Extensions.cs`
- `src/opencertserver.ca.server/Handlers/OcspHandler.cs`
- `src/opencertserver.ca/CaConfiguration.cs`
- `src/opencertserver.ca/CertificateAuthority.cs`
- `src/opencertserver.ca.utils/Ca/IStoreCertificates.cs`
- `src/opencertserver.ca.utils/Ca/InMemoryCertificateStore.cs`
- `src/opencertserver.ca.utils/Ocsp/OCSPRequest.cs`
- `src/opencertserver.ca.utils/Ocsp/TbsRequest.cs`
- `src/opencertserver.ca.utils/Ocsp/Request.cs`
- `src/opencertserver.ca.utils/Ocsp/CertId.cs`
- `src/opencertserver.ca.utils/Ocsp/Signature.cs`
- `src/opencertserver.ca.utils/Ocsp/OcspResponse.cs`
- `src/opencertserver.ca.utils/Ocsp/ResponseBytes.cs`
- `src/opencertserver.ca.utils/Ocsp/OcspBasicResponse.cs`
- `src/opencertserver.ca.utils/Ocsp/ResponseData.cs`
- `src/opencertserver.ca.utils/Ocsp/SingleResponse.cs`
- `src/opencertserver.ca.utils/Ocsp/RevokedInfo.cs`
- `src/opencertserver.ca.utils/Ocsp/ResponderIdByKey.cs`
- `src/opencertserver.ca.utils/Ocsp/ResponderIdByName.cs`
- `src/opencertserver.ca.utils/Ocsp/IResponderId.cs`
- `src/opencertserver.ca.utils/Ocsp/IValidateOcspRequest.cs`
- `src/opencertserver.ca.utils/Ocsp/OcspResponseStatus.cs`
- `src/opencertserver.ca.utils/Ocsp/OcspResponseStatusExtensions.cs`
- `src/opencertserver.ca.utils/Oids.cs`

Existing executable coverage reviewed:

- `tests/opencertserver.certserver.tests/Features/OcspFeature.feature`
- `tests/opencertserver.certserver.tests/StepDefinitions/Ocsp.cs`
- `tests/opencertserver.certserver.tests/StepDefinitions/CertificateServerFeatures.cs`

The new RFC inventory lives in `tests/opencertserver.certserver.tests/Features/OcspConformance.feature`.

## Current executable coverage

The existing OCSP coverage in this test project is still smoke-level rather than conformance-level.

What is already covered by the existing feature and steps:

- good certificate status lookup through `POST /ca/ocsp`;
- revoked certificate status lookup after server-side revocation;
- unknown certificate lookup;
- DER decoding of the response into `OcspResponse` / `OcspBasicResponse` / `SingleResponse`.

What is not yet covered by executable OCSP tests:

- OCSP error status behavior (`malformedRequest`, `internalError`, `tryLater`, `sigRequired`, `unauthorized`);
- request validation rules and extension handling;
- response signing and authorized responder requirements;
- nonce behavior;
- multi-request semantics;
- response freshness semantics (`producedAt`, `thisUpdate`, `nextUpdate`);
- HTTP GET binding and request media-type behavior;
- delegated responder certificate rules.

## What is clearly implemented today

### Responder endpoint wiring

The certificate authority server exposes an anonymous OCSP endpoint at:

- `POST /ca/ocsp`

This is registered in `src/opencertserver.ca.server/Extensions.cs` via `MapPost("/ocsp", OcspHandler.Handle)`.

### Response content type

`src/opencertserver.ca.server/Handlers/OcspHandler.cs` sets:

- `Content-Type: application/ocsp-response`

That is consistent with the RFC 6960 HTTP binding.

### Basic certificate-state lookup model

The responder currently maps each request to certificate state by calling:

- `IStoreCertificates.GetCertificateStatus(CertId certId)`

The default in-memory implementation in `src/opencertserver.ca.utils/Ca/InMemoryCertificateStore.cs` can currently return:

- `CertificateStatus.Good`
- `CertificateStatus.Revoked`
- `CertificateStatus.Unknown`

### OCSP ASN.1 model types exist

`src/opencertserver.ca.utils/Ocsp` already contains a substantial set of OCSP request and response classes, including:

- `OcspRequest`, `TbsRequest`, `Request`, `CertId`, and `Signature` for request-side structures;
- `OcspResponse`, `ResponseBytes`, `OcspBasicResponse`, `ResponseData`, `SingleResponse`, and `RevokedInfo` for response-side structures;
- `ResponderIdByName` and `ResponderIdByKey` for responder identification;
- `OcspResponseStatus` and `CertificateStatus` enums.

That gives the project a real OCSP data model to build on rather than requiring the protocol to be added from scratch.

### Issued certificates can advertise OCSP URLs

`src/opencertserver.ca/CertificateAuthority.cs` adds an Authority Information Access extension when `CaConfiguration.OcspUrls` is configured.
That means issued certificates can already publish OCSP responder URLs for relying parties.

## High-confidence RFC 6960 conformance gaps

The items below are the actionable OCSP non-conformance list for the current workspace.
They are ordered from most critical protocol correctness gaps to broader interoperability work.

1. **Generate real signed `BasicOCSPResponse` values.**
   - Current behavior in `src/opencertserver.ca.server/Handlers/OcspHandler.cs` constructs a successful response with:
     - `new OcspBasicResponse(...)`
     - a placeholder `signatureAlgorithm`
     - an empty signature byte array (`[]`)
     - no included responder certificates.
   - RFC 6960 requires successful basic responses to be signed by an authorized responder.
   - The current `signatureAlgorithm` also uses key-identification OIDs (`ecPublicKey` + `secp521r1`) instead of an actual signature algorithm identifier.
   - **Action:** select a real responder signing certificate/key, sign `ResponseData`, emit the correct signature algorithm OID, and include responder certs when needed.

2. **Match certificate status requests by the full `CertID`, not only by serial number.**
   - `src/opencertserver.ca.utils/Ca/InMemoryCertificateStore.cs` currently resolves status with:
     - `Convert.ToHexString(certId.SerialNumber)`
   - It does **not** validate `issuerNameHash`, `issuerKeyHash`, or the request hash algorithm.
   - RFC 6960 request matching is based on the complete `CertID` tuple.
   - **Action:** validate the issuer name hash, issuer key hash, and supported hash algorithm before returning `good`, `revoked`, or `unknown`.

3. **Correct `CertId` generation so it uses the issuer public key rather than the subject certificate public key.**
   - `src/opencertserver.ca.utils/Ocsp/CertId.cs` currently computes:
     - `issuerNameHash` from `certificate.IssuerName.RawData`
     - `issuerKeyHash` from `certificate.GetPublicKey()`
   - For a leaf certificate, the issuer key hash must be derived from the **issuer certificate public key**, not the subject certificate public key.
   - The current smoke tests pass because the store ignores the issuer hashes entirely.
   - **Action:** change `CertId.Create(...)` or add an overload that takes the issuer certificate and computes RFC-correct issuer hashes.

4. **Implement real OCSP request validation and map failures to the full RFC 6960 response-status set.**
   - `src/opencertserver.ca.server/Handlers/OcspHandler.cs` depends on `IValidateOcspRequest` validators.
   - `src/opencertserver.ca.utils/Ocsp/IValidateOcspRequest.cs` defines the extension point.
   - No concrete `IValidateOcspRequest` implementations are currently registered in the application code reviewed here.
   - Today the responder mostly collapses failures into either `malformedRequest` or `internalError`.
   - **Action:** add real request validators for ASN.1 shape, critical extensions, signature policy, and responder authorization; then map validation results to `malformedRequest`, `sigRequired`, `unauthorized`, or `tryLater` where appropriate.

5. **Implement signed-request verification when signed OCSP requests are accepted or required.**
   - `OcspRequest.Signature` and `TbsRequest.Sign(...)` exist, so the data model anticipates signed requests.
   - `OcspHandler` currently parses signed requests but does not verify request signatures.
   - RFC 6960 allows unsigned requests in general, but if signed requests are accepted or required, their signatures and signer authorization must be validated.
   - **Action:** add signature verification for `OcspRequest.Signature`, define when signatures are required, and emit `sigRequired` / `unauthorized` when policy requires it.

6. **Implement OCSP request and response extension support, especially nonce handling.**
   - `TbsRequest` and `Request` expose request extensions.
   - `ResponseData` does **not** currently expose or encode `responseExtensions` even though the RFC structure includes them.
   - `SingleResponse` does **not** expose or encode `singleExtensions` even though the RFC structure includes them.
   - `src/opencertserver.ca.utils/Oids.cs` already includes OCSP-related OIDs such as `OcspNonce`.
   - **Action:** add support for RFC 6960 extensions, starting with OCSP nonce handling, then `archiveCutoff`, `serviceLocator`, and `preferred signature algorithms` where desired.

7. **Fix ASN.1 modeling errors in the OCSP utility classes.**
   - `src/opencertserver.ca.utils/Ocsp/SingleResponse.cs` currently encodes `good` as an untagged `NULL`, but RFC 6960 requires the context-specific `good [0] IMPLICIT NULL` choice.
   - `src/opencertserver.ca.utils/Ocsp/RevokedInfo.cs` currently reads and writes `UtcTime`, while RFC 6960 defines `revocationTime` as `GeneralizedTime`.
   - `ResponseData` and `SingleResponse` omit RFC-defined extension fields from their object models.
   - `TbsRequest.Sign(...)` currently uses key algorithm identifiers instead of proper signature algorithm identifiers for request signatures.
   - `src/opencertserver.ca.utils/Ocsp/IResponderId.cs` is explicitly documented as a placeholder.
   - **Action:** audit every OCSP ASN.1 class against RFC 6960 and correct tagging, time encodings, optional fields, and algorithm identifiers before relying on them for conformance tests.

8. **Implement authorized-responder certificate handling.**
   - RFC 6960 requires successful responses to be signed either by the issuing CA or by a delegated responder certificate with `id-kp-OCSPSigning`.
   - The reviewed code injects only an `IResponderId`; it does not implement responder certificate selection, chain construction, or delegated responder authorization checks.
   - **Action:** add a responder credential model that binds `IResponderId` to an actual signer certificate/key pair and validates delegated responder authorization rules.

9. **Improve response freshness semantics instead of stamping everything with `UtcNow`.**
   - `OcspHandler` currently sets:
     - `producedAt = DateTimeOffset.UtcNow`
     - `thisUpdate = DateTimeOffset.UtcNow`
     - `nextUpdate` omitted
   - That is enough to build a parsable response, but not enough for a robust RFC 6960 freshness policy.
   - **Action:** introduce configurable freshness windows so `thisUpdate`, `nextUpdate`, and `producedAt` represent meaningful responder policy rather than only request time.

10. **Expand HTTP binding conformance beyond a single anonymous POST endpoint.**
    - The current responder only exposes `POST /ca/ocsp`.
    - There is no reviewed support for OCSP GET requests carrying base64-encoded request bytes in the URI.
    - There is also no reviewed request media-type validation for `application/ocsp-request`.
    - **Action:** decide whether to support the optional GET binding, validate request media types for POST, and add any desired HTTP caching headers that follow the responder freshness policy.

11. **Add explicit handling for non-issued certificate policies such as extended revoked behavior.**
    - The current store returns `unknown` whenever a serial number is not found.
    - RFC 6960 also defines the extended revoked model for some non-issued certificate cases.
    - **Action:** keep `unknown` as the default unless extended revoked is intentionally implemented, and if extended revoked is added, encode the required extensions and status semantics explicitly.

12. **Promote the current smoke coverage into executable RFC 6960 conformance tests.**
    - The new `Features/OcspConformance.feature` provides the requirement inventory only.
    - The existing executable suite in `Features/OcspFeature.feature` covers only three basic certificate-state outcomes.
    - **Action:** add BDD step definitions for the new OCSP conformance scenarios incrementally, starting with signed responses, full `CertID` matching, ASN.1 fixes, and nonce behavior.

## Detailed assessment by protocol area

### 1. Endpoint surface and HTTP behavior

Implemented today:

- anonymous OCSP responder endpoint at `POST /ca/ocsp`;
- response media type set to `application/ocsp-response`.

Observed gaps:

- no reviewed GET binding;
- no reviewed request media-type validation;
- no explicit OCSP-specific cache-control behavior.

### 2. Request parsing and validation

Implemented today:

- DER parsing of `OcspRequest` and `TbsRequest`;
- optional request-signature parsing through `Signature`;
- extension point for custom request validators via `IValidateOcspRequest`.

Observed gaps:

- no concrete request validators found in the reviewed application wiring;
- no signature verification for signed requests;
- no policy-driven use of `sigRequired` or `unauthorized`.

### 3. CertID and certificate-state lookup

Implemented today:

- `CertId` object model exists;
- `IStoreCertificates.GetCertificateStatus(...)` returns good / revoked / unknown;
- the smoke suite proves these three states can be emitted.

Observed gaps:

- current status lookup is serial-only rather than full-`CertID` based;
- issuer key hashing in `CertId.Create(...)` is not RFC-correct.

### 4. Successful response encoding

Implemented today:

- `OcspResponse`, `ResponseBytes`, `OcspBasicResponse`, `ResponseData`, `SingleResponse`, and `RevokedInfo` can all be encoded and decoded.

Observed gaps:

- successful responses are not cryptographically signed;
- the emitted signature algorithm identifier is not a proper OCSP response signing algorithm;
- response extensions and single-response extensions are not modeled.

### 5. Authorized responder model

Implemented today:

- responder identity abstraction exists through `IResponderId`, `ResponderIdByName`, and `ResponderIdByKey`.

Observed gaps:

- no binding from responder ID to a real signer certificate and key;
- no delegated responder validation logic.

### 6. Freshness and revocation timing

Implemented today:

- `producedAt` and `thisUpdate` values are emitted;
- revoked responses can include `RevokedInfo`.

Observed gaps:

- `nextUpdate` policy is absent;
- `RevokedInfo` uses UTCTime instead of the RFC 6960 `GeneralizedTime` encoding;
- timestamps reflect request time rather than a defined responder freshness model.

### 7. Certificate publication integration

Implemented today:

- `CertificateAuthority.SignCertificateRequest(...)` adds OCSP URLs to Authority Information Access when `CaConfiguration.OcspUrls` is configured.

Observed gaps:

- this publication path helps discovery, but it does not by itself make the responder RFC 6960 conformant.

## Overall assessment

The current OCSP implementation is **functional as a basic internal smoke responder**, but it is not yet RFC 6960 conformant.

The strongest parts already in place are:

- endpoint wiring;
- a reusable OCSP ASN.1 object model;
- good / revoked / unknown state projection from the certificate store;
- AIA publication of OCSP URLs in issued certificates when configured.

The largest protocol gaps are:

- the lack of a real signed authorized `BasicOCSPResponse`;
- incomplete request validation and status-code mapping;
- incorrect or incomplete ASN.1 details in several OCSP classes;
- serial-only matching instead of full `CertID` processing;
- missing nonce and extension support.

In short, the project already has enough OCSP infrastructure to support TDD-driven conformance work, but the responder still needs substantial protocol-correctness work before it can be described as RFC 6960 conformant.

