# `opencertserver.certserver.tests`

This test project contains the executable server-side conformance coverage for the certificate server.
The feature files are intended to be used in a TDD style:

- the scenarios are fully bound and executable;
- passing scenarios document behavior the current implementation already satisfies;
- failing scenarios identify concrete protocol gaps rather than missing step definitions.

This README is the primary conformance overview for the project-level test harness.

## Conformance suites

### EST conformance

Primary files:

- `Features/EstConformance.feature`
- `StepDefinitions/EstConformance.cs`
- `StepDefinitions/EstEnrollment.cs`
- `StepDefinitions/CertificateServerFeatures.cs`

Focused run:

```zsh
dotnet test tests/opencertserver.certserver.tests/opencertserver.certserver.tests.csproj --filter "FullyQualifiedName~EstConformance"
```

Implemented and exercised coverage includes:

- mandatory EST `/simpleenroll` and `/simplereenroll` route support;
- authenticated enrollment and re-enrollment flows used by the in-memory test harness;
- RFC 7030 enrollment and re-enrollment response semantics, including authorization, renewal, and rekey handling;
- `/csrattrs` authentication, status-code handling, RFC 8951 base64 updates, and RFC 9908 template and legacy requirements covered by the current harness;
- `/serverkeygen` request and response handling, including base64 private-key delivery, `Content-Transfer-Encoding` tolerance, multipart responses, and encrypted key-delivery request validation;
- request-shape validation for enrollment endpoints;
- template-driven subject/key checks supported by the current fixture loader.

Current scope notes:

- optional and conditional EST scenarios remain intentionally dependent on server configuration and available feature support;
- the current test server configuration does not enable optional `/fullcmc` support or certificate-less TLS mutual authentication;
- future TDD work can extend the suite by enabling additional optional EST capabilities rather than by filling in missing bindings.

### ACME conformance

Primary files:

- `Features/AcmeConformance.feature`
- `Features/AcmeFeature.feature`
- `StepDefinitions/AcmeConformance.cs`
- `StepDefinitions/CertificateServerFeatures.cs`
- `StepDefinitions/TestAcmeIssuer.cs`
- `StepDefinitions/TestAcmeHttp01ChallengeValidator.cs`
- `StepDefinitions/TestAcmeDns01ChallengeValidator.cs`

Focused conformance run:

```zsh
dotnet test tests/opencertserver.certserver.tests/opencertserver.certserver.tests.csproj --filter "FullyQualifiedName~AcmeConformance"
```

Happy-path smoke run:

```zsh
dotnet test tests/opencertserver.certserver.tests/opencertserver.certserver.tests.csproj --filter "DisplayName~Can complete certificate flow"
```

Implemented and exercised coverage includes:

- directory discovery, index links, replay nonces, anti-replay behavior, and ACME problem-document shaping;
- ACME JWS envelope validation, request media-type enforcement, supported signature-algorithm handling, and POST-as-GET behavior;
- account creation, `onlyReturnExisting`, account retrieval and update, deactivation, and account order listing;
- order creation and retrieval, authorization/challenge resource exposure, strict CSR validation, invalid-order propagation, and issuance-time `notBefore` / `notAfter` enforcement;
- challenge acknowledgement flow, authorization deactivation, embedded ACME error objects, and `http-01` / `dns-01` validation semantics;
- certificate retrieval, including PEM certificate-chain responses for valid orders;
- account key rollover via `keyChange`, including replacement-key authorization behavior;
- certificate revocation via `revokeCert`, including both issuing-account and certificate-key authorization paths.

Primary implementation touchpoints exercised by the suite include:

- `src/opencertserver.acme.server/AcmeRegistration.cs`
- `src/opencertserver.acme.server/Endpoints/DirectoryEndpoints.cs`
- `src/opencertserver.acme.server/Endpoints/NonceEndpoints.cs`
- `src/opencertserver.acme.server/Endpoints/AccountEndpoints.cs`
- `src/opencertserver.acme.server/Endpoints/OrderEndpoints.cs`
- `src/opencertserver.acme.server/Endpoints/RevocationEndpoints.cs`
- `src/opencertserver.acme.server/Filters/AcmeProtocolResponseFilter.cs`
- `src/opencertserver.acme.server/Filters/ValidateAcmeRequestFilter.cs`
- `src/opencertserver.acme.server/RequestServices/DefaultRequestValidationService.cs`
- `src/opencertserver.acme.server/Services/DefaultAccountService.cs`
- `src/opencertserver.acme.server/Services/DefaultOrderService.cs`
- `src/opencertserver.acme.server/Services/DefaultRevocationService.cs`
- `src/opencertserver.acme.server/Workers/ValidationWorker.cs`
- `src/opencertserver.certserver/DefaultCsrValidator.cs`
- `src/opencertserver.certserver/DefaultIssuer.cs`

Current scope notes:

- the ACME conformance suite runs against the in-memory test harness in `StepDefinitions/CertificateServerFeatures.cs`, 
  so transport-level HTTPS and TLS assertions remain bounded by `TestServer` behavior;
- conditional ACME behaviors such as terms-of-service enforcement, external account binding, and alternate certificate 
  chains depend on runtime configuration and supported server features;
- `Features/AcmeFeature.feature` remains the quick smoke suite, while `Features/AcmeConformance.feature` is the broader 
  RFC 8555 behavior inventory.

### OCSP conformance

Primary files:

- `Features/OcspFeature.feature`
- `Features/OcspConformance.feature`
- `StepDefinitions/OcspConformance.cs`
- `StepDefinitions/CertificateServerFeatures.cs`

Focused conformance run:

```zsh
dotnet test tests/opencertserver.certserver.tests/opencertserver.certserver.tests.csproj --filter "FullyQualifiedName~OcspConformance"
```

Smoke run:

```zsh
dotnet test tests/opencertserver.certserver.tests/opencertserver.certserver.tests.csproj --filter "FullyQualifiedName~OcspFeature"
```

Implemented and exercised coverage includes:

- OCSP POST and GET endpoint bindings under `/ca/ocsp` with `Content-Type: application/ocsp-response` and DER-encoded response bodies;
- strict HTTP binding validation: `application/ocsp-request` content-type enforcement for POST requests, returning HTTP 400 for non-conforming clients when enabled;
- request parsing with distinct OCSP status responses: ASN.1/DER parse failures map to `malformedRequest`, unexpected handler failures map to `internalError`;
- pluggable `IValidateOcspRequest` validator chain returning the first non-null error status (`tryLater`, `sigRequired`, `unauthorized`);
- multi-request handling: one `SingleResponse` per requested `CertID`, preserving order-independent semantics for mixed-status request lists;
- full `CertID` matching: issuer name hash, issuer key hash, serial number, and hash algorithm are all validated before store lookup; mismatched issuer identity returns `unknown`;
- `good`, `revoked`, and `unknown` certificate status values; revoked responses include `revocationTime` and `revocationReason` when known;
- `producedAt`, `thisUpdate`, and `nextUpdate` freshness fields on every successful response;
- configurable freshness window via `CaProfile.OcspFreshnessWindow` (default 1 hour), exercised by the custom-freshness scenario;
- nonce echo: request nonce is read from `requestExtensions` and emitted back in response extensions;
- signed `BasicOCSPResponse` with a real cryptographic signature, `ResponderIdByKey` responder ID, and the signing certificate included in `certs`;
- delegated OCSP signing certificate path via `CaProfile.OcspSigningCertificate` and `CaProfile.OcspSigningKey`, falling back to the issuing CA when not configured;
- signed OCSP request validation via `OcspRequestSignatureValidator`: verifies RSA and ECDSA TBSRequest signatures using certificates embedded in the request, returning `unauthorized` for invalid signatures or missing certificate material.

Primary implementation touchpoints exercised by the suite include:

- `src/opencertserver.ca.server/Extensions.cs`
- `src/opencertserver.ca.server/Handlers/OcspHandler.cs`
- `src/opencertserver.ca.server/OcspRequestSignatureValidator.cs`
- `src/opencertserver.ca.utils/Ca/CaProfile.cs`
- `src/opencertserver.ca.utils/Ca/InMemoryCertificateStore.cs`
- `src/opencertserver.ca.utils/Ocsp/CertId.cs`
- `src/opencertserver.ca.utils/Ocsp/OcspRequest.cs`
- `src/opencertserver.ca.utils/Ocsp/OcspResponse.cs`
- `src/opencertserver.ca.utils/Ocsp/OcspBasicResponse.cs`
- `src/opencertserver.ca.utils/Ocsp/ResponseData.cs`
- `src/opencertserver.ca.utils/Ocsp/SingleResponse.cs`
- `src/opencertserver.ca.utils/Ocsp/RevokedInfo.cs`
- `src/opencertserver.ca/CaConfiguration.cs`

Current scope notes:

- the OCSP responder is exposed through the certificate authority server at `/ca/ocsp`;
- the conformance suite runs against the in-memory test harness in `StepDefinitions/CertificateServerFeatures.cs`, so transport-level HTTPS assertions remain bounded by `TestServer` behavior;
- delegated OCSP signing certificate scenarios use the issuing CA directly in the test harness; production deployments can supply a dedicated signing certificate with the appropriate EKU via `CaProfile`;
- `Features/OcspFeature.feature` remains the quick smoke suite for basic good, revoked, and unknown status checks; `Features/OcspConformance.feature` is the full RFC 6960 behavior inventory.

