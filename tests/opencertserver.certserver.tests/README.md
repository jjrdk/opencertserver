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
- `StepDefinitions/Ocsp.cs`
- `StepDefinitions/CertificateServerFeatures.cs`
- `OcspConformance.md`

Existing smoke run:

```zsh
dotnet test tests/opencertserver.certserver.tests/opencertserver.certserver.tests.csproj --filter "FullyQualifiedName~OcspFeature"
```

Current suite layout:

- `Features/OcspFeature.feature` is the existing OCSP smoke suite for basic good, revoked, and unknown certificate-state checks;
- `Features/OcspConformance.feature` is the RFC 6960 requirement inventory and currently contains scenarios only;
- `OcspConformance.md` records the current implementation assessment, gaps, and numbered follow-up tasks.

Current scope notes:

- the OCSP responder is currently exposed through the certificate authority server endpoint at `/ca/ocsp`;
- the current OCSP review covers both responder behavior in `src/opencertserver.ca.server` and the ASN.1 OCSP structures in `src/opencertserver.ca.utils/Ocsp`;
- the OCSP conformance feature is intentionally added before bindings so future work can implement responder requirements in TDD order.

