# ACME compliance review for `OpenCertServer`

This document is the ACME counterpart to the EST conformance review.
It is a **server-side RFC 8555 conformance inventory** for the code that is actually wired into the certificate server today.

## Scope reviewed

Primary implementation files reviewed:

- `src/opencertserver.acme.server/AcmeRegistration.cs`
- `src/opencertserver.acme.server/Filters/AcmeProtocolResponseFilter.cs`
- `src/opencertserver.acme.server/Endpoints/DirectoryEndpoints.cs`
- `src/opencertserver.acme.server/Endpoints/NonceEndpoints.cs`
- `src/opencertserver.acme.server/Endpoints/AccountEndpoints.cs`
- `src/opencertserver.acme.server/Endpoints/OrderEndpoints.cs`
- `src/opencertserver.acme.server/Filters/AcmeIndexLinkFilter.cs`
- `src/opencertserver.acme.server/Filters/AcmeLocationFilter.cs`
- `src/opencertserver.acme.server/Filters/ValidateAcmeRequestFilter.cs`
- `src/opencertserver.acme.server/RequestServices/DefaultRequestValidationService.cs`
- `src/opencertserver.acme.server/Services/DefaultAccountService.cs`
- `src/opencertserver.acme.server/Services/DefaultOrderService.cs`
- `src/opencertserver.acme.server/Services/DefaultAuthorizationFactory.cs`
- `src/opencertserver.acme.server/Services/DefaultChallengeValidatorFactory.cs`
- `src/opencertserver.acme.server/Services/Http01ChallengeValidator.cs`
- `src/opencertserver.acme.server/Services/Dns01ChallengeValidator.cs`
- `src/opencertserver.acme.server/Workers/ValidationWorker.cs`
- `src/opencertserver.certserver/Program.cs`
- `src/opencertserver.certserver/DefaultCsrValidator.cs`
- `src/opencertserver.certserver/DefaultIssuer.cs`

Existing integration coverage reviewed:

- `tests/opencertserver.certserver.tests/Features/AcmeFeature.feature`
- `tests/opencertserver.certserver.tests/Features/AcmeConformance.feature`
- `tests/opencertserver.certserver.tests/StepDefinitions/CertificateServerFeatures.cs`
- `tests/opencertserver.certserver.tests/StepDefinitions/AcmeConformance.cs`

The new RFC inventory lives in `tests/opencertserver.certserver.tests/Features/AcmeConformance.feature`.

## Focused feature runs

### Item 1 focused run

```zsh
dotnet test tests/opencertserver.certserver.tests/opencertserver.certserver.tests.csproj --filter "Category=acme-item1"
```

Verified in this workspace:
- Total: `5`
- Passed: `5`
- Failed: `0`
- Skipped: `0`

Covered scenarios:
- `RFC 8555 Section 7.2 defines the newNonce resource`
- `RFC 8555 Sections 6.4 and 6.5 require anti-replay protection on POST requests`
- `RFC 8555 Section 6.5 requires fresh nonces on successful POST responses`
- `RFC 8555 Section 6.7 requires RFC 7807 style ACME problem documents`
- `RFC 8555 Section 6.5 requires protocol error responses to carry a fresh nonce`

### Item 2 focused run

```zsh
dotnet test tests/opencertserver.certserver.tests/opencertserver.certserver.tests.csproj --filter "Category=acme-item2"
```

Verified in this workspace:
- Total: `6`
- Passed: `6`
- Failed: `0`
- Skipped: `0`

Covered scenarios:
- `RFC 8555 Section 7.3 allows an ACME client to create a new account`
- `RFC 8555 Section 7.3 requires onlyReturnExisting to return an existing account without creating a new one`
- `RFC 8555 Section 7.3 requires account URLs to be dereferenceable with POST-as-GET`
- `RFC 8555 Section 7.3.2 allows account updates`
- `RFC 8555 Section 7.3.2 allows account deactivation`
- `RFC 8555 Section 7.3 requires the account orders list resource`

### Item 3 focused run

```zsh
dotnet test tests/opencertserver.certserver.tests/opencertserver.certserver.tests.csproj --filter "Category=acme-item3"
```

Verified in this workspace:
- Total: `13`
- Passed: `13`
- Failed: `0`
- Skipped: `0`

Covered scenarios:
- `RFC 8555 Sections 6.2 6.3 and 6.5 require ACME POST bodies to be signed JWS objects`
- `RFC 8555 Section 6.2 requires ACME POST requests to use the application jose+json media type`
- `RFC 8555 Section 6.3 requires the protected header URL to match the request URL`
- `RFC 8555 Section 6.2 forbids non-empty payloads on POST-as-GET requests`
- `RFC 8555 Section 6.5 distinguishes account-creation requests from existing-account requests`
- `RFC 8555 Section 6.5 requires newAccount requests to use a jwk rather than a kid`
- `RFC 8555 Section 6.5 requires existing-account requests to use a kid rather than a jwk`
- `RFC 8555 Section 6.5 requires unknown kids to be rejected as accountDoesNotExist`
- `RFC 8555 Section 6.5 requires unsupported signature algorithms to be rejected`
- `RFC 8555 Section 7.4 allows the core certificate flow for supported account key algorithms` (`RS256`)
- `RFC 8555 Section 7.4 allows the core certificate flow for supported account key algorithms` (`ES256`)
- `RFC 8555 Section 7.4 allows the core certificate flow for supported account key algorithms` (`ES384`)
- `RFC 8555 Section 7.4 allows the core certificate flow for supported account key algorithms` (`ES512`)

### ACME smoke regression run

```zsh
dotnet test tests/opencertserver.certserver.tests/opencertserver.certserver.tests.csproj --filter "DisplayName~Can complete certificate flow"
```

Verified in this workspace:
- Total: `4`
- Passed: `4`
- Failed: `0`
- Skipped: `0`

This confirms the existing ACME happy-path issuance scenarios still pass after the account lifecycle and URL-handling changes.

## Resolved items

1. **Add a centralized ACME error/response layer and emit fresh nonces on POST responses.**
   - Fixed in this workspace.
   - `src/opencertserver.acme.server/Filters/AcmeProtocolResponseFilter.cs` now centralizes ACME exception handling for the route group and emits RFC 8555 `application/problem+json` responses.
   - `src/opencertserver.acme.server/Endpoints/NonceEndpoints.cs` now exposes the replay-nonce helper so successful POST responses and ACME protocol error responses both receive fresh `Replay-Nonce` headers.
   - The focused item 1 scenarios in `tests/opencertserver.certserver.tests/Features/AcmeConformance.feature` are now implemented and passing.

2. **Fix account lifecycle conformance and account URL handling.**
   - Fixed in this workspace.
   - `src/opencertserver.acme.server/Services/DefaultAccountService.cs` now performs true JWK-based account lookup and supports account updates/deactivation.
   - `src/opencertserver.acme.server/Endpoints/AccountEndpoints.cs` now implements `onlyReturnExisting`, account retrieval/update/deactivation, and `/account/{accountId}/orders`, and emits absolute HTTPS account/order URLs.
   - `tests/opencertserver.certserver.tests/StepDefinitions/AcmeConformance.cs` now implements the focused item 2 BDD scenarios, all of which are passing in this workspace.

3. **Tighten ACME JWS and POST-as-GET request validation.**
   - Fixed in this workspace.
   - `src/opencertserver.acme.server/RequestServices/DefaultRequestValidationService.cs` now enforces `application/jose+json`, supports the RFC key algorithms used by the test client (`RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`), requires `jwk` on `newAccount`, requires `kid` on existing-account resources, rejects non-empty payloads on retrieval-only POST-as-GET endpoints, and maps unknown `kid` values to `accountDoesNotExist`.
   - `src/opencertserver.acme.server/Filters/ValidateAcmeRequestFilter.cs` now passes endpoint identity and request media type into the shared validator.
   - `tests/opencertserver.certserver.tests/Features/AcmeConformance.feature` and `tests/opencertserver.certserver.tests/StepDefinitions/AcmeConformance.cs` now implement the focused item 3 conformance scenarios, all of which are passing in this workspace.

## Current non-conformance list

The items below are the ACME counterpart to the EST non-conformance tracking list.
They are intended to be actionable, removable one by one, and backed by the detailed analysis in the sections that follow.

4. **Complete order metadata and strict finalization validation.**
   - Orders do not currently populate `Expires`.
   - `DefaultCsrValidator` is too permissive because it does not enforce exact identifier matching and can accept CSRs with no SAN extension.
   - `notBefore` / `notAfter` values are accepted into the order object but not clearly enforced during issuance.
   - Primary touchpoints: `src/opencertserver.acme.server/Services/DefaultOrderService.cs`, `src/opencertserver.acme.server/Endpoints/OrderEndpoints.cs`, `src/opencertserver.certserver/DefaultCsrValidator.cs`, `src/opencertserver.certserver/DefaultIssuer.cs`.

5. **Complete authorization and challenge RFC semantics.**
   - Authorization deactivation is not implemented.
   - Successful challenge validation does not set `validated`, so the challenge resource omits a required/expected RFC field.
   - Embedded challenge/order error objects still use ad-hoc types rather than RFC 8555 ACME problem URNs.
   - Primary touchpoints: `src/opencertserver.acme.server/Endpoints/OrderEndpoints.cs`, `src/opencertserver.acme.server/Workers/ValidationWorker.cs`, `src/opencertserver.acme.server/Services/Http01ChallengeValidator.cs`, `src/opencertserver.acme.server/Services/Dns01ChallengeValidator.cs`.

6. **Implement certificate revocation and advertise it in the directory.**
   - The client library already has revocation support, but the server does not expose `revokeCert`, a revocation endpoint, or the associated authorization rules.
   - Primary touchpoints: `src/opencertserver.acme.server/Endpoints/DirectoryEndpoints.cs` and new server-side revocation endpoint/service code.

7. **Implement account key rollover and advertise it in the directory.**
   - The client library already has `ChangeKey(...)`, but the server has no `keyChange` route, no nested-JWS verification logic, and no account-key replacement flow.
   - Primary touchpoints: `src/opencertserver.acme.server/Endpoints/DirectoryEndpoints.cs`, `src/opencertserver.acme.server/Endpoints/AccountEndpoints.cs` or a dedicated key-change endpoint, `src/opencertserver.acme.server/Services/DefaultAccountService.cs`, and account storage.

---

## 1. Endpoint surface and directory object

### Implemented today

The server is wired through `UseAcmeServer()` in:

- `src/opencertserver.certserver/Program.cs`
- `src/opencertserver.acme.server/AcmeRegistration.cs`

The registered ACME routes currently include:

- `GET /directory`
- `HEAD /new-nonce`
- `GET /new-nonce`
- `POST /new-account`
- `POST /account/{accountId}`
- `POST /account/{accountId}/orders`
- `POST /new-order`
- `POST /order/{orderId}`
- `POST /order/{orderId}/auth/{authId}`
- `POST /order/{orderId}/auth/{authId}/chall/{challengeId}`
- `POST /order/{orderId}/finalize`
- `POST /order/{orderId}/certificate`

This is defined in:

- `src/opencertserver.acme.server/Endpoints/DirectoryEndpoints.cs`
- `src/opencertserver.acme.server/Endpoints/NonceEndpoints.cs`
- `src/opencertserver.acme.server/Endpoints/AccountEndpoints.cs`
- `src/opencertserver.acme.server/Endpoints/OrderEndpoints.cs`

### Gaps and bugs found

1. **`revokeCert` is not implemented.**
   - `DirectoryEndpoints.cs` sets `RevokeCert = null`.
   - There is no `/revoke-cert` endpoint in `src/opencertserver.acme.server`.
   - RFC 8555 revocation support is therefore absent.

2. **`keyChange` is not implemented.**
   - `DirectoryEndpoints.cs` attempts `GetUrl("KeyChange")`, but there is no route named `KeyChange`.
   - There is no `/key-change` endpoint.
   - RFC 8555 account key rollover is therefore absent.

3. **Account management surface is now implemented for the core RFC 8555 lifecycle.**
   - `POST /account/{accountId}` now supports POST-as-GET retrieval, updates, and deactivation.
   - `POST /account/{accountId}/orders` now returns the account’s order URLs.

4. **The directory advertises only part of the RFC 8555 surface.**
   - `newNonce`, `newAccount`, and `newOrder` are present.
   - `newAuthz` is omitted, which is acceptable for RFC 8555.
   - `revokeCert` and `keyChange` are absent because the features are absent.

5. **Account URLs are now emitted as absolute HTTPS URLs.**
   - `AccountEndpoints.cs` now uses absolute URI generation for the `Location` header, the account resource URL, and the embedded `orders` URL.

---

## 2. HTTPS transport and TLS posture

### Implemented today

The production server config in `src/opencertserver.certserver/Program.cs`:

- enables HTTPS redirection;
- configures Kestrel HTTPS defaults;
- restricts TLS to `Tls12 | Tls13`.

That is directionally correct for RFC 8555's HTTPS requirement.

### Gaps and bugs found

1. **Transport conformance is not currently exercised by the certserver ACME tests.**
   - `CertificateServerFeatures.cs` uses `TestServer` and `UseUrls("http://localhost")`.
   - That is fine for in-memory testing, but it means HTTPS/TLS requirements are not presently covered by executable ACME conformance scenarios.

2. **No explicit ACME-specific transport assertions exist yet.**
   - The new feature file includes them, but implementation steps do not exist yet.

---

## 3. Replay nonces and anti-replay protection

### Implemented today

Nonce creation and validation exist:

- `src/opencertserver.acme.server/Services/DefaultNonceService.cs`
- `src/opencertserver.acme.server/Stores/InMemoryNonceStore.cs`
- `src/opencertserver.acme.server/RequestServices/DefaultRequestValidationService.cs`
- `src/opencertserver.acme.server/Filters/AcmeProtocolResponseFilter.cs`

What works:

- `HEAD /new-nonce` and `GET /new-nonce` mint nonces.
- POST validation rejects missing or unknown nonces.
- Nonces are one-time-use because `TryRemoveNonceAsync` removes them from the store.
- Successful ACME POST responses now include a fresh `Replay-Nonce` header.
- ACME protocol error responses now include a fresh `Replay-Nonce` header.

### Gaps and bugs found

No remaining replay-nonce response-shaping gaps are currently tracked for item 1 in this workspace.

---

## 4. JWS envelope and request validation

### Implemented today

The request-validation pipeline is wired by:

- `src/opencertserver.acme.server/Filters/ValidateAcmeRequestFilter.cs`
- `src/opencertserver.acme.server/RequestServices/DefaultRequestValidationService.cs`

What is already checked:

- POST requests are expected to bind to `JwsPayload`.
- ACME POST requests must use `application/jose+json`.
- flattened-JWS required members (`protected`, `payload`, `signature`) are validated before endpoint logic runs.
- `url` in the protected header must match the request URL.
- `nonce` must be present and known.
- `jwk` and `kid` are mutually exclusive.
- one of `jwk` or `kid` must be present.
- `newAccount` requests must use `jwk`, while existing-account resources must use `kid`.
- retrieval-only POST-as-GET resources reject non-empty JWS payloads.
- `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, and `ES512` are accepted.
- the JWS signature is verified against the supplied JWK or the stored account key.
- unknown `kid` values are rejected with `accountDoesNotExist`.

### Gaps and bugs found

No remaining item-3 request-validation gaps are currently tracked in this workspace.

---

## 5. ACME problem documents and error handling

### Implemented today

There is an ACME exception hierarchy in `src/opencertserver.acme.abstractions/Exceptions`, including:

- `BadNonceException`
- `BadSignatureAlgorithmException`
- `MalformedRequestException`
- `NotAllowedException`
- `NotAuthorizedException`
- `NotFoundException`
- `ConflictRequestException`

There is now also a centralized ACME response layer in:

- `src/opencertserver.acme.server/Filters/AcmeProtocolResponseFilter.cs`

This is a good starting point conceptually.

### Gaps and bugs found

3. **Challenge and order embedded error objects use ad-hoc strings instead of ACME URNs.**
   - Examples include `"incorrectResponse"`, `"connection"`, `"dns"`, `"custom:authExpired"`, and `"custom:orderExpired"` in the challenge validation path.
   - Those do not follow the RFC 8555 ACME problem URN namespace.

---

## 6. Account creation, lookup, update, and deactivation

### Implemented today

Basic account creation is present:

- route: `POST /new-account` in `AccountEndpoints.cs`
- service: `DefaultAccountService.CreateAccount(...)`
- HTTP account object projection: `src/opencertserver.acme.abstractions/HttpModel/Account.cs`

The code supports:

- `contact`
- `termsOfServiceAgreed`
- `onlyReturnExisting`

### Remaining gaps

1. **Terms-of-service enforcement is incomplete.**
   - `DirectoryEndpoints.cs` can advertise a TOS URL when `AcmeServerOptions.TOS.RequireAgreement` is set.
   - But `AccountEndpoints.cs` and `DefaultAccountService.cs` do not enforce rejection when the client omits `termsOfServiceAgreed` under a required-agreement policy.

2. **External account binding is not enforced.**
   - The directory metadata hardcodes `ExternalAccountRequired = false`.
   - There is no server-side validation of `externalAccountBinding` if that mode were to be enabled later.

---

## 7. Orders, order objects, and the account order list

### Implemented today

Order creation and retrieval are implemented in `OrderEndpoints.cs` and `DefaultOrderService.cs`.

What works:

- new orders can be created;
- order objects are returned;
- authorization URLs are generated;
- finalize URLs are generated;
- certificate URLs are exposed once the order becomes `valid` via `HttpModel.Order`.

The integration smoke flow in `AcmeFeature.feature` and `CertificateServerFeatures.cs` demonstrates the happy path.

### Gaps and bugs found

1. **Orders do not currently set `Expires`.**
   - `src/opencertserver.acme.abstractions/Model/Order.cs` has an `Expires` property.
   - `DefaultOrderService.CreateOrder(...)` never populates it.
   - `HttpModel.Order` therefore emits no order expiration information.

2. **Malformed order requests can fall through to non-RFC-shaped failures.**
   - `OrderEndpoints.cs` checks `Identifiers?.Count == 0`, but then force-uses `orderRequest!` and `Identifiers!`.
   - A truly null or badly shaped payload risks a server-side exception path rather than a proper ACME problem response.

3. **The order list / pagination behavior required by RFC 8555 is still absent beyond the non-paginated account order list resource.**
   - No implementation exists yet to return the account’s orders or paginate them.

---

## 8. Authorization and challenge resources

### Implemented today

Authorization creation and challenge generation are implemented in:

- `DefaultAuthorizationFactory.cs`
- `OrderEndpoints.cs`
- `src/opencertserver.acme.abstractions/HttpModel/Authorization.cs`
- `src/opencertserver.acme.abstractions/HttpModel/Challenge.cs`

Current behavior includes:

- one authorization per identifier;
- challenge generation for `dns-01` and, for non-wildcard identifiers, `http-01`;
- `POST` to a challenge URL transitions it to `processing` and selects that challenge.

A good detail already present:

- wildcard identifiers do **not** receive `http-01` challenges because `DefaultAuthorizationFactory` suppresses `http-01` when `authorization.IsWildcard` is true.

### Gaps and bugs found

1. **Authorization deactivation is not implemented.**
   - RFC 8555 allows deactivation via POST to the authorization URL.
   - `POST /order/{orderId}/auth/{authId}` currently ignores the payload and always returns the authorization resource unchanged.

2. **Valid challenges never record a validation timestamp.**
   - `ValidationWorker.cs` sets challenge status to `Valid`, but never sets `challenge.Validated`.
   - As a result, the challenge object cannot expose the validation time.

3. **Challenge error object types are not RFC ACME URNs.**
   - The challenge validation path emits ad-hoc strings, not `urn:ietf:params:acme:error:*` values.

4. **Challenge objects are available, but their RFC error semantics are incomplete.**
   - The state transitions exist.
   - The problem-detail shape does not fully match RFC 8555 yet.

---

## 9. Identifier validation methods (`http-01` and `dns-01`)

### Implemented today

Both challenge types are implemented:

- `http-01`: `src/opencertserver.acme.server/Services/Http01ChallengeValidator.cs`
- `dns-01`: `src/opencertserver.acme.server/Services/Dns01ChallengeValidator.cs`

What is good already:

- `http-01` computes the expected key authorization as `{token}.{thumbprint}`.
- `dns-01` computes the expected TXT value as `base64url(SHA-256(keyAuthorization))`.
- the worker updates order/authorization/challenge state after validation.
- wildcard identifiers naturally route to `dns-01` only.

### Gaps and bugs found

1. **The success path does not stamp `validated`.**
   - This is the most direct missing RFC field in the challenge object.

2. **`http-01` and `dns-01` errors are not surfaced as RFC-shaped ACME problem objects.**
   - The validator error payloads are internal model objects with non-URN types.

3. **`http-01` behavior is intentionally security-conscious, but not yet documented in conformance terms.**
   - The validator blocks loopback, link-local, and private address ranges.
   - That is good hardening, but it is extra policy on top of RFC 8555 and should eventually be documented explicitly so the conformance suite can distinguish policy from protocol.

---

## 10. Finalization and CSR validation

### Implemented today

Finalization is implemented in:

- `src/opencertserver.acme.server/Endpoints/OrderEndpoints.cs`
- `src/opencertserver.acme.server/Services/DefaultOrderService.cs`
- `src/opencertserver.certserver/DefaultCsrValidator.cs`
- `src/opencertserver.certserver/DefaultIssuer.cs`

What works:

- the finalize endpoint requires a non-empty `csr` field;
- only `ready` orders can be finalized;
- the certificate issuer is called;
- successful issuance marks the order `valid`;
- issuance failure can mark the order `invalid`.

### Gaps and bugs found

1. **CSR validation is too weak for RFC 8555 exact-identifier matching.**
   - `DefaultCsrValidator.cs` only checks that every DNS SAN in the CSR appears in the order.
   - It does **not** ensure that every identifier in the order appears in the CSR.
   - It also allows a CSR with no SAN extension at all because `All(...)` over an empty set returns `true`.
   - That is not strict enough for ACME finalization.

2. **The CSR validator does not produce RFC-specific ACME problem types.**
   - It only returns a boolean and a nullable `AcmeError`, and the current implementation returns `null` even on most mismatch paths.

3. **Requested `notBefore` / `notAfter` values are not clearly enforced end-to-end.**
   - They are accepted into the order object.
   - `DefaultIssuer.cs` does not use them when calling the CA.
   - The server may therefore echo values in the order while ignoring them during issuance.

4. **Order error objects are only partially populated.**
   - The order can become `invalid`, but the resulting `error` information is not yet consistently RFC shaped.

---

## 11. Certificate retrieval

### Implemented today

Certificate download is implemented in `OrderEndpoints.cs` and `DefaultOrderService.cs`.

What works:

- certificate retrieval is a POST to `/order/{orderId}/certificate`;
- the response content type is `application/pem-certificate-chain`;
- the response body is a PEM chain built from the issued certificate bytes.

### Gaps and bugs found

1. **No alternate chain support is exposed.**
   - RFC 8555 allows alternate chains via `Link: ...;rel="alternate"`.
   - The server does not currently emit alternate chain links.

2. **Certificate retrieval now participates in the centralized ACME POST response behavior.**
   - fresh `Replay-Nonce` handling and ACME problem-document shaping are provided by the shared ACME response filter.

---

## 12. Revocation support

### Implemented today

Client-side support exists in `src/CertesSlim/AcmeContext.cs` via `RevokeCertificate(...)`.

### Gaps and bugs found

1. **Server-side revocation is completely missing.**
   - No `revokeCert` directory entry.
   - No revocation endpoint.
   - No validation path for account-authorized revocation.
   - No validation path for certificate-key-authorized revocation.

This is a cleanly identifiable missing RFC 8555 feature area.

---

## 13. Account key rollover

### Implemented today

Client-side support exists in `src/CertesSlim/AcmeContext.cs` via `ChangeKey(...)`.

### Gaps and bugs found

1. **Server-side key rollover is completely missing.**
   - No `keyChange` endpoint.
   - No nested-JWS verification logic.
   - No account-key replacement logic in `DefaultAccountService` or storage.

This is another cleanly identifiable missing RFC 8555 feature area.

---

## 14. Existing executable coverage versus protocol surface

### Implemented today

The certserver test project currently has one ACME smoke feature:

- `tests/opencertserver.certserver.tests/Features/AcmeFeature.feature`

It proves:

- the server can complete a basic ACME issuance flow in the in-memory harness;
- the current route set is sufficient for the happy path used by `CertesSlim` in `CertificateServerFeatures.cs`.

### Gaps and bugs found

1. **Current ACME coverage is improving from smoke-level toward conformance-level.**
   - Focused executable scenarios now cover:
     - nonce replay rejection and ACME problem documents;
     - account update/deactivation and account order listing;
     - request media-type enforcement, key-identifier rules, unsupported-algorithm rejection, and POST-as-GET rejection rules.
   - Focused executable scenarios are still missing for:
     - revocation;
     - key rollover;
     - wildcard order behavior;
     - exact CSR identifier matching;
     - authorization deactivation and validation timestamps.

2. **The new `AcmeConformance.feature` is intentionally broader than the current implementation.**
   - It provides the requirement inventory before any step implementations are added.

---

## Overall assessment

### What is clearly implemented already

The current ACME server is **good enough for a narrow happy-path issuance flow**:

- directory discovery;
- nonce minting and nonce consumption;
- signed POST request validation;
- account creation;
- order creation;
- authorization and challenge exposure;
- `http-01` and `dns-01` validation;
- finalization;
- certificate download.

That is why the existing basic ACME feature can succeed.

### What is still non-conformant or incomplete

The major RFC 8555 gaps are captured in the numbered non-conformance list above.

In short, the current implementation is a functioning ACME happy-path server, but it still needs:

- stricter order/finalization validation;
- full authorization/challenge semantics;
- revocation support;
- key rollover support.

### Practical implementation touchpoints for the next phase

When the project moves from inventory to implementation, the highest-value files to change first are:

- `src/opencertserver.acme.server/RequestServices/DefaultRequestValidationService.cs`
- `src/opencertserver.acme.server/Filters/ValidateAcmeRequestFilter.cs`
- `src/opencertserver.acme.server/Endpoints/AccountEndpoints.cs`
- `src/opencertserver.acme.server/Endpoints/DirectoryEndpoints.cs`
- `src/opencertserver.acme.server/Endpoints/OrderEndpoints.cs`
- `src/opencertserver.acme.server/Workers/ValidationWorker.cs`
- `src/opencertserver.certserver/DefaultCsrValidator.cs`

And the project likely needs **one new centralized ACME error/response component** so the server can emit:

- `application/problem+json` responses;
- correct ACME error URNs;
- fresh `Replay-Nonce` headers on POST responses and failures.

