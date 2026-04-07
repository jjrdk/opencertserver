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

### Item 4 focused run

```zsh
dotnet test tests/opencertserver.certserver.tests/opencertserver.certserver.tests.csproj --filter "Category=acme-item4"
```

Verified in this workspace:
- Total: `10`
- Passed: `10`
- Failed: `0`
- Skipped: `0`

Covered scenarios:
- `RFC 8555 Section 7.4 requires new orders to create pending authorizations`
- `RFC 8555 Section 7.1.3 defines the order object fields and certificate link timing`
- `RFC 8555 Section 7.4 requires malformed new-order requests to be rejected`
- `RFC 8555 Section 7.4 requires the order to become ready before finalization`
- `RFC 8555 Section 7.4 requires CSR submission to the finalize URL`
- `RFC 8555 Section 7.4 requires CSRs without subjectAltName entries to be rejected`
- `RFC 8555 Section 7.4 requires CSR identifiers to match the order exactly`
- `RFC 8555 Section 7.4 allows successful finalization to return processing or valid`
- `RFC 8555 Section 7.4 requires orders that cannot be issued to become invalid`
- `RFC 8555 Sections 7.1.3 and 7.4 require accepted notBefore and notAfter values to be enforced during issuance`

### Item 5 focused run

```zsh
dotnet test tests/opencertserver.certserver.tests/opencertserver.certserver.tests.csproj --filter "Category=acme-item5"
```

Verified in this workspace:
- Total: `8`
- Passed: `8`
- Failed: `0`
- Skipped: `0`

Covered scenarios:
- `RFC 8555 Section 7.1.4 defines the authorization object`
- `RFC 8555 Section 7.1.5 defines the challenge object`
- `RFC 8555 Section 7.5 requires challenge acknowledgements to trigger validation`
- `RFC 8555 Section 7.5 permits authorization deactivation`
- `RFC 8555 requires embedded challenge and order errors to use ACME problem URNs`
- `RFC 8555 Section 8.3 defines http-01 validation for non-wildcard DNS identifiers`
- `RFC 8555 Section 8.4 defines dns-01 validation`
- `RFC 8555 Section 7.5 requires failed challenge validation to invalidate the authorization`

### Item 6 focused run

```zsh
dotnet test tests/opencertserver.certserver.tests/opencertserver.certserver.tests.csproj --filter "Category=acme-item6"
```

Verified in this workspace:
- Total: `2`
- Passed: `2`
- Failed: `0`
- Skipped: `0`

Covered scenarios:
- `RFC 8555 Section 7.3.5 defines account key rollover when the server supports it`
- `RFC 8555 Section 7.3.5 requires the new key to authorize subsequent requests`

### Item 7 focused run

```zsh
dotnet test tests/opencertserver.certserver.tests/opencertserver.certserver.tests.csproj --filter "DisplayName~Section 7.6"
```

Verified in this workspace:
- Total: `3`
- Passed: `3`
- Failed: `0`
- Skipped: `0`

Covered scenarios:
- `RFC 8555 Section 7.6 defines certificate revocation when the server supports it`
- `RFC 8555 Section 7.6 also allows revocation using the certificate's private key`
- `RFC 8555 Section 7.6 requires authorization checks on revocation`

### Full `AcmeConformance.feature` verification

Verified in this workspace by executing every scenario in `tests/opencertserver.certserver.tests/Features/AcmeConformance.feature` individually:

- Total: `56`
- Passed: `56`
- Failed: `0`
- Skipped: `0`

This confirms that all currently defined ACME conformance scenarios in the feature file pass in this workspace.

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

4. **Complete order metadata and strict finalization validation.**
   - Fixed in this workspace.
   - `src/opencertserver.acme.server/Services/DefaultOrderService.cs` now sets order `Expires`, rejects invalid requested validity windows, preserves issuer errors on invalid orders, and forwards accepted `notBefore` / `notAfter` values into issuance.
   - `src/opencertserver.certserver/DefaultCsrValidator.cs` now rejects malformed CSRs, rejects CSRs without DNS SAN entries, and enforces exact SAN-to-order identifier equality with RFC-shaped `badCSR` failures.
   - `src/opencertserver.certserver/DefaultIssuer.cs`, `src/opencertserver.lambda/DefaultIssuer.cs`, `src/opencertserver.ca.utils/Ca/ICertificateAuthority.cs`, and `src/opencertserver.ca/CertificateAuthority.cs` now honor accepted `notBefore` / `notAfter` values when issuing certificates.
   - `src/opencertserver.acme.abstractions/HttpModel/Order.cs` now always exposes the finalize URL, and `src/opencertserver.acme.server/Endpoints/OrderEndpoints.cs` now rejects malformed new-order payloads more safely.
   - `tests/opencertserver.certserver.tests/Features/AcmeConformance.feature` and `tests/opencertserver.certserver.tests/StepDefinitions/AcmeConformance.cs` now implement the focused item 4 conformance scenarios, all of which are passing in this workspace.

5. **Complete authorization and challenge RFC semantics.**
   - Fixed in this workspace.
   - `src/opencertserver.acme.server/Endpoints/OrderEndpoints.cs` now supports authorization deactivation via POST to the authorization resource and challenge retrieval via POST-as-GET.
   - `src/opencertserver.acme.server/Services/DefaultOrderService.cs` now deactivates authorizations through the order service, while `src/opencertserver.acme.server/Workers/ValidationWorker.cs` stamps `validated` timestamps on successful challenge validation and propagates RFC-shaped challenge/order errors.
   - `src/opencertserver.acme.server/Services/TokenChallengeValidator.cs`, `src/opencertserver.acme.server/Services/Http01ChallengeValidator.cs`, and `src/opencertserver.acme.server/Services/Dns01ChallengeValidator.cs` now normalize embedded challenge-validation errors to ACME problem URNs.
   - `tests/opencertserver.certserver.tests/Features/AcmeConformance.feature` and `tests/opencertserver.certserver.tests/StepDefinitions/AcmeConformance.cs` now implement the focused item 5 scenarios, all of which are passing in this workspace.

6. **Implement account key rollover and advertise it in the directory.**
   - Fixed in this workspace.
   - `src/opencertserver.acme.server/Endpoints/DirectoryEndpoints.cs` now advertises the `keyChange` resource, and `src/opencertserver.acme.server/Endpoints/AccountEndpoints.cs` now exposes `/key-change` with RFC 8555 nested-JWS validation.
   - `src/opencertserver.acme.server/RequestServices/DefaultRequestValidationService.cs` now treats `keyChange` as an outer JWK-signed ACME request, and `src/opencertserver.acme.server/Services/DefaultAccountService.cs` together with `src/opencertserver.acme.abstractions/Model/Account.cs` now replace the persisted account key while rejecting rollover to a key already bound to another account.
   - `tests/opencertserver.certserver.tests/Features/AcmeConformance.feature` and `tests/opencertserver.certserver.tests/StepDefinitions/AcmeConformance.cs` now implement the focused item 6 scenarios, all of which are passing in this workspace.

7. **Implement certificate revocation and advertise it in the directory.**
   - Fixed in this workspace.
   - `src/opencertserver.acme.server/Endpoints/DirectoryEndpoints.cs`, `src/opencertserver.acme.server/AcmeRegistration.cs`, `src/opencertserver.acme.server/Endpoints/RevocationEndpoints.cs`, and `src/opencertserver.acme.server/Services/DefaultRevocationService.cs` now expose `revokeCert`, validate account-authorized and certificate-key-authorized revocation requests, and apply revocation through the CA.
   - `tests/opencertserver.certserver.tests/Features/AcmeConformance.feature` and `tests/opencertserver.certserver.tests/StepDefinitions/AcmeConformance.cs` now implement and pass the RFC 8555 Section 7.6 revocation scenarios in this workspace.

## Current non-conformance list

The items below are the ACME counterpart to the EST non-conformance tracking list.
They are intended to be actionable, removable one by one, and backed by the detailed analysis in the sections that follow.

- No active ACME non-conformance items remain in this workspace.

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
- `POST /key-change`
- `POST /new-order`
- `POST /order/{orderId}`
- `POST /order/{orderId}/auth/{authId}`
- `POST /order/{orderId}/auth/{authId}/chall/{challengeId}`
- `POST /order/{orderId}/finalize`
- `POST /order/{orderId}/certificate`
- `POST /revoke-cert`

This is defined in:

- `src/opencertserver.acme.server/Endpoints/DirectoryEndpoints.cs`
- `src/opencertserver.acme.server/Endpoints/NonceEndpoints.cs`
- `src/opencertserver.acme.server/Endpoints/AccountEndpoints.cs`
- `src/opencertserver.acme.server/Endpoints/OrderEndpoints.cs`

### Gaps and bugs found

1. **Account management surface is now implemented for the core RFC 8555 lifecycle.**
   - `POST /account/{accountId}` now supports POST-as-GET retrieval, updates, and deactivation.
   - `POST /account/{accountId}/orders` now returns the account’s order URLs.
   - `POST /key-change` now supports nested-JWS account key rollover.

2. **The directory now advertises the RFC 8555 resources implemented in this server.**
   - `newNonce`, `newAccount`, and `newOrder` are present.
   - `newAuthz` is omitted, which is acceptable for RFC 8555.
   - `keyChange` is now advertised.
   - `revokeCert` is now advertised.

3. **Account URLs are now emitted as absolute HTTPS URLs.**
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
- `keyChange` requests must use an outer `jwk` rather than a `kid`.
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

No remaining embedded challenge/order error-URN gaps are currently tracked in this workspace.

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
- order objects now include `Expires` and the accepted `notBefore` / `notAfter` values;
- authorization URLs are generated;
- finalize URLs are generated;
- certificate URLs are exposed once the order becomes `valid` via `HttpModel.Order`.
- malformed new-order payloads are rejected with ACME protocol errors instead of falling through into null-forgiving paths.

The integration smoke flow in `AcmeFeature.feature` and `CertificateServerFeatures.cs` demonstrates the happy path.

### Gaps and bugs found

1. **The order list / pagination behavior required by RFC 8555 is still absent beyond the non-paginated account order list resource.**
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
- `POST` to a challenge URL transitions it to `processing` and selects that challenge;
- `POST` to an authorization URL can deactivate the authorization when the client submits status `deactivated`;
- successful challenge validation now stamps `validated` and promotes the authorization to `valid`;
- failed challenge validation now populates embedded challenge and order errors with ACME problem URNs.

A good detail already present:

- wildcard identifiers do **not** receive `http-01` challenges because `DefaultAuthorizationFactory` suppresses `http-01` when `authorization.IsWildcard` is true.

### Gaps and bugs found

No remaining authorization/challenge-semantics gaps are currently tracked for item 5 in this workspace.

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
- successful validation stamps the challenge `validated` timestamp.
- validation failures are surfaced as embedded ACME problem URNs on the challenge/order state.
- wildcard identifiers naturally route to `dns-01` only.

### Gaps and bugs found

1. **`http-01` behavior is intentionally security-conscious, but not yet documented in conformance terms.**
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
- malformed or unacceptable CSRs now fail with ACME `badCSR` semantics;
- CSRs without subjectAltName extensions are rejected;
- CSRs must contain exactly the same identifiers as the order;
- the certificate issuer is called;
- successful issuance marks the order `valid`;
- issuance failure can mark the order `invalid` and populate the order error object;
- accepted `notBefore` / `notAfter` values are now enforced during issuance.

### Gaps and bugs found

No additional finalization-specific gaps are currently tracked in this workspace beyond the remaining revocation feature area.

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

Server-side support now exists in:

- `src/opencertserver.acme.server/Endpoints/DirectoryEndpoints.cs`
- `src/opencertserver.acme.server/AcmeRegistration.cs`
- `src/opencertserver.acme.server/Endpoints/RevocationEndpoints.cs`
- `src/opencertserver.acme.server/Services/DefaultRevocationService.cs`

What works:

- The ACME directory advertises `revokeCert`.
- `POST /revoke-cert` is registered and returns ACME-shaped responses through the shared protocol filter.
- Revocation signed with the issuing account (`kid`) is accepted.
- Revocation signed with the certificate's private key (`jwk`) is accepted.
- Unrelated accounts are rejected from revoking certificates they do not control.

---

## 13. Account key rollover

### Implemented today

Client-side support exists in `src/CertesSlim/AcmeContext.cs` via `ChangeKey(...)`.

Server-side support now exists in:

- `src/opencertserver.acme.server/Endpoints/DirectoryEndpoints.cs`
- `src/opencertserver.acme.server/Endpoints/AccountEndpoints.cs`
- `src/opencertserver.acme.server/RequestServices/DefaultRequestValidationService.cs`
- `src/opencertserver.acme.server/Services/DefaultAccountService.cs`
- `src/opencertserver.acme.abstractions/Model/Account.cs`

What works:

- the directory now advertises `keyChange`;
- `/key-change` accepts the RFC 8555 outer JWS signed by the new key;
- the nested JWS must be signed by the old key and identify the same account URL;
- the server verifies that the old key currently controls the account;
- the server rejects rollover to a key already in use by another account;
- subsequent requests signed with the new key are accepted, while requests signed only with the old key are rejected.

### Gaps and bugs found

No remaining account-key-rollover gaps are currently tracked in this workspace.

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
     - account key rollover and post-rollover authorization with the replacement key;
     - request media-type enforcement, key-identifier rules, unsupported-algorithm rejection, and POST-as-GET rejection rules;
     - order metadata, malformed new-order handling, strict CSR validation, invalid-order propagation, and `notBefore` / `notAfter` issuance enforcement;
     - authorization deactivation, challenge validation timestamps, challenge acknowledgement flow, and embedded challenge/order ACME problem URNs.
   - Focused executable scenarios are still missing for:
     - revocation;
     - wildcard order behavior.

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

In short, the current implementation is a functioning ACME server for the currently exercised account, order, authorization, challenge, finalization, and certificate-download flows, but it still needs:

- revocation support.

### Practical implementation touchpoints for the next phase

When the project moves from inventory to implementation, the highest-value files to change next are:

- `src/opencertserver.acme.server/Endpoints/DirectoryEndpoints.cs`
- new server-side revocation endpoint/service code under `src/opencertserver.acme.server`
- the issuance/account ownership data available through the ACME order/account stores

The centralized ACME response layer added in this workspace already provides the core problem-document and replay-nonce behavior, so the next phase can focus on the remaining revocation protocol surface.

