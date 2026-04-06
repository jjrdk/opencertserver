# ACME compliance review for `OpenCertServer`

This document is the ACME counterpart to the EST conformance review.
It is a **server-side RFC 8555 conformance inventory** for the code that is actually wired into the certificate server today.

## Scope reviewed

Primary implementation files reviewed:

- `src/opencertserver.acme.server/AcmeRegistration.cs`
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
- `tests/opencertserver.certserver.tests/StepDefinitions/CertificateServerFeatures.cs`

The new RFC inventory lives in `tests/opencertserver.certserver.tests/Features/AcmeConformance.feature`.

## Current non-conformance list

The items below are the ACME counterpart to the EST non-conformance tracking list.
They are intended to be actionable, removable one by one, and backed by the detailed analysis in the sections that follow.

1. **Add a centralized ACME error/response layer and emit fresh nonces on POST responses.**
   - The server currently lacks a component that converts `AcmeException` instances into RFC 8555 `application/problem+json` responses.
   - Successful POST responses and protocol error responses also do not consistently include a fresh `Replay-Nonce` header.
   - Primary touchpoints: `src/opencertserver.acme.server/Filters/ValidateAcmeRequestFilter.cs`, `src/opencertserver.acme.server/RequestServices/DefaultRequestValidationService.cs`, the ACME endpoint classes, and a new centralized response/middleware component.

2. **Fix account lifecycle conformance and account URL handling.**
   - `onlyReturnExisting` is currently wrong because `DefaultAccountService.FindAccount(...)` creates a new account instead of only finding one.
   - `POST /account/{accountId}` and `POST /account/{accountId}/orders` still return `501`, so account retrieval/update/deactivation and order listing are incomplete.
   - Account and orders URLs are currently built with `GetPathByName(...)` instead of absolute URLs.
   - Primary touchpoints: `src/opencertserver.acme.server/Services/DefaultAccountService.cs`, `src/opencertserver.acme.server/Endpoints/AccountEndpoints.cs`.

3. **Tighten ACME JWS and POST-as-GET request validation.**
   - The server validates nonce, URL, signature, and `jwk`/`kid` exclusivity, but it does not explicitly enforce `application/jose+json`, endpoint-specific `jwk` versus `kid` rules, or empty payloads for POST-as-GET.
   - Supported algorithms are currently limited to `RS256` and `ES256`, which is narrower than the client library capability already present in `CertesSlim`.
   - Primary touchpoints: `src/opencertserver.acme.server/RequestServices/DefaultRequestValidationService.cs`, `src/opencertserver.acme.server/Filters/ValidateAcmeRequestFilter.cs`.

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

3. **Account management surface is only partially implemented.**
   - `POST /account/{accountId}` returns `501` in `AccountEndpoints.cs`.
   - `POST /account/{accountId}/orders` returns `501` in `AccountEndpoints.cs`.
   - That leaves account update, deactivation, and account order listing non-conformant.

4. **The directory advertises only part of the RFC 8555 surface.**
   - `newNonce`, `newAccount`, and `newOrder` are present.
   - `newAuthz` is omitted, which is acceptable for RFC 8555.
   - `revokeCert` and `keyChange` are absent because the features are absent.

5. **Likely interoperability issue: account URLs are built as relative paths, not absolute URLs.**
   - `AccountEndpoints.cs` uses `links.GetPathByName(...)` for `ordersUrl` and `accountUrl`.
   - ACME resource fields are specified as URLs; using relative paths is risky and should be treated as non-conformant until proven interoperable with strict clients.

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

What works:

- `HEAD /new-nonce` and `GET /new-nonce` mint nonces.
- POST validation rejects missing or unknown nonces.
- Nonces are one-time-use because `TryRemoveNonceAsync` removes them from the store.

### Gaps and bugs found

1. **Fresh `Replay-Nonce` headers are only added on `/new-nonce`.**
   - `NonceEndpoints.AddNonceHeader(...)` is only called by the nonce endpoint handlers.
   - RFC 8555 requires fresh nonces on successful POST responses and on protocol error responses as well.
   - The current server does not add them globally.

2. **`badNonce` responses are not rendered as ACME problem documents.**
   - `DefaultRequestValidationService` throws `BadNonceException`.
   - No ACME exception-to-`application/problem+json` mapping is currently present.
   - So even though the server detects bad nonces, the response shape is not RFC conformant.

---

## 4. JWS envelope and request validation

### Implemented today

The request-validation pipeline is wired by:

- `src/opencertserver.acme.server/Filters/ValidateAcmeRequestFilter.cs`
- `src/opencertserver.acme.server/RequestServices/DefaultRequestValidationService.cs`

What is already checked:

- POST requests are expected to bind to `JwsPayload`.
- `url` in the protected header must match the request URL.
- `nonce` must be present and known.
- `jwk` and `kid` are mutually exclusive.
- one of `jwk` or `kid` must be present.
- the JWS signature is verified against the supplied JWK or the stored account key.

### Gaps and bugs found

1. **Only `RS256` and `ES256` are accepted.**
   - `_supportedAlgs` in `DefaultRequestValidationService.cs` is hardcoded to `["RS256", "ES256"]`.
   - That is narrower than the algorithms already present in `CertesSlim.Json.JwsSigner`.
   - It is also likely to break the existing `AcmeFeature.feature` example rows for `ES384` and `ES512` if those are executed against the current server.

2. **No explicit enforcement of `application/jose+json`.**
   - I found no content-type validation in the request pipeline.
   - RFC 8555 requires the ACME POST body format and media type.

3. **No explicit POST-as-GET payload enforcement.**
   - Retrieval endpoints currently accept a `JwsPayload`, but do not verify that the payload is the empty string.
   - That means non-empty POST-as-GET requests appear to be accepted when they should be rejected.

4. **No endpoint-specific `jwk` versus `kid` enforcement beyond mutual exclusion.**
   - RFC 8555 requires `jwk` on `newAccount` and `keyChange`, and `kid` on existing-account resources.
   - The current validator only enforces “one or the other”, not “the correct one for this endpoint”.

5. **Unknown `kid` handling is not RFC-shaped.**
   - `ValidateSignatureAsync` converts a missing account lookup into `MalformedRequestException("KID could not be found.")`.
   - The server should return an ACME error document with the appropriate problem type, not a generic malformed flow.

6. **There is no verification that the JWS body is a valid flattened JWS beyond model binding.**
   - The envelope shape is assumed from deserialization into `JwsPayload`.
   - Additional ACME/JWS constraints are not explicitly enforced.

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

This is a good starting point conceptually.

### Gaps and bugs found

1. **I found no exception-handling layer that converts ACME exceptions into RFC 8555 problem documents.**
   - A workspace search did not find `UseExceptionHandler`, `IExceptionHandler`, `Results.Problem`, or any ACME-specific error middleware in `src/opencertserver.acme.server`.
   - In practice this means the server is not currently producing reliable `application/problem+json` error bodies.

2. **HTTP status mapping is not centralized.**
   - Even when the code throws a semantically meaningful ACME exception, there is no visible response factory that maps it to the expected ACME status code and problem document.

3. **Challenge and order embedded error objects use ad-hoc strings instead of ACME URNs.**
   - Examples include `"incorrectResponse"`, `"connection"`, `"dns"`, `"custom:authExpired"`, and `"custom:orderExpired"` in the challenge validation path.
   - Those do not follow the RFC 8555 ACME problem URN namespace.

4. **Protocol error responses do not appear to guarantee a fresh nonce.**
   - This compounds the nonce non-conformance above.

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

### Gaps and bugs found

1. **`onlyReturnExisting` is implemented incorrectly.**
   - `DefaultAccountService.FindAccount(...)` calls `CreateAccount(...)` and returns the new account.
   - This means `onlyReturnExisting = true` creates accounts instead of only returning existing ones.
   - That is a direct RFC 8555 conformance failure.

2. **Unknown existing-account lookup returns the wrong behavior.**
   - Because of the bug above, the server does not currently have the RFC-required “do not create a new account” behavior.

3. **Account update is not implemented.**
   - `POST /account/{accountId}` returns `501`.

4. **Account deactivation is not implemented.**
   - Same endpoint, same `501`.

5. **Terms-of-service enforcement is incomplete.**
   - `DirectoryEndpoints.cs` can advertise a TOS URL when `AcmeServerOptions.TOS.RequireAgreement` is set.
   - But `AccountEndpoints.cs` and `DefaultAccountService.cs` do not enforce rejection when the client omits `termsOfServiceAgreed` under a required-agreement policy.

6. **External account binding is not enforced.**
   - The directory metadata hardcodes `ExternalAccountRequired = false`.
   - There is no server-side validation of `externalAccountBinding` if that mode were to be enabled later.

7. **The account object's URLs are likely not emitted as absolute URLs.**
   - `GetPathByName(...)` is used instead of `GetUriByName(...)`.

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

1. **The account order-list resource is not implemented.**
   - `/account/{accountId}/orders` returns `501`.
   - RFC 8555 requires this resource as part of the account object.

2. **Orders do not currently set `Expires`.**
   - `src/opencertserver.acme.abstractions/Model/Order.cs` has an `Expires` property.
   - `DefaultOrderService.CreateOrder(...)` never populates it.
   - `HttpModel.Order` therefore emits no order expiration information.

3. **Malformed order requests can fall through to non-RFC-shaped failures.**
   - `OrderEndpoints.cs` checks `Identifiers?.Count == 0`, but then force-uses `orderRequest!` and `Identifiers!`.
   - A truly null or badly shaped payload risks a server-side exception path rather than a proper ACME problem response.

4. **The order list / pagination behavior required by RFC 8555 is absent.**
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

2. **Certificate retrieval still depends on the broader ACME POST response gaps.**
   - fresh nonce behavior is missing;
   - problem-document behavior is missing for retrieval errors.

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

1. **Current ACME coverage is smoke-level, not conformance-level.**
   - There are no existing executable scenarios for:
     - nonce replay rejection;
     - ACME problem documents;
     - account update/deactivation;
     - account order listing;
     - POST-as-GET rejection rules;
     - revocation;
     - key rollover;
     - wildcard order behavior;
     - exact CSR identifier matching.

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

- RFC-shaped error handling and nonce emission;
- complete account lifecycle support;
- stricter JWS and POST-as-GET enforcement;
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

