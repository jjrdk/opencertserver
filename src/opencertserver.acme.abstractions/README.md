# opencertserver.acme.abstractions

The shared **ACME (RFC 8555) contracts and models** for the OpenCertServer
ecosystem. This project contains no protocol behaviour of its own — only the
interfaces and data shapes that the ACME server, the ASP.NET Core ACME client,
and the per-route YARP integration all depend on, so those three stay decoupled
and can be swapped independently. Its root namespace is
`OpenCertServer.Acme.Abstractions`
([opencertserver.acme.abstractions.csproj:4](opencertserver.acme.abstractions.csproj#L4)).

The only dependency is the
[`CertesSlim`](../CertesSlim/README.md) ACME protocol client
([opencertserver.acme.abstractions.csproj:10](opencertserver.acme.abstractions.csproj#L10));
`Microsoft.IdentityModel.Tokens` (`JsonWebKey`) is pulled in transitively through
it. There is no framework reference.

## What runs here

### Service contracts (`Services/`)

The behavioural seams a server implementation provides:

- **`IAccountService`** ([Services/IAccountService.cs:13](Services/IAccountService.cs#L13)) —
  create / find / update / deactivate / key-change / load an ACME account.
- **`IOrderService`** ([Services/IOrderService.cs:14](Services/IOrderService.cs#L14)) —
  the order lifecycle: `CreateOrder`, `ProcessCsr`, `GetCertificate`, `ProcessChallenge`,
  `DeactivateAuthorization`.
- **`IRevocationService`** ([Services/IRevocationService.cs:10](Services/IRevocationService.cs#L10)) —
  RFC 8555 certificate revocation.
- **`INonceService`** ([Services/INonceService.cs:10](Services/INonceService.cs#L10)) —
  create a fresh nonce.
- **`IAuthorizationFactory`** ([Services/IAuthorizationFactory.cs:8](Services/IAuthorizationFactory.cs#L8)) and
  **`IAllowedIdentifiersPolicy`** ([Services/IAllowedIdentifiersPolicy.cs:9](Services/IAllowedIdentifiersPolicy.cs#L9)) —
  authorizations and the allow/reject decision for a requested identifier.
- **`ICaaValidator`** ([Services/ICaaValidator.cs:14](Services/ICaaValidator.cs#L14)) —
  whether the CA may issue for an identifier (RFC 8659 / RFC 8657).
- **`IExternalAccountBindingService`** ([Services/IExternalAccountBindingService.cs:12](Services/IExternalAccountBindingService.cs#L12)) —
  validate the `externalAccountBinding` JWS of a new-account request (RFC 8555 §7.3.4).
- **`IAttestationTrustProvider`** ([Services/IAttestationTrustProvider.cs:9](Services/IAttestationTrustProvider.cs#L9)) —
  the trusted manufacturer root CAs used to verify `device-attest-01` AIK chains.
- **Challenge validators.** `IValidateChallenges`
  ([Services/IValidateChallenges.cs:12](Services/IValidateChallenges.cs#L12)) is the common
  `ValidateChallenge` contract; `IValidateHttp01Challenges`
  ([Services/IValidateHttp01Challenges.cs:6](Services/IValidateHttp01Challenges.cs#L6)),
  `IValidateDns01Challenges`
  ([Services/IValidateDns01Challenges.cs:6](Services/IValidateDns01Challenges.cs#L6)) and
  `IValidateDeviceAttestChallenges`
  ([Services/IValidateDeviceAttestChallenges.cs:7](Services/IValidateDeviceAttestChallenges.cs#L7))
  are marker interfaces so each method is resolved through the same service locator.
  **`IChallengeValidatorFactory`**
  ([Services/IChallengeValidatorFactory.cs:8](Services/IChallengeValidatorFactory.cs#L8))
  returns the right validator for a challenge.

### Issuance contracts (`IssuanceServices/`)

The two seams the RA / ACME / remote-CA topology is built on:

- **`IIssueCertificates`** ([IssuanceServices/IIssueCertificates.cs:13](IssuanceServices/IIssueCertificates.cs#L13)) —
  sign a CSR and return the certificate.
- **`ICsrValidator`** ([IssuanceServices/ICsrValidator.cs:12](IssuanceServices/ICsrValidator.cs#L12)) —
  validate the proof-of-possession CSR against the order.

The server delegates both to whatever the host registers, which is exactly what
lets the same ACME code run as an in-process monolith or as a remote-CA host
(see the Usage note and the [`opencertserver.acme.server`](../opencertserver.acme.server/README.md)
documentation).

### Storage contracts (`Storage/`)

The persistence seams: **`IStoreAccounts`**
([Storage/IStoreAccounts.cs:11](Storage/IStoreAccounts.cs#L11)), **`IStoreOrders`**
([Storage/IStoreOrders.cs:11](Storage/IStoreOrders.cs#L11)), **`INonceStore`**
([Storage/INonceStore.cs:10](Storage/INonceStore.cs#L10)) and
**`IStoreExternalAccountKeys`**
([Storage/IStoreExternalAccountKeys.cs:10](Storage/IStoreExternalAccountKeys.cs#L10)).

### Request and worker contracts

**`IRequestValidationService`**
([RequestServices/IRequestValidationService.cs:11](RequestServices/IRequestValidationService.cs#L11))
validates an incoming JWS request; **`IValidationWorker`**
([Workers/IValidationWorker.cs:9](Workers/IValidationWorker.cs#L9)) is the background
challenge-validation loop.

### Domain models (`Model/`)

The in-process, versioned, persistable shapes: **`Account`**
([Model/Account.cs:13](Model/Account.cs#L13)), **`Order`**
([Model/Order.cs:14](Model/Order.cs#L14)), **`Authorization`**
([Model/Authorization.cs:13](Model/Authorization.cs#L13)) and **`Challenge`**
([Model/Challenge.cs:14](Model/Challenge.cs#L14)), plus `ExternalAccountKey`, `Nonce`,
`CryptoString`, `GuidString`, `DeviceAttestChallengeAnswer` and `IVersioned`.

### HTTP wire models (`HttpModel/`)

The RFC 8555 §7.1 JSON DTOs: **`Directory`**
([HttpModel/Directory.cs:10](HttpModel/Directory.cs#L10), §7.1.1), **`Account`**
([HttpModel/Account.cs:10](HttpModel/Account.cs#L10), §7.1.2), **`Order`**
([HttpModel/Order.cs:14](HttpModel/Order.cs#L14), §7.1.3), **`Authorization`**
([HttpModel/Authorization.cs:13](HttpModel/Authorization.cs#L13), §7.1.4), **`Challenge`**
([HttpModel/Challenge.cs:12](HttpModel/Challenge.cs#L12), §7.1.5), plus the request
payloads under `HttpModel/Requests/` (`CreateOrGetAccount`, `CreateOrderRequest`,
`FinalizeOrderRequest`, `KeyChangeRequest`, `RevokeCertificateRequest`,
`UpdateAccountRequest`, `UpdateAuthorizationRequest`, `AcmeHeader`).

### Per-route ACME (`AcmeRoute/`)

The seam the YARP integration publishes route descriptors through:
**`IAcmeRouteConfiguration`** ([AcmeRoute/IAcmeRouteConfiguration.cs:14](AcmeRoute/IAcmeRouteConfiguration.cs#L14)),
**`IAcmeRouteConfigurationSource`** ([AcmeRoute/IAcmeRouteConfigurationSource.cs:6](AcmeRoute/IAcmeRouteConfigurationSource.cs#L6)),
the concrete **`RouteConfiguration`** record ([AcmeRoute/RouteConfiguration.cs:8](AcmeRoute/RouteConfiguration.cs#L8)),
**`InMemoryAcmeRouteConfigurationSource`** ([AcmeRoute/InMemoryAcmeRouteConfigurationSource.cs:11](AcmeRoute/InMemoryAcmeRouteConfigurationSource.cs#L11)),
and **`AcmeRouteConstants`** ([AcmeRoute/AcmeRouteConstants.cs:6](AcmeRoute/AcmeRouteConstants.cs#L6)),
whose `DefaultRouteId` (`"__default__"`) preserves single-listener behaviour.

### Exceptions (`Exceptions/`)

The RFC 8555 / RFC 7807 error types (`AcmeException` and its subclasses such as
`BadNonceException`, `ConflictRequestException`, `UserActionRequiredException`,
`RejectedIdentifierException`, …) thrown across the service contracts above.

## Usage

This is a contracts library: nothing is called directly, it is implemented and
consumed. The interesting part is the issuance seam — a host supplies
`IIssueCertificates` and `ICsrValidator`, and the server drives orders through
them. In the in-process monolith the host registers the CA-backed
implementations; in a remote-CA host it registers the remote issuer instead, and
the ACME code is unchanged:

```csharp
// In-process host (opencertserver.certserver): sign with the local CA.
services.AddSingleton<ICsrValidator, DefaultCsrValidator>();
services.AddSingleton<IIssueCertificates, DefaultIssuer>();

// Remote-CA host (opencertserver.acme): sign through a backing CA.
// AddAcmeRemoteCa registers RemoteIssuer as IIssueCertificates; DefaultCsrValidator
// still validates the PoP CSR. See ../opencertserver.acme/README.md.
services.AddAcmeRemoteCa(configuration);
services.AddSingleton<ICsrValidator, DefaultCsrValidator>();
```

## Dependencies

- [`CertesSlim`](../CertesSlim/README.md) — project reference; the ACME protocol
  client. `Microsoft.IdentityModel.Tokens` (`JsonWebKey`) is transitive through it.
- No `FrameworkReference` — this is a plain class library.

This project is a foundational library, not an application. Its consumers are
[`opencertserver.acme.server`](../opencertserver.acme.server/README.md),
[`opencertserver.acme.aspnetclient`](../opencertserver.acme.aspnetclient/README.md)
and the per-route integration
[`opencertserver.acme.yarp`](../opencertserver.acme.yarp/README.md) (the remote
issuer [`opencertserver.acme.remote`](../opencertserver.acme.remote/README.md)
and `opencertserver.data` reach it transitively through the server).
