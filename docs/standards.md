# Implemented standards

OpenCertServer is, at heart, a certificate authority *plus* the HTTP protocols used to enroll, renew,
and check certificates automatically. This page lists the standards OpenCertServer actually
implements, what each one means for you, **where in the code it lives**, and — importantly —
**which tests prove the behaviour**. Every claim below points at a source file or a Reqnroll BDD
feature, so you can verify it rather than take it on trust.

> **How to read this page.** Each standard is split into *what it is* (the reader's problem it solves),
> *what OpenCertServer does*, *where it lives*, and *the tests that lock it in*. RFC numbers link to
> the IETF text. For runnable code that exercises a standard, see
> [Getting started](getting-started.md); for the endpoint reference, see
> [Documentation index](documentation.md).

---

## Enrollment protocols

### Pluggable relational store

The optional `opencertserver.data` module persists ACME accounts, complete order/authorization/
challenge graphs, nonces, external-account keys and CA certificate inventory through
provider-independent EF Core stores. The optional `opencertserver.data.postgresql` dependency
supplies Npgsql, SQL, migrations and design-time tooling; `opencertserver.data.mssql`
supplies the corresponding SQL Server implementation and separate migrations. This is a persistence capability,
not a new protocol conformance claim.
Default memory/file implementations remain available and no protocol call sites depend on
the provider. PostgreSQL and MSSQL use the same database-table scenarios; Redis and
further providers are deferred.
Runtime qualification covers an untrimmed JIT host. Native AOT qualification does not carry
over to the provider split; provider-specific compiled-model/query integration remains open.

**Proving features:** [RelationalStores.feature](../tests/opencertserver.data.tests/Features/RelationalStores.feature)
covers reloads, optimistic concurrency, atomic/case-sensitive nonce consumption, UTC certificate
status and memory-equivalent pagination using real containers. Each scenario outline's database
examples table is the extension point for future providers. A separate provider-boundary
scenario proves engine-free shared assembly dependencies and injected adapter dispatch.
[RelationalStore.feature](../tests/opencertserver.certserver.tests/Features/RelationalStore.feature)
qualifies ACME/CA service flows with relational configuration.
See [PostgreSQL setup](getting-started.md#postgresql-persistence).

| Standard | OpenCertServer name | Project | One-line summary |
|---|---|---|---|
| [RFC 7030](https://www.rfc-editor.org/rfc/rfc7030) | **EST** (Enrollment over Secure Transport) | `opencertserver.est.server`, `opencertserver.est.client` | Enroll/renew/peek certificates over TLS with mTLS or a JWT |
| [RFC 8951](https://www.rfc-editor.org/rfc/rfc8951) | EST clarifications | `opencertserver.est.server` | Whitespace + `Content-Transfer-Encoding` tolerance |
| [RFC 9908](https://www.rfc-editor.org/rfc/rfc9908) | `CsrAttributes` response | `opencertserver.est.server` | Server hands back a CSR template the client must fill in |
| [RFC 8894](https://www.rfc-editor.org/rfc/rfc8894) | **SCEP** (Simple Certificate Enrolment Protocol) | `opencertserver.scep.server` | Enroll/renew with a challenge password; the protocol Intune and MDM systems speak |
| Intune SCEP challenge | Intune challenge validation and revocation sync | `opencertserver.contrib.intune` (optional) | Intune vouches for each request; certificates of disabled users and retired devices are revoked |
| [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555) | **ACME** (Automated Certificate Management Environment) | `opencertserver.acme.server`, `CertesSlim`, `opencertserver.acme.aspnetclient` | Domain-validated issuance via `http-01` / `dns-01` |
| [RFC 8659](https://www.rfc-editor.org/rfc/rfc8659) | CAA | `opencertserver.acme.server` | Domain owner's DNS "which CAs may issue for me?" list |
| [RFC 8657](https://www.rfc-editor.org/rfc/rfc8657) | CAA `accounturi` / `validationmethods` | `opencertserver.acme.server` | Which ACME account / challenge types may bind a domain |
| CA/Browser Forum TLS BR §3.2.2.9 | Multi-Perspective Issuance Corroboration | `opencertserver.acme.server` | Corroborates `dns-01` / `http-01` / CAA answers across configured DoH perspectives |
| `device-attest-01` | Hardware device challenge | `opencertserver.acme.server`, `opencertserver.attestation` | TPM/Apple-SE-backed identity instead of a domain |
| [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) | Base16/32/64 | `CertesSlim` | Encodings used throughout ACME/EST |
| [RFC 4211](https://www.rfc-editor.org/rfc/rfc4211) | PKCS#10 CSR | `opencertserver.ca.utils` | The request format enrollment accepts |
| [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) | JWS | `CertesSlim` | The signed envelope protecting ACME requests |
| [RFC 7807](https://www.rfc-editor.org/rfc/rfc7807) | PROBLEM-DETAILS | all handlers | Uniform error bodies |

### EST — [RFC 7030](https://www.rfc-editor.org/rfc/rfc7030)

**What it is.** The RFC you use when a *machine* must get a certificate over TLS but doesn't yet have
one to present. EST lets the client identify itself by a JWT (or an existing client cert) and receive
its new cert over that TLS connection. It's the protocol behind Microsoft's SCEP-with-JWT lineage and
the one OpenCertServer's `est-enroll` CLI and `EstClient` wrap.

**What OpenCertServer implements:**

| Endpoint | RFC section | Notes |
|---|---|---|
| `GET /.well-known/est/cacerts` | §4.1 | Base64 DER PKCS#7 CA chain in `application/pkcs7-mime; smime-type=certs-only`; cached 30 days. |
| `GET /.well-known/est/csrattrs` | §4.5 (with [RFC 9908](#rst-9908--csr-attribute-templates)) | A `CsrAttributesResponse` in `application/csrattrs` telling the client which template to use. |
| `POST /.well-known/est/simpleenroll` | §4.2 | Accepts PEM/DER PKCS#10; returns leaf+chain in `application/pkix-cert` or `application/pem-certificate-chain` via `Accept`. |
| HTTP Basic authentication | §3.2.3 | Opt-in (`AddEstBasicAuthentication`): a user name and password over TLS, next to certificates and tokens. Off until users are configured; the identity is the user name; passwords are held as PBKDF2-SHA256 hashes. Tested in [EstBasicAuthentication.feature](../tests/opencertserver.est.server.tests/Features/EstBasicAuthentication.feature). |
| Explicit client trust anchors | §3.3.2 | `CaProfile.TrustAnchors` and `AdditionalChainCertificates` scope client authentication to the selected profile. `IEstTrustAnchorProvider` adds only server-wide trust. Intermediates alone never establish trust; external anchors are not accepted on non-EST endpoints. |
| `POST /.well-known/est/simplereenroll` | §4.2.3 | Requires the current certificate over mTLS (or explicit trusted-proxy forwarding), plus an accepted authentication scheme. The CA rejects expired and not-yet-valid renewal certificates independently of the scheme. |
| `POST /.well-known/est/serverkeygen` | §4.4 | Server generates the key on the client's behalf; returns a `multipart/mixed` bundle with the private key, optionally encrypted (see below). |
| `/{profile}/…` | §3.2.2 | Per-profile variants of the above let one server act as multiple logical CAs. |
| `Content-Transfer-Encoding` / whitespace | [RFC 8951](#rst-8951--est-clarifications) §3.2/§3.3 | Tolerated, per the EST clarifications. |

**Encrypted key delivery (§4.4.1.2, §4.4.2).** A client asks for it with an `SMIMECapabilities` attribute
and an `AsymmetricDecryptKeyIdentifier` attribute (`1.2.840.113549.1.9.16.2.54`) in the CSR; the
`X-Est-*` headers are accepted as a fallback. The private key is returned as an AsymmetricKeyPackage
(RFC 5958) in a CMS SignedData, signed by the CA profile that issues the certificate, inside an
EnvelopedData (RSAES-OAEP with SHA-256, AES-CBC chosen from the client's `SMIMECapabilities`).
Limitations: the only key the server holds for encryption is the CSR's own public key, so the
identifier must be that key's subject key identifier (SHA-1 of the key bits) and the key must be RSA;
any other identifier is refused with 400 as §4.4.1.2 requires. Note that §4.4.1 has the server
ignore the CSR public key otherwise - using it as the key-transport key is this server's choice of
where the identified key comes from. Symmetric protection (`DecryptKeyIdentifier`, §4.4.1.1) is not
supported and is refused with 400.

**Where it lives.**
Endpoints are mapped in
[`src/opencertserver.est.server/EstServerExtensions.cs`](../src/opencertserver.est.server/EstServerExtensions.cs)
(`MapPost`/`MapGet` under `/.well-known/est`). The client is
[`src/opencertserver.est.client/EstClient.cs`](../src/opencertserver.est.client/EstClient.cs)
(`Enroll`, `ReEnroll`, `ServerCertificates`, `GetCsrAttributes`). Registration is
`AddEstServer<TCsrTemplateLoader>()` → `UseEstServer()`. Profile-specific trust is configured on
`CaProfile` (`rsa:TrustAnchors` / `rsa:AdditionalChainCertificates`, likewise for `ecdsa`).
`EstTrustAnchorOptions` and `IEstTrustAnchorProvider` are exclusively server-wide;
`certserver` reads their PEM paths from `Est:ExplicitTrustAnchors` (or `Est:TrustedClientCerts`).
Client-authentication anchors are separate from the section 4.1.3 `/cacerts` response:
the selected profile's issuing chain is always published, together with any additional
`PublishedCertificateChain` rollover certificates, without unrelated client-authentication roots.

**Tests that prove it.**
* [EstConformance.feature](../tests/opencertserver.certserver.tests/Features/EstConformance.feature) —
full RFC 7030 conformance: `/cacerts`, `csrattrs`, `serverkeygen`, `simpleenroll`,
`simplereenroll`, `Content-Transfer-Encoding` handling, per-profile paths, dual-scheme auth (mTLS +
JWT), `Accept` negotiation, and RFC 9908 `CsrAttributes` responses.
* [EstEnrollment.feature](../tests/opencertserver.certserver.tests/Features/EstEnrollment.feature) —
client-side enrollment against a live EST server (drives `EstClient.Enroll`).
* [EstClientTls.feature](../tests/opencertserver.est.server.tests/Features/EstClientTls.feature) —
real mTLS with the default EST client transport, including anonymous-to-certificate transitions
and renewal-key rotation without certificate headers.
* [EstServer.feature](../tests/opencertserver.est.server.tests/Features/EstServer.feature) —
endpoint-level server tests, including acceptance of a configured external client CA and refusal
when that CA is not configured; profile/default-profile isolation, server-wide client trust,
intermediate-chain building without promoting intermediates to trust anchors, non-EST isolation,
and exclusion of client-authentication roots from `/cacerts`.
* [ReEnrollmentProfiles.feature](../tests/opencertserver.est.server.tests/Features/ReEnrollmentProfiles.feature) —
re-enrollment stays within its recorded issuing profile even when profiles share a CA key/chain
or identical permissions. Covers named/default EST routes, direct CA calls, revoked certificates,
missing/imported provenance, and serial-number collisions. Missing provenance fails closed;
see [re-enrollment upgrade and custom-store requirements](documentation.md#post-well-knownestsimplereenroll).
* [TrustedCertificateForwarding.feature](../tests/opencertserver.certserver.tests/Features/TrustedCertificateForwarding.feature) —
genuine public certificates in headers do not authenticate direct EST requests; explicit
trusted-proxy and CIDR forwarding, IPv4-mapped addresses, forged forwarded-address rejection,
and fail-closed startup configuration.
* [IQ CertificateServerSecurity.feature](../tests/opencertserver.iq.tests/Features/CertificateServerSecurity.feature) —
HTTP-11 presents a genuine issued client certificate in a header without a TLS client key:
`simpleenroll`, `simplereenroll` and `/ca/csr` refuse impersonation, and the victim's certificate
remains unrevoked.
* [IQ EstEnrollment.feature](../tests/opencertserver.iq.tests/Features/EstEnrollment.feature) —
all six Cisco `estclient` scenarios against the deployed container: published CA verification,
signed-JWT enrollment, same-key mTLS re-enrollment, retrieval and independent inspection of a
configured RFC 9908 template, PKCS#8 server-key delivery with certificate/key verification, and Basic
enrollment with client-side PEM conversion. The [IQ README](../tests/opencertserver.iq.tests/README.md#est-enrollment-scenarios)
documents the source-build compatibility patches and the client's lack of encrypted CMS key delivery;
encrypted delivery and server-side PEM negotiation remain covered by `EstConformance.feature`.

### RFC 8951 — EST clarifications

**What it is.** A clarification RFC for EST that pins down whitespace and `Content-Transfer-Encoding`
behaviour and the profile path scheme (§3.1). OpenCertServer's EST endpoints ignore the
`Content-Transfer-Encoding` header and tolerate stray whitespace in base64 payloads, which is what
lets clients that add their own content-transfer encoding still work.

**Where it lives.** `opencertserver.est.server` endpoint handlers (see
[`EstConformance.feature`](../tests/opencertserver.certserver.tests/Features/EstConformance.feature)
"Content-Transfer-Encoding" and "profile path" scenarios).

### RST 9908 — CSR attribute templates

**What it is.** A newer EST extension that lets the server return a `CsrAttributesResponse`
(`application/csrattrs`) telling the client the exact template to fill in, so the client's unstructured
PKCS#10 is constrained before it leaves the device. OpenCertServer returns this response from
`/csrattrs`; the CLI's `--basic-ca` / key-usage / EKU flags are the client-side equivalent.

**Where it lives.** `src/opencertserver.est.server/Response/CsrAttributesResponse.cs`,
`CertificateSigningRequestTemplateResult.cs`.
The standalone host can publish DER CsrAttrs using `Est:CsrAttributesFile`; without it,
`/csrattrs` returns HTTP 204. See the [configuration reference](documentation.md#get-well-knownestcsrattrs).

### SCEP — [RFC 8894](https://www.rfc-editor.org/rfc/rfc8894)

**What it is.** The enrollment protocol of device management. A client that has no certificate
proves itself with a challenge password, encrypts its PKCS#10 request to the CA's registration
authority (RA) and receives the certificate in a signed, encrypted reply. Windows, macOS, iOS and
Android all ship a SCEP client, and Microsoft Intune can deliver certificates to managed devices in
exactly two ways: SCEP against a third-party CA, or PKCS through its own connector. For an Intune
deployment without Microsoft's PKI, the CA has to speak SCEP.

**What OpenCertServer implements:**

| Operation / message | RFC section | Notes |
|---|---|---|
| `GET ?operation=GetCACaps` | §3.5.2 | `POSTPKIOperation`, `SHA-256`, `AES`, `SCEPStandard`, `Renewal`. |
| `GET ?operation=GetCACert` | §4.2 | `application/x-x509-ca-ra-cert`: the RA certificate first, then the profile's published chain - including a root above an issuing CA, which Windows needs to match the trusted root of its Intune profile. |
| `GET`/`POST ?operation=PKIOperation` | §4.3 | `PKCSReq` (initial enrollment) and `RenewalReq` (renewal); `CertRep` with `SUCCESS` or `FAILURE` and `failInfo`. |
| Malformed request | §3.2.1 | Malformed CMS, a non-16-byte `senderNonce` or an undefined message type is refused with HTTP 400 - the server cannot answer such a message in SCEP. A verified message it cannot process - a decrypted payload that is not a certificate request, or a valid `CertPoll` - is refused in a signed `FAILURE` `CertRep` with `failInfo=badRequest` (§3.2.1.4); pending requests are not stored. |
| Message protection | §3.1, §3.2.1 | Requests are enveloped to the RA (RSA key transport) and signed by the requester. Only AES-128/192/256-CBC is accepted, as the capabilities promise; a request encrypted with anything else (3DES, DES, RC2) is not decrypted and is refused in a signed `FAILURE` `CertRep` with `failInfo=badAlg`. The reply is encrypted with the algorithm of the request and signed with SHA-256. A `senderNonce` must be 16 bytes. |
| Transaction ID | §3.2.1.1 | Values must be 1 to 128 PrintableString characters, including when encoded as UTF8String or IA5String. Invalid values receive HTTP 400 before envelope processing or transaction logging, not a `CertRep`. `ScepCompliance.feature` covers newline injection (including the badAlg path), character validation, a single safe rejection warning, and the exact length boundary. |
| Challenge password | §2.2 | Read from the CSR and passed to an `IScepChallengeValidator`: a shared secret by default, Intune with `opencertserver.contrib.intune`. Without a validator, `PKIOperation` issues nothing. |
| Replay protection | §3.2.1.5 | An accepted request is remembered for 24 hours by transaction ID and `senderNonce`; the same message again is refused. A new request under an earlier transaction ID - clients derive it from the key, so a renewal with the same key or a retry carries it - has a new nonce and is accepted. Only requests that passed the challenge or the renewal check are remembered, at most `MaxRememberedRequests` (100,000); when full, a new request is refused rather than risk a replay. |
| `/scep/{profile}` | — | One endpoint per CA profile; `/scep` is the default profile. |

**Not implemented:** `CertPoll` / `PENDING` (manual approval), `GetCert`, `GetCRL` (the CRL is
served by `ca.server`), and DES or MD5/SHA-1.

**The RA.** SCEP defines the envelope for RSA key transport only, so the RA certificate carries an
RSA key even when the CA profile is ECDSA. The CA still signs requests of either key algorithm
(an RSA request against an ECDSA profile is issued by the ECDSA CA).

**Renewal (`RenewalReq`, §3.3.1.2).** A renewal is signed with the certificate it replaces; that
certificate is the proof and no challenge is needed. It must chain to the profile's CA, be valid,
not be revoked, and name the same subject and the same subjectAltName as the request - as EST
requires for `simplereenroll`. The CA core checks it again when it signs (issuer signature, the
issuing profile as for EST re-enrollment, revocation), and supersedes the previous certificate once
the new one is issued.

**Windows and Intune - what the device test showed.** Two points an operator should know:

* *Windows appends `/pkiclient.exe`* to the SCEP server URL configured in Intune, as it does for
  NDES. Both `/scep/pkiclient.exe` and `/scep/{profile}/pkiclient.exe` are mapped. Configure the URL
  without a trailing slash, otherwise Windows asks for `//pkiclient.exe`.
* *Windows does not renew with `RenewalReq`.* Intune hands the device a new challenge before the
  certificate expires, and the device enrolls again with a `PKCSReq`. The previous certificate is
  therefore **not superseded** and stays valid until it expires, so a device holds two valid
  certificates for a while, and the CA does not know they belong together. (Whether Intune removes
  the old certificate from the device was not confirmed in the test.) An operator who wants the old
  certificate revoked at once has to do so outside the CA - for example by revoking the older
  certificates that carry the same `IntuneDeviceId://` URI once the device has used the new one.
  Seen on Windows 11 devices enrolled through Intune; `RenewalReq` is covered by the scenarios and
  by other SCEP clients.

**Where it lives.**
Endpoints are mapped by `MapScepServer()` in
[`src/opencertserver.scep.server/ScepServerExtensions.cs`](../src/opencertserver.scep.server/ScepServerExtensions.cs);
the protocol is
[`Handlers/ScepHandler.cs`](../src/opencertserver.scep.server/Handlers/ScepHandler.cs) and the
CMS envelopes
[`ScepMessageCodec.cs`](../src/opencertserver.scep.server/ScepMessageCodec.cs). Registration is
`AddScepServer(ScepServerOptions, IScepChallengeValidator)`; the challenge contract is
[`IScepChallengeValidator.cs`](../src/opencertserver.scep.server/IScepChallengeValidator.cs).

**Tests that prove it.**
* [ScepServer.feature](../tests/opencertserver.scep.server.tests/Features/ScepServer.feature) —
capabilities, `GetCACert` with and without a root above the issuing CA, enrollment through POST and
GET and through the `/pkiclient.exe` paths, wrong and missing challenge, a request encrypted to
another key, the UPN carried into the certificate, a CA certificate refused, renewal with the
previous certificate, a look-alike issuer, another subject or subjectAltName, a revoked certificate,
renewal through another profile of the same CA key, renewal below a root that is only
published, replay, a new request under an earlier transaction ID, a refused request not
remembered, a full replay store, a malformed signed attribute, no validator, the reply
algorithm, and the `senderNonce` length. The test client builds real SCEP messages with `SignedCms` and
`EnvelopedCms`, so the server is exercised over HTTP the way a device would.
* [IQ ScepEnrollment.feature](../tests/opencertserver.iq.tests/Features/ScepEnrollment.feature) —
`sscep` (AES) against the deployed, hardened container: capabilities, the RA and CA bundle,
enrollment with the challenge, a wrong challenge refused, the `/pkiclient.exe` path, triple DES
refused with `badAlg`, and a new enrollment signed with the certificate the client holds;
`openssl` verifies what it receives. `RenewalReq` is covered in-process, since sscep does not send
one. See the [IQ README](../tests/opencertserver.iq.tests/README.md#scep-enrollment-scenarios).

### Intune challenge validation and revocation sync (`opencertserver.contrib.intune`)

**What it is.** Intune issues every managed device a one-time challenge and expects the CA to ask
Intune whether a request is genuine. It also never tells the CA when a user is disabled or a device
is retired. This optional package covers both, outside the SCEP core: the core knows nothing about
Intune.

**What it does.**

| Part | Behaviour |
|---|---|
| `IntuneChallengeValidator` | Sends each `PKCSReq` (transaction ID and CSR) to Intune's SCEP validation service (`validateRequest`, discovered through Microsoft Graph) and lets the CA issue only when Intune agrees. Refused, unreachable or throttled (429) all mean *deny*. After issuing it sends `successNotification`; when the CA refuses after Intune agreed, `failureNotification`. A `RenewalReq` signed with the previous certificate passes without Intune. |
| `IntuneRevocationSync` | Walks the certificates issued through the configured profiles (`SyncProfiles`, by the issuing profile the store recorded) and asks Graph about the user (UPN from the subjectAltName), the Intune managed device (`IntuneDeviceId://` URI) and the Entra device. What is gone or disabled is revoked (`cessationOfOperation`); certificates from other profiles are never judged. Graph unreachable, throttled or answering in an unexpected shape means *unknown*, and unknown is never revoked; a run that would revoke more than `MaxRevocationsPerSync` aborts. |
| `POST /scep/intune/sync?dryRun=` | Runs the sync and returns the report; 409 while a run is in progress. Requires the authorization policy `scep_intune_sync`. It is an operation, not a scheduler - the caller decides how often. |
| `IIntuneClient.GetManagedDeviceName` | The name of a managed device, for an inventory that lists certificates by device. |

**Where it lives.**
[`src/opencertserver.contrib.intune`](../src/opencertserver.contrib.intune/README.md) - configuration
under `Scep:Intune`, see the [configuration reference](documentation.md#scep-with-intune).

**Tests that prove it.**
* [IntuneChallenge.feature](../tests/opencertserver.contrib.intune.tests/Features/IntuneChallenge.feature) —
allowed, refused, unreachable, throttled, the validation service not discoverable, refused by
the CA after Intune allowed, two requests under one transaction ID, no challenge, discovery and
token reuse, renewal without Intune, certificate credential instead of a secret.
* [IntuneRevocationSync.feature](../tests/opencertserver.contrib.intune.tests/Features/IntuneRevocationSync.feature) —
nothing to do, disabled and deleted users, a retired Intune device, a disabled Entra device, Graph
throttled, unreachable or answering without a value list (nothing revoked), a certificate from
another profile, no sync profiles, dry run, the revocation limit, a second run while one is in
progress, and the endpoint's policy.
* [IntuneDeviceName.feature](../tests/opencertserver.contrib.intune.tests/Features/IntuneDeviceName.feature).

All three run against an in-process fake of Entra, Graph and the validation service. What a fake
cannot say about the real service was checked against a real tenant: Windows 11 devices enrolled
and renewed through Intune, with `validateRequest` and `successNotification` accepted by Intune,
and the sync running daily.

### ACME — [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555)

**What it is.** The Web PKI protocol for automatic certificate issuance and renewal without a human
in the loop. It's the protocol that backs Let's Encrypt. OpenCertServer is a full ACME *server*;
`CertesSlim` and `opencertserver.acme.aspNetClient` are the client side.

**What OpenCertServer implements:**

* **Directory** (`GET /directory`) — advertises `newNonce`, `newAccount`, `newOrder`, `keyChange`,
   `revokeCert`, and an optional `meta` block (`websiteUrl`, `termsOfServiceUrl`,
   `challengeTypesWithAdditionalContent` including `device-attest-01`).
* **Nonce protection** — `HEAD/GET /new-nonce`; every mutating request must carry a fresh nonce that
   is discarded after use.
* **Accounts** (`POST /new-account`, key-change) — accounts are created and retrieved by public key;
   external account binding (EAB, RFC 8555 §6.7) is validated via
   `IExternalAccountBindingService`, which verifies the EAB JWS signature.
* **Term-of-service changes** (§7.3.3) — when `TOS.LastUpdate` is configured and an account's stored
   agreement pre-dates it, `newOrder` is rejected with HTTP 403 `userActionRequired` and a
   `Link: <tos-url>; rel="terms-of-service"` header. A client sends an account update with
   `termsOfServiceAgreed: true` to re-agree.
* **Order lifecycle** — `/new-order`, `/order/{orderId}`, `/order/{orderId}/finalize`,
   `/order/{orderId}/certificate`, and the nested challenge authorization endpoints
   `/order/{id}/auth/{authId}` and `/order/{id}/auth/{authId}/chall/{challengeId}`.
* **Interoperability with off-the-shelf clients** — responses omit absent optional fields instead
   of sending `null`; challenge responses carry `Link: <authz>;rel="up"` (§7.5.1); the certificate
   resource returns the end-entity certificate followed by its issuer certificates (§7.4.2); and
   SAN-only CSRs with an empty subject are accepted, with subjectAltName marked critical in the issued
   certificate (RFC 5280 §4.1.2.6).
* **Challenge validation** — `http-01` over HTTP (`/.well-known/acme-challenge/{token}`),
   `dns-01` via `DnsClientX`, and `device-attest-01` (see below). A hosted
   `HostedValidationService` runs validations asynchronously.
* **JWS protection** — compact JWS with `alg`, `nonce`, `url`, and either `jwk` (first request) or
   `kid` (subsequent requests).
* **Revocation** (`POST /revoke-cert`) — revoke via ACME or via the authenticated CA endpoint
   `DELETE /ca/revoke`. Both require proof of possession of the target key. The CA endpoint
   additionally enforces self-service (the presented certificate must be the CA-issued certificate
   with that serial number) or administrative authorization (the `ca_admin` role).
* **Storage** — `AddAcmeInMemoryStore` (default) or `AddAcmeFileStore(configuration)`; custom stores
   implement `IStoreAccounts`, `IStoreOrders`, `INonceStore`.
* **Profiles** — an optional `profile` field on orders maps to a named CA profile, so a single ACME
   server can issue multiple certificate types.
* **Problem details** — all error responses are `problem+json` per
   [RFC 7807](https://www.rfc-editor.org/rfc/rfc7807).

**Where it lives.**
* Server: `src/opencertserver.acme.server/Endpoints/` —
   `DirectoryEndpoints.cs`, `NonceEndpoints.cs`, `AccountEndpoints.cs`, `OrderEndpoints.cs`,
   `RevocationEndpoints.cs`.
* Server: `src/opencertserver.acme.server/AcmeRegistration.cs` (`UseAcmeServer`),
   `Extensions/ServiceCollectionExtensions.cs` (`AddAcmeServer`, `AddAcmeInMemoryStore`,
   `AddAcmeFileStore`).
* Client: `src/CertesSlim/AcmeContext.cs` (`NewAccount`, `NewOrder`, `RevokeCertificate`,
   `ChangeKey`), `src/opencertserver.acme.aspNetClient/Certes/AcmeClient.cs`
   (`PlaceOrder`, `FinalizeOrder`).

**Tests that prove it.**
* [AcmeFeature.feature](../tests/opencertserver.certserver.tests/Features/AcmeFeature.feature) — a
   client requests a certificate and it appears in the CA inventory.
* [AcmeConformance.feature](../tests/opencertserver.certserver.tests/Features/AcmeConformance.feature) —
   directory, nonces, accounts, TOS changes, order lifecycle, all three challenge types, JWS
   envelope fields, EAB, revocation, error shapes.
* [AcmeCaaRfc8657.feature](../tests/opencertserver.certserver.tests/Features/AcmeCaaRfc8657.feature) —
   the CAA `accounturi` / `validationmethods` extension (see below).
* YARP coverage in `tests/opencertserver.acme.yarp.tests` (see
   [opencertserver.acme.yarp](#yarp-per-route-acme)) and
   `tests/opencertserver.acme.aspnetclient.tests` (challenge middleware + renewal).
* [AcmeIssuance.feature](../tests/opencertserver.iq.tests/Features/AcmeIssuance.feature) — black-box
   IQ run against a container, driven by `acme.sh` and `certbot` from a Linux client container.

### RST 8659 — CAA

**What it is.** The Certification Authority Authorization resource record. It's the DNS mechanism by
which a domain owner declares which CAs are *permitted* to issue for that domain. OpenCertServer
checks it before issuing an ACME certificate for a validated domain.

**Where it lives.** `src/opencertserver.acme.server/Services/CaaValidator.cs` and
`DefaultAuthorizationFactory.cs` (wired in via `AddAcmeServer` / `ServiceCollectionExtensions.cs`).

**Fail-closed behaviour.** CAA enforcement is **fail-closed by default**.  If
`AcmeServer:CAAIdentities` is empty or absent, `CaaValidator` **rejects every order** with a
`caa` error rather than silently skipping the check.  This prevents mis-issuance in deployments
where an operator believes CAA is enforced but forgot to supply the identity list.

**Explicit opt-out.** Operators who intentionally do not want CAA enforcement (e.g. isolated lab
deployments or internal-only CAs with no public DNS) must set:

```json
{
  "AcmeServer": {
    "DisableCaaChecks": true
  }
}
```

Setting `DisableCaaChecks` to `true` bypasses all CAA DNS lookups unconditionally.
**Never set this on a public-facing CA.**

**Configuration summary.**

| Key | Type | Default | Effect |
|---|---|---|---|
| `AcmeServer:CAAIdentities` | `string[]` | `null` | Issuer domain names to match against the CAA RRset. Must be set for CAA enforcement to work. |
| `AcmeServer:DisableCaaChecks` | `bool` | `false` | When `true`, skips all CAA lookups. Required when `CAAIdentities` is not set and you want to issue without CAA. |

**Tests that prove it.** [AcmeFeature.feature](../tests/opencertserver.certserver.tests/Features/AcmeFeature.feature)
runs issuance against a CAA-enabled domain; [AcmeConformance.feature](../tests/opencertserver.certserver.tests/Features/AcmeConformance.feature)
asserts the CAA-gated issuance path; [AcmeCaaEnforcement.feature](../tests/opencertserver.certserver.tests/Features/AcmeCaaEnforcement.feature)
covers the fail-closed default and the `DisableCaaChecks` opt-out.

### Multi-Perspective Issuance Corroboration — CA/Browser Forum TLS Baseline Requirements §3.2.2.9

**What it is.** [TLS Baseline Requirements §3.2.2.9](https://cabforum.org/working-groups/server/baseline-requirements/requirements/#3229-multi-perspective-issuance-corroboration)
requires a public CA to corroborate domain validation and CAA determinations from multiple
independent **Network Perspectives**, so that a BGP hijack, DNS cache poison, or resolver compromise
visible from one network cannot cause mis-issuance. OpenCertServer implements the DNS portion of
this requirement for the ACME `dns-01` and `http-01` validators, and for CAA processing.

**How it works.** Each entry in `AcmeServer:DohServers` is an independent DNS-over-HTTPS resolver
that acts as one Network Perspective. For every issuance-critical lookup
(`dns-01` TXT, `http-01` A/AAAA, and CAA) the server:

1. Queries every perspective independently and in parallel (no shared cache).
2. Canonicalizes the answer sets (order-insensitive, duplicates and TTLs ignored).
3. Returns the answer only when every perspective agrees.

A lookup that fails in any perspective, or whose canonical answer sets differ, throws
`DnsPerspectiveMismatchException` (or a `DnsClientException` for a perspective failure).
`CaaValidator` preserves that DNS failure classification instead of reporting a CAA policy
rejection, and both challenge validators translate it into an ACME
`urn:ietf:params:acme:error:dns` failure, so the challenge becomes `invalid` rather than being
retried or silently accepted. A CAA policy rejection — a CAA RRset that does not authorize the CA
— remains `urn:ietf:params:acme:error:caa`.

For `http-01`, the corroborated A/AAAA set is pinned onto the challenge request. The connection
handler connects only to those addresses — it never performs a second, ambient-DNS lookup — and
re-checks each actual connection target against the prohibited address ranges before opening a
socket. This prevents a poisoned local resolver from redirecting the HTTP fetch to an address that
none of the Network Perspectives returned.

**Configuration summary.**

| Key | Type | Default | Effect |
|---|---|---|---|
| `AcmeServer:DohServers` | `string[]` | `[]` | DoH URLs or `DnsEndpoint` names used as Network Perspectives. All entries must be queried with no disagreement. |
| `AcmeServer:DnsQueryTimeout` | `TimeSpan` | `00:00:10` | Timeout applied to each individual perspective query. |
| `AcmeServer:DnsEndpoint` | `DnsEndpoint` | `Cloudflare` | Single-perspective fallback used only when `DohServers` is empty. Does **not** satisfy §3.2.2.9 for a public CA. |

```json
{
  "AcmeServer": {
    "DohServers": [
      "https://cloudflare-dns.com/dns-query",
      "https://dns.google/dns-query",
      "https://dns.quad9.net/dns-query"
    ],
    "DnsQueryTimeout": "00:00:10"
  }
}
```

Configure at least three distinct perspectives in different RIR service regions. Using multiple
resolver endpoints operated by the same provider or network does not count as distinct Network
Perspectives under §3.2.2.9. Invalid entries (not an absolute URL and not a known `DnsEndpoint`)
fail closed when the resolver is created rather than silently disabling corroboration.

**Where it lives.** `src/opencertserver.acme.server/Services/MultiPerspectiveDnsResolver.cs`
(fan-out and comparison), `DnsPerspectiveFactory.cs` (configuration parsing),
`DnsPerspectiveMismatchException.cs` (disagreement signal), wired via
`Extensions/ServiceCollectionExtensions.cs` as the DI `IDnsResolver`. The validators are
`Dns01ChallengeValidator.cs` and `Http01ChallengeValidator.cs`.

**Tests that prove it.**
[AcmeMultiPerspectiveIssuanceCorroboration.feature](../tests/opencertserver.certserver.tests/Features/AcmeMultiPerspectiveIssuanceCorroboration.feature)
covers configured perspectives, the single-endpoint fallback, programmatic `AddAcmeServer` options
reaching the DI options pipeline, matching and differing TXT records, matching and differing A
records, an unavailable perspective, differing CAA records, and CAA lookup failures surfacing as
`dns` challenge errors through the real `CaaValidator`.

### RST 8657 — CAA `accounturi` / `validationmethods`

**What it is.** An extension to RFC 8659 that lets the domain owner narrow which *ACME account* may
obtain the cert (via `accounturi`) and which challenge *validation method* may bind it
(`validationmethods`). This is the mechanism that stops a compromised ACME account from reusing
`http-01` on a domain that has moved on.

**Where it lives.** `src/opencertserver.acme.server/Services/DefaultAllowedIdentifiersPolicy.cs`,
`DefaultAuthorizationFactory.cs`, and the CAA validation path.

**Tests that prove it.**
[AcmeCaaRfc8657.feature](../tests/opencertserver.certserver.tests/Features/AcmeCaaRfc8657.feature) is
the canonical reference; scenarios cover `accounturi` allow/allow-list, `validationmethods`
allow/allow-list, and their intersection with `issue` / `issuewild`.

### Device attestation (`device-attest-01`)

**What it is.** An OpenCertServer-specific ACME challenge type for hardware-backed devices. The
device submits an Attestation Identity Key (AIK) certificate and a TPM proof instead of proving
domain control. OpenCertServer's `opencertserver.attestation` layer abstracts AMD SEV-SNP, Intel SGX,
and Apple Secure Element so the ACME server can talk to any of them behind `IAttestationTrustProvider`.

**What OpenCertServer implements:**

* **Directory advertisement.** `meta.challengeTypesWithAdditionalContent` always includes
   `device-attest-01` in the directory metadata. The ACME server still gates challenge creation: when
   `IAttestationTrustProvider.GetTrustedRoots()` is empty, no `device-attest-01` challenge is created
   for any order even though the type remains advertised to clients.
* **Validator.** `DeviceAttestChallengeValidator` performs three checks:
   1. **Chain verification (fail-closed)** — if no trust roots are configured the validator returns
      `invalid_attestation` immediately. System trust is **never** used as a fallback. When roots are
      present the AIK must chain to an injected root under custom-trust mode. A self-signed AIK and
      any cert signed by a root not in the injected set are rejected. Revocation is checked online
      (`X509RevocationMode.Online`); unknown revocation status (e.g. the manufacturer CA omits CDP/AIA
      extensions) is tolerated rather than treated as a hard failure, but an explicitly revoked cert
      will be rejected.
   2. **Proof verification** — a TPM `quote`-style proof whose magic value, attestation type, and
      nonce-bind match the challenge. Garbage bytes or wrong magic ⇒ `invalid_attestation`.
   3. **Anti-replay** — a consumed nonce is rejected on second use with error type `replay_nonce`.
      Over HTTP, another evidence submission to a processed device challenge returns HTTP 400
      `urn:ietf:params:acme:error:replay_nonce`; POST-as-GET still returns the original outcome.
* **Factory gating.** `DefaultAuthorizationFactory` only creates a `device-attest-01` challenge
   when `IAttestationTrustProvider.GetTrustedRoots()` returns a non-empty collection. With the
   default empty `StaticAttestationTrustProvider` registered by `AddAcmeServer`, only `http-01` and
   `dns-01` are offered.
* **Factory routing.** `IChallengeValidatorFactory.GetValidator("device-attest-01")` returns the
   device validator; unknown types throw `InvalidOperationException("Unknown Challenge Type")`.
* **Model.** `DeviceAttestChallengeAnswer` (Nonce, Proof, Signature, AikCertificate, DeviceId) is the
   JSON contract submitted as the signed challenge request payload. The HTTP endpoint preserves it
   in the server-side `Challenge.ExtraData` field for the asynchronous validator.
* **Installation qualification.** The Linux-client
   [DeviceAttestation IQ feature](../tests/opencertserver.iq.tests/Features/DeviceAttestation.feature)
   checks advertisement, empty-root offer gating, both empty and malformed proofs, and acceptance
   followed by replay rejection through the deployed HTTPS endpoint. Its disposable manufacturer
   PKI and independently signed software quotes do not establish real hardware provenance.

**Where it lives.**
* Model: `src/opencertserver.acme.abstractions/Model/DeviceAttestChallengeAnswer.cs`,
   `Challenge.cs` (challenge `type` field).
* Interfaces: `src/opencertserver.acme.abstractions/Services/IAttestationTrustProvider.cs`,
   `IValidateDeviceAttestChallenges.cs`.
* Server-side validator: `src/opencertserver.acme.server/Services/DeviceAttestChallengeValidator.cs`,
   `StaticAttestationTrustProvider.cs`, `DefaultChallengeValidatorFactory.cs`,
   `DefaultAuthorizationFactory.cs`.
* Attestation backends: `src/opencertserver.attestation/*` (AMD SEV-SNP, Intel SGX, Apple SE,
   `AppleSeProvider`, `SecurityFrameworkAppleAttestInterop`).
* Enablement: `AddAcmeServer(...)` registers an empty `StaticAttestationTrustProvider` and
   `DeviceAttestChallengeValidator`. With an empty provider no `device-attest-01` challenges are
   created and any that arrive are rejected. To enable device attestation, replace the singleton:

   ```csharp
   services.AddSingleton<OpenCertServer.Acme.Abstractions.Services.IAttestationTrustProvider>(
        _ => new OpenCertServer.Acme.Server.Services.StaticAttestationTrustProvider(
            new X509Certificate2Collection { /* Apple Attestation CA, Intel ME, AMD PSP */ }));
   ```

**Tests that prove it.**
* [device-attest-core.feature](../tests/opencertserver.certserver.tests/Features/device-attest-core.feature) —
   `device-attest-01` is in `ChallengeTypes.AllTypes`; offered on orders only when trust roots are
   configured; not offered when trust provider has no roots.
* [device-attest-directory.feature](../tests/opencertserver.certserver.tests/Features/device-attest-directory.feature) —
   the directory advertises `device-attest-01` alongside `http-01` and `dns-01` under
   `meta.challengeTypesWithAdditionalContent`.
* [device-attest-validation.feature](../tests/opencertserver.certserver.tests/Features/device-attest-validation.feature) —
   the full validation matrix: self-signed AIK rejected, trusted-CA AIK with valid TPM proof passes,
   **empty trust provider rejects any attestation (fail-closed)**,
   garbage / wrong-magic / wrong-type / mismatched-extra-data / empty proof rejected, replay
   nonce → `replay_nonce`, nonce-mismatch → `invalid_nonce`, missing proof → `device_attestation`.
* [device-attest-e2e.feature](../tests/opencertserver.certserver.tests/Features/device-attest-e2e.feature) —
   a full device-attestation flow that reaches a `valid` challenge.
* [device-attest-factory.feature](../tests/opencertserver.certserver.tests/Features/device-attest-factory.feature) —
   the validator factory routes to the right validator per challenge type.
* [device-attest-models.feature](../tests/opencertserver.certserver.tests/Features/device-attest-models.feature) —
   JSON round-trip of `DeviceAttestChallengeAnswer`.
* `tests/opencertserver.attestation.Tests` — platform-specific coverage (AMD SEV-SNP, Intel SGX,
   Apple SE, `GlobalServiceMapping`, `TrustStore`, `TrustStoreEdgeCases`, `Config`).

### Supporting encodings

* [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) — Base16/32/64. Used throughout ACME JWS
   (`CertesSlim`) and EST base64 payloads.
* [RFC 4211](https://www.rfc-editor.org/rfc/rfc4211) — PKCS#10 CSR. The request format EST and ACME
   accept; helpers are `src/opencertserver.ca.utils/CertificateRequestsExtensions.ToPkcs10Pem` /
   `ToPkcs10Base64`. The template
   (`src/opencertserver.ca.utils/X509/Templates/CertificateSigningRequestTemplate.cs`) is
   explicitly a "Certificate Signing Request as per RFC 4211".
* [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) — JWS. The envelope
   (`src/CertesSlim/Json/JwsSigner.cs`, `JwsPayload`, `AcmeHeader`) that protects ACME requests.
   Compacted serialization, `alg`/`nonce`/`url`/`jwk` or `kid` header parameters.
* [RFC 7807](https://www.rfc-editor.org/rfc/rfc7807) — PROBLEM-DETAILS. Error bodies returned by
   `acme.server` handlers (`type`, `status`, `detail`); see the "Error response shapes" scenarios in
   [AcmeConformance.feature](../tests/opencertserver.certserver.tests/Features/AcmeConformance.feature).

### CSR extension allow-list (`AllowedCsrExtensions`)

**What it is.** A per-profile security boundary on `CaProfile` that controls which X.509 extensions
the CA copies from a CSR into the issued certificate. Extensions not on the list are silently
dropped before signing, so an enrollee cannot obtain a CA certificate or poison issued certs with
structural extensions (nameConstraints, certificatePolicies, etc.) they are not entitled to.

**Defaults.** The default list is SAN (2.5.29.17), EKU (2.5.29.37), and keyUsage (2.5.29.15).

**CA issuance opt-in.** To let a profile issue intermediate CA certificates, add `2.5.29.19`
(basicConstraints) to the profile's `AllowedCsrExtensions`. The `CaExtensionValidation` and
`KeyCrlSignatureValidation` validators both gate on this OID: CA:TRUE in basicConstraints is
rejected unless `2.5.29.19` is in the list, and keyCertSign in keyUsage is rejected unless
`2.5.29.19` is in the list. When the profile does allow CA issuance, keyCertSign is additionally
tied to CA:TRUE — a CSR asserting keyCertSign without CA:TRUE is rejected (RFC 5280 §4.2.1.3).
cRLSign without keyCertSign is freely allowed on CA-enabled profiles (indirect CRL issuers).

**Server-managed extensions.** SKI (2.5.29.14), AKI (2.5.29.35), AIA (1.3.6.1.5.5.7.1.1),
CRLDP (2.5.29.31) and certificatePolicies (2.5.29.32) are always regenerated from the CA's own
state and are stripped from the CSR unconditionally — listing them in `AllowedCsrExtensions` has
no effect.

**Where it lives.** `src/opencertserver.ca.utils/Ca/CaProfile.cs` (`AllowedCsrExtensions`),
enforced by `CaExtensionValidation`, `KeyCrlSignatureValidation`, and `CleanCsrExtensions` in
`src/opencertserver.ca/CertificateAuthority.cs`.

### Certificate content fixed by the profile (`CertificatePolicies`, `KeyUsage`, `ExtendedKeyUsages`)

**What it is.** Three per-profile settings on `CaProfile` for what every certificate issued from
the profile says, regardless of the CSR:

* `CertificatePolicies` — the policy identifiers the CA asserts
  ([RFC 5280 §4.2.1.4](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.4)), written as a
  certificatePolicies extension (2.5.29.32, identifiers only, no qualifiers). Empty by default: no
  extension. A policy is the CA's assertion and never the requester's, so a policy in a CSR is
  dropped even when the profile lists 2.5.29.32 as allowed. A relying party that requires a policy
  (strongSwan's `cert_policy`, Windows application policies) needs the CA to assert it. A profile
  that issues intermediate CA certificates typically asserts anyPolicy (2.5.29.32.0) so the leaf
  policies below it validate.
* `KeyUsage` — when set, the key usage of every certificate
  ([§4.2.1.3](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.3)), marked critical, replacing
  what the CSR asked for. Not set by default.
* `ExtendedKeyUsages` — when set, the extended key usages
  ([§4.2.1.12](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.12)), replacing what the CSR
  asked for; an empty list means no extendedKeyUsage extension at all. Not set by default.

The CSR validators still see the request as submitted: a CSR that asks for keyCertSign is refused
on a profile that does not issue CA certificates, whatever the profile would have fixed.

**Where it lives.** `CaProfile.cs` (the three properties), `CleanCsrExtensions` in
`CertificateAuthority.cs` (applies them after the allow-list), and
`src/opencertserver.ca.utils/X509Extensions/X509CertificatePoliciesExtension.cs` (encodes and
decodes 2.5.29.32). In `certserver` they come from configuration, see
[Documentation → Profile configuration](documentation.md#profile-configuration-certserver).

**Tests that prove it.**
[CaProfilePolicies.feature](../tests/opencertserver.est.server.tests/Features/CaProfilePolicies.feature) —
no policies by default; the profile's policies in every certificate; a CSR policy never taken over
even when its OID is allowed; fixed key usage and fixed extended key usages replacing the CSR's; an
intermediate CA certificate asserting anyPolicy.

---

## Revocation & status

### OCSP — [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960)

**What it is.** Online Certificate Status Protocol. Instead of pulling a CRL and scanning it, a
relying party POSTs a question and gets back `good` / `revoked` / `unknown`. OpenCertServer ships a
signing OCSP responder and embeds its URL in every issued cert's AIA extension when `--ocsp` is
supplied.

**What OpenCertServer implements:**

* `POST /ca/ocsp` takes a DER-encoded `OCSPRequest` and returns `application/ocsp-response` with a
   signed `BasicOCSPResponse`. Each `SingleResponse` reports `good`, `revoked`, or `unknown` from the
   certificate store.
* `GET /ca/ocsp/{requestEncoded}` accepts URL-encoded standard base64 requests as specified
   by RFC 6960 Appendix A.1 and RFC 5019 section 5. Unescaped `/` characters also reach the
   responder. Padded and unpadded base64url requests remain supported for compatibility.
* **Signed requests.** `IValidateOcspRequest` implementations run before status lookup; a `malformedRequest`
   is returned on an unparseable request, `unauthorized` when the server refuses service, `internalError`
   and `tryLater` cover responder faults, and `nonce` + `archiveCutoff` + `serviceLocator` +
   `preferredSignatureAlgorithms` extensions are supported.
* **Status values** — every `SingleResponse` carries a `tbsResponseData` with `producedAt`/`thisUpdate`
   and optional `nextUpdate`; the response carries `responderID` and the signature.
* **Encoding.** The RFC 6960 ASN.1 module uses `EXPLICIT TAGS`: `responseBytes`, `certs`, `version`,
   `responderID`, `nextUpdate`, `revocationReason` and all extension lists are explicitly tagged in
   requests and responses; only `certStatus` (`good` / `revoked` / `unknown`) is `IMPLICIT`, as the
   module says. Checked against OpenSSL as an independent client.
* **Freshness policy** is configurable (`ocspFreshnessWindow`, default 1 hour on the
   `ca.server`) via a freshness window.
* **Cache.** `CacheOutput` for `GET /ca/ocsp`; fresh responses are signed with the
   `IRegister`/responder credentials OpenCertServer is configured with.

**Where it lives.** `src/opencertserver.ca.server/Handlers/OcspHandler.cs` (POST + GET),
`OcspRequestSignatureValidator.cs`, and metrics in `CaInstruments.cs`. Registration:
`AddCertificateAuthority(...)` registers the `IValidateOcspRequest`, `UseCertificateAuthorityServer()`
maps the endpoint.

**Tests that prove it.**
* [OcspGet.feature](../tests/opencertserver.certserver.tests/Features/OcspGet.feature) —
   URL-encoded standard base64, unescaped slashes, and legacy base64url, using requests whose
   standard encoding contains `+`, `/`, and `=`; invalid encodings and invalid DER return
   `malformedRequest`.
* [OcspConformance.feature](../tests/opencertserver.certserver.tests/Features/OcspConformance.feature) —
   RFC 6960 conformance across nine rules: responder endpoint + OCSP-over-HTTP, request syntax +
   `CertID` matching, successful response structure, certificate status values, response freshness,
   authorized-responder signature requirements, request/response extensions, and multi-request
   semantics; plus interoperability with OpenSSL (`openssl ocsp` builds the request with a nonce and
   verifies signature, nonce and status, for a good and a revoked certificate - skipped where
   `openssl` is not installed).
* [OcspFeature.feature](../tests/opencertserver.certserver.tests/Features/OcspFeature.feature) —
   end-to-end: enroll, then check OCSP status.
* [McpServerRevocation.feature](../tests/opencertserver.mcp.tests/Features/McpServerRevocation.feature) —
   the MCP `check_ocsp_status` / `get_crl` / `get_revocation_status` tools.

### CRL & revocation — [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280)

**What it is.** The traditional batch revocation record. `CRL` is the offline companion to OCSP: a
signed list of revoked serial numbers. OpenCertServer publishes one per profile and lets clients
fetch it by CA or by profile.

**What OpenCertServer implements:**

* `GET /ca/crl` and `GET /ca/{profile}/crl` return `application/pkix-crl` bodies, cached for 12 hours.
  Each CRL is scoped to its issuing CA profile: it lists only certificates whose stored issuing
  profile matches (ordinal comparison), so one profile's (tenant's) revocations are never published
  in another profile's CRL. Certificates stored without an issuing profile appear in no CRL; OCSP
  still reports them as revoked.
* Because profiles may share one CA key, each profile's CRL is a partitioned CRL. It carries a
  **critical `issuingDistributionPoint`** (2.5.29.28) whose distribution point equals that profile's
  CRL URL. Issued certificates carry a matching `cRLDistributionPoints` entry. Configure this with
  the `{profile}` token in `CaServer:CrlDistributionPoints` (e.g. `https://ca.example/ca/{profile}/crl`).
  When more than one profile is configured, every CRL URL must contain `{profile}`. Otherwise
  issuance and CRL generation fail closed with `InvalidOperationException`, because a certificate
  could otherwise be checked against another profile's partial CRL and be treated as unrevoked.
* `DELETE /ca/revoke` is authenticated and authorized. The caller must:
   1. Present a TLS client certificate.
   2. Supply a SHA-256 signature of `serialNumber + reason` made with that certificate's private key
      (proof of key possession).
   3. Pass one of two authorization checks:
      - **Self-service**: the presented certificate's serial number **and thumbprint** must match the
        certificate stored in the CA's issuance store. Matching on the thumbprint (not only the serial
        number) prevents an attacker from crafting a certificate with the same serial number as a
        victim's certificate and using it to trigger self-service revocation.
      - **Administrative**: the caller's authenticated identity carries the role claim
        `ca_admin` (`RevocationAuthorizationConstants.CaAdminRole`). Admins may revoke any
        certificate in the CA.
   Any other combination returns `403 Forbidden`.
* The authorization policy for the revoke endpoint is named `"ca_revoke"`
  (`RevocationAuthorizationConstants.RevocationPolicyName`). Register it with
  `services.AddCertificateAuthorityAuthorization()` and optionally pass a configure action to add
  further restrictions (e.g. require a specific authentication scheme).
* Revocation reasons (`keyCompromise`, `cessationOfOperation`, etc.) are passed as query parameters.
* CRL Distribution Point URLs are embedded in issued certs when `--crl` is supplied at startup.

**Where it lives.** `src/opencertserver.ca.server/Handlers/CrlHandler.cs`,
`RevocationHandler.cs`. Metrics are in `CaInstruments.cs`.

**Tests that prove it.**
* [CrlConformance.feature](../tests/opencertserver.certserver.tests/Features/CrlConformance.feature) —
   CRL generation, caching (`Expire(12h)`), per-profile paths, per-profile revocation scoping, and revocation flows.
* [CertificateAuthority.feature](../tests/opencertserver.certserver.tests/Features/CertificateAuthority.feature) —
   the CA's inventory + lifecycle.
* [CrlRevocation.feature](../tests/opencertserver.iq.tests/Features/CrlRevocation.feature) —
   Linux black-box qualification against the deployed container: default and RSA/ECDSA profile
   CRLs, OpenSSL decoding/signature verification, mTLS self-service, signed-JWT administrative
   revocation, rejection of non-admin cross-certificate revocation, and a dereferenceable CDP.
* [McpServerRevocation.feature](../tests/opencertserver.mcp.tests/Features/McpServerRevocation.feature) —
   the MCP `get_crl` and `get_revocation_status` tools.

---

## Client & integration layers

These aren't standard *protocols* but they're how OpenCertServer is wired into the rest of the
system, so they get a short section each.

### YARP per-route ACME

One YARP reverse proxy on a single HTTPS listener can auto-issue one ACME certificate per route,
selected by SNI, with each route renewed independently.

**Where it lives.** `src/opencertserver.acme.yarp/` — `YarpAcmeExtensions.cs`
(`AddAcmeProxy`, `WithAcmeRouteFilter`, `LoadFromMemory`),
`RouteAcmeMetadataExtensions.cs` (`.WithAcmeRoute`), and
`KestrelOptionsSetup` (SNI → leaf selection). Full code sample and explanation are in
[`src/opencertserver.acme.yarp/README.md`](../src/opencertserver.acme.yarp/README.md) and
summarized in [Getting started → ACME client per YARP route](getting-started.md#acme-client-per-yarp-route).

**Tests that prove it.** `tests/opencertserver.acme.yarp.tests`: `PerRouteIssuance` (two routes
place two orders, each serving its own cert), `PerRouteRegistration`, `KestrelSniSelection`,
`ChallengeApproval` (HTTP-01 across routes), `RenewalLifecycle`, `BackwardCompatibility`.

### MCP server

The MCP (`opencertserver.mcp`) package exposes the CA over a Model Context Protocol stdio transport
for AI agents (e.g. Claude Code, Cline, or any MCP host). It registers ten tools:

```
get_server_metadata, list_certificates, search_certificates, get_certificate,
get_ca_certificates, sign_certificate, revoke_certificate,
get_revocation_status, check_ocsp_status, get_crl
```

Each tool has a unique name, a non-empty description, a JSON Schema input schema, and is tagged
`ReadOnly`/`Idempotent`/`Destructive`. `sign_certificate` and `revoke_certificate` are the only
`Destructive: true` tools; an unknown tool name returns a failed result with error code
`McpErrorCode.ToolNotFound` (the JSON-RPC "method not found" code, `-32601`).

**What it is.** The server sits on the stdio pipe (JSON-RPC), reads the CA configuration from
`MCP_`-prefixed environment variables (e.g. `MCP_CA_DN`), and registers
`AddMcpServer().WithStdioServerTransport().WithTools<...>()` in
`src/opencertserver.mcp/Program.cs`. From a client, an MCP host calls the tool by name with a
JSON-encoded argument node.

**Security for the destructive tools.** `sign_certificate` and `revoke_certificate`
are the only `Destructive: true` tools and are therefore gated behind an authenticated,
authorized caller via `IMcpAuthorization`/`DefaultMcpAuthorization`
(`src/opencertserver.mcp/McpAuthorization.cs`):

* **Fail-closed by default.** `McpServerOptions.EnableCaOperations` defaults to `false`, so the
  server starts as a read-only MCP and does **not** register `sign_certificate` /
  `revoke_certificate`. Read-only tools (CRL / OCSP / query / metadata) remain available.
* **Opt-in CA operations.** Setting `McpServer:EnableCaOperations = true` registers the two
  destructive tools, but the server refuses to start unless a `McpServer:AuthenticationToken`
  is configured and a CA key source is opted into. In production that key must be the real,
  access-controlled CA key; `McpServer:AllowSelfSignedTestCa` (default `false`) is the explicit,
  loud switch that permits the in-memory self-signed "MCP Test CA", which is for development and
  tests only. This gating lives in `McpServerConfiguration.EnsureConfigured` and runs before the
  host starts.
* **Per-call authorization.** `McpServerOptions.RequireCallerAuthentication` (default `true`)
  makes every call require an authenticated caller. Signing requires authentication (mirroring
  `ca.server`'s `RequireAuthenticatedUser`); revoking additionally requires the
  `McpServer:RevocationRole` — defaulting to `RevocationAuthorizationConstants.CaAdminRole`
  (`ca_admin`) — matching the HTTP `ca.server` revocation handler, so a co-located caller may not
  revoke arbitrary certificates. The authenticated caller's `ClaimsIdentity` is passed to
  `SignCertificateRequest` as the `requestor` (never `null`), so requestor-aware validators can
  enforce authority. An unauthenticated/under-privileged call is rejected with an `McpException`
  before any CA mutation.

**Where it lives.** `src/opencertserver.mcp/Program.cs`,
`src/opencertserver.mcp/McpAuthorization.cs`, and
`src/opencertserver.mcp/Tools/*.cs` (one file per tool).

**Tests that prove it.**
* [McpServerTools.feature](../tests/opencertserver.mcp.tests/Features/McpServerTools.feature) —
   all ten tools register; each tool has valid metadata; an unknown tool returns `ToolNotFound`.
* [McpServerMetadata.feature](../tests/opencertserver.mcp.tests/Features/McpServerMetadata.feature) —
   `get_server_metadata` shape and versioning.
* [McpServerCertificateQuery.feature](../tests/opencertserver.mcp.tests/Features/McpServerCertificateQuery.feature) —
   `list_certificates`, `search_certificates`, `get_certificate`, `get_ca_certificates`.
* [McpServerCertificateOperations.feature](../tests/opencertserver.mcp.tests/Features/McpServerCertificateOperations.feature) —
   `sign_certificate`.
* [McpServerRevocation.feature](../tests/opencertserver.mcp.tests/Features/McpServerRevocation.feature) —
   `revoke_certificate`, `get_revocation_status`, `get_crl`, `check_ocsp_status` (with the
   `includePem` flag on `get_crl`).
* [McpServerParameterHandling.feature](../tests/opencertserver.mcp.tests/Features/McpServerParameterHandling.feature) —
   parameter validation.
* [McpServerAuthorization.feature](../tests/opencertserver.mcp.tests/Features/McpServerAuthorization.feature) —
   Fail-closed authorization: an unauthenticated caller is rejected for both `sign_certificate`
   and `revoke_certificate`; an authenticated caller without the `ca_admin` role may sign but not
   revoke; an authenticated `ca_admin` may sign and revoke; and the start gate refuses a CA-enabled
   server that has no token or has not opted into the self-signed test CA.


### OpenTelemetry metrics & traces

OpenCertServer emits OpenTelemetry counters/successes/failures/durations/activities under the
`opencertserver.{protocol}.{operation}.{type}` namespace for EST, ACME, SCEP, Intune, OCSP, CRL,
and CA endpoints. SCEP and Intune telemetry does not include request-derived values or exception
messages. The metric and trace name catalogue is in
[OpenTelemetry metrics & traces](../OpenTelemetryMetricsTraces.md).

**Where it lives.** `src/opencertserver.ca.server/CaInstruments.cs`, `MetricNames.cs`,
`ActivityNames.cs`; mirrored on the EST, ACME, SCEP, and Intune sides.

**Tests that prove it.**
[OpenTelemetryMetrics.feature](../tests/opencertserver.certserver.tests/Features/OpenTelemetryMetrics.feature) —
counters increment on `cacerts`, `simpleenroll`, `ocsp`, and friends.
[ScepServer.feature](../tests/opencertserver.scep.server.tests/Features/ScepServer.feature) and
[IntuneChallenge.feature](../tests/opencertserver.contrib.intune.tests/Features/IntuneChallenge.feature) /
[IntuneRevocationSync.feature](../tests/opencertserver.contrib.intune.tests/Features/IntuneRevocationSync.feature)
verify SCEP and Intune signals are emitted without attributes; SCEP also verifies that a signed
protocol refusal counts as a PKIOperation failure.

---

## Hardware & infrastructure integrations

### TPM-backed CA keys

`opencertserver.tpm` / `opencertserver.tss.net` lets the CA's private key be provisioned *inside* a
TPM so it never leaves the hardware. A `TpmCaProfileFactory` produces
`TpmRsa` / `TpmEcDsa` private-key implementations that the CA can use as the signing key for its
profile, and a rollover path produces `OldWithOld`, `OldWithNew`, and `NewWithOld` certificate
variants for a smooth transition.

**Where it lives.** `src/opencertserver.tpm/*` (provisioning) and
`src/opencertserver.tss.net/*` (the TPM2 binding
,
`Tpm2Device`, `LinuxTpmDevice`, `TpmKey`).

**Tests that prove it.**
[TpmKeyProvisioning.feature](../tests/opencertserver.tpm.tests/Features/TpmKeyProvisioning.feature) —
RSA/ECDsa keys are provisioned at fixed TPM handles and reused on subsequent startups; sign-verify
round-trips work; the two `TpmCaProfileFactory` variants produce CA certificates; and a rollover
publishes the three transition variants.

### Attestation backends (AMD SEV-SNP / Intel SGX / Apple Secure Element)

`opencertserver.attestation` is the hardware abstraction that backs
`device-attest-01`. It picks the platform's native package at load time (Apple SE
`SecurityFrameworkAppleAttestInterop`, AMD SEV-SNP, Intel SGX), exposes the attestation APIs to the
CA, and gives the solution a common `IAttestationProvider` / `IAttestationTrustProvider` interface.

**Where it lives.** `src/opencertserver.attestation/` — `*Native/*.cs` (one per platform),
`GlobalAttestationService.cs` (`GlobalServiceMapping` test target),
`AppleSeProvider.cs`, and `README.md`. See
`opencertserver.attestation/README.md` for the dependency map.

**Tests that prove it.** `tests/opencertserver.attestation.Tests` — `AmdSnpAttestation`,
`AmdSnpFailureModes`, `AmdSnpNativeAttestation`, `AppleAttestationValidation`, `AppleAttestFailureModes`,
`AppleNativeAttestation`, `AppleSeAttestation`, `SgxAttestation`, `SgxFailureModes`,
`SgxNativeAttestation`, `Config`, `GlobalServiceMapping`, `TrustStore`, `TrustStoreEdgeCases`.

### `opencert` CLI

The `opencertserver.cli` project ships an executable named `opencert` (see
[`Program.cs`](../src/opencertserver.cli/Program.cs)) built on `System.CommandLine`. Subcommands:
`print-cert`, `generate-keys`, `create-csr`, `create-csr-from-keys`, `sign-csr`, `est-enroll`,
`est-reenroll`, `est-server-certificates`. The code sample in
[Getting started → CLI](getting-started.md#4-use-the-opencert-cli) shows the full flag surface.

**Where it lives.** `src/opencertserver.cli/Program*.cs` — one partial class per subcommand
(`Program_GenerateKeys`, `Program_PrintCert`, `Program_CreateCsr`, `Program_CreateCsrFromKeys`,
`Program_SignCsr`, `Program_EstEnroll`, `Program_EstReEnroll`,
`Program_EstServerCertificates`).

**Tests that prove it.** `tests/opencertserver.cli.tests` —
`GenerateKeys`, `CreateCsrFromKeys`, `CreateCsrNonInteractive`, `OpenCertServerCli`.

---

## A summary of how the standards fit together

```
  ┌────────────────────────────┐   EST  ────  ┌──────────────────────┐
  │  Machine / device client   │─────────────▸│                      │
  │  (est-enroll, EstClient)   │              │  opencertserver      │
  └────────────────────────────┘   TLS 1.2/1.3  │  .certserver       │
                                              │  ───────────────    │
  ┌────────────────────────────┐  ACME  ────  │  ┌─ est.server      │
  │  Web application / YARP     │─────────────▸│  ├─ acme.server     │
  │  (AcmeClient, YARP ext.)    │─────────────▸│  ├─ ca.server       │
  │                             │  device-     │  └─ ca (core)       │
  │                             │  attest-01   │                     │
  └────────────────────────────┘  ──────────▸  │  Stores in-memory  │
                                              │  or on-disk         │
  ┌────────────────────────────┐              │                     │
  │  OCSP / CRL clients        │◂─────────────┤  /ca/ocsp, /ca/crl  │
  │  (browsers, OS validators)  │  HTTP/GET   │  /cacerts           │
  └────────────────────────────┘              └──────────────────────┘
        ▲
        │  status
        │
        ▼
  ┌─────────────┐   MCP   ┌──────────────────────┐
  │  AI agents   │◂───────►│  opencertserver.mcp   │  (stdio)
  │  (Claude…)  │  /tools │  CA as ten tools      │
  └─────────────┘         └──────────────────────┘
```

* **Enrollment** flows left → center: machines enroll over EST (RFC 7030), web apps over ACME
   (RFC 8555 + CAA, RFC 8659 + `accounturi`/`validationmethods`, RFC 8657), and hardware devices
   over `device-attest-01` (FIDO-style, TPM/SE-backed).
* **Status** flows right → left: OCSP (RFC 6960) and CRL (RFC 5280) answers "is this certificate
   still good?"
* **Automation** flows top ↔ bottom: the `opencert` CLI and the MCP server put every CA operation on
   the command line or behind a tool interface for AI agents.
* **Every claim on this page is locked in by a test** — see the bullet points under each standard
   for the exact `.feature` file.

## Server hardening (IQ installation profile)

The IQ scenarios assert a *hardened* installation. All of the following are already in
`opencertserver.certserver`'s `Program.cs` (the live server is hardened, not a test-only instance) and
are enabled by shipping `ASPNETCORE_ENVIRONMENT=Hardened` (the profile in
`src/opencertserver.certserver/appsettings.Hardened.json`, shipped as appsettings in the release image):

| Concern | Config surface | Effect when configured | Effect when absent |
|---|---|---|---|
| External account binding (RFC 8555 §7.3.4) | `AcmeServer:ExternalAccountKey:{keyId}` → `{MacKey,MacAlgorithm}` | The static `IStoreExternalAccountKeys` is populated and new-account requests may carry `externalAccountBinding`. | The ACME default in-memory store is empty: every new-account request carrying an EAB binding is rejected. |
| Device attestation (FIDO / `device-attest-01`) | `Attestation:TrustAnchors:[]` → list of PEM files | Roots are loaded into `IAttestationTrustProvider`; the device-attestation challenge succeeds for a chain that trusts one anchor. | No `IAttestationTrustProvider` is registered → `device-attest-01` fails closed. |
| OpenTelemetry / OTLP | `Telemetry:Enabled=true`, `Telemetry:OtlpEndpoint=http://collector:4317` | Meters and activity sources for ACME, EST, SCEP, Intune and CA operations export over OTLP. SCEP/Intune telemetry excludes request-derived attributes and exception messages. | No metrics or tracing are exported. |
| CDP / AIA / OCSP responder URLs (RFC 5280 / RFC 6960) | `CaServer:CrlDistributionPoints:[]`, `CaServer:OCSP:[]`, `CaServer:CaIssuers:[]` | Every issued certificate carries CRLDP, AIA OCSP + caIssuers extensions pointing at the configured responders. | Only the localhost loopback fallback is embedded on every issued certificate. |

The attestation trust roots are intentionally **not baked in** — the default (absent) posture fails
closed and offers no `device-attest-01` challenge; operators supply the roots per deployment via
`Attestation__TrustAnchors__0=<PEM>` (and `__1`, `__2`, …). The `AcmeServer:ExternalAccountKey`
`MacKey` shipped in the profile is an **example** and must be rotated before real use.

### OpenTelemetry metrics emitted

| Meter | Counter | When |
|---|---|---|
| `opencertserver.acme` | `opencertserver.acme.newaccount.{successes,failures}` | an ACME new-account request completes. |
| `opencertserver.acme` | `opencertserver.acme.orderfinalize.{successes,failures}` | an ACME order finalization completes. |
| `opencertserver.est` | `opencertserver.est.simpleenroll.{successes,failures}` | an EST enrollment completes. |
| `opencertserver.ca` | `opencertserver.ocsp.request.{requests,successes,failures}` | an OCSP request is handled. |

### Authority information a Linux client observes

Issued certificates carry the RFC 5280 extensions below, which the `openssl x509 -text` inspector in
`tests/opencertserver.iq.tests/client/assert.sh` checks: CRL Distribution Point, Authority Information
Access (OCSP responder + `caIssuers`), and OCSP responder signature verification. These are asserted by
`tests/opencertserver.iq.tests/Features/AuthorityInformation.feature`.
