# OpenCertServer documentation

This is the **endpoint and configuration reference** for OpenCertServer and the hub that ties the
documentation set together.

Start elsewhere:

| I want to… | Read this |
|---|---|
| Understand what OpenCertServer is and where everything fits | [../README.md](../README.md) (project overview) |
| Get a CA running and enroll a first certificate | [Getting started](getting-started.md) |
| See every standard implemented and the tests that prove it | [Implemented standards](standards.md) |
| Read the operational rules | [Certification Practice Statement](opencertserver_cps.md) / [Certificate Policy](opencertserver_cp.md) |
| Run it in Docker | [Docker.md](../Docker.md) |
| Report a vulnerability | [SECURITY.md](../SECURITY.md) |
| See the metrics/traces the server emits | [OpenTelemetry metrics & traces](../OpenTelemetryMetricsTraces.md) |
| Integrate the CA into YARP | [opencertserver.acme.yarp/README.md](../src/opencertserver.acme.yarp/README.md) |
| Feed the CA to an AI agent | [opencertserver.mcp/README.md](../src/opencertserver.mcp/README.md) |
| Issue certificates to Intune-managed devices | [SCEP with Intune](#scep-with-intune), [opencertserver.contrib.intune/README.md](../src/opencertserver.contrib.intune/README.md) |
| Wire device attestation | [opencertserver.attestation/README.md](../src/opencertserver.attestation/README.md) |

This page keeps the concrete HTTP surface — methods, paths, content types, and authentication — so
you don't have to read handler source. The reasoning and the RFC citations for each protocol live in
[Implemented standards](standards.md); runnable code that exercises them is in
[Getting started](getting-started.md).

---

## Host perimeter and deployment configuration

### Optional PostgreSQL persistence

`opencertserver.data` implements the ACME account, order, nonce and external-account-key
stores and the CA certificate inventory behind their existing interfaces without depending
on a database engine. The optional `opencertserver.data.postgresql` dependency owns Npgsql,
SQL, migrations and design-time tooling. Configure it before building the service provider;
the standalone host selects storage modes and calls `AddPostgreSqlStore()` followed by
`AddAcmeRelationalStore(configuration, "OpenCertServer")` and/or
`AddCaRelationalStore(configuration, "OpenCertServer")` for the selected relational stores.
Embedded hosts must register an `IRelationalStoreProvider` before selecting relational
storage. No schema changes run automatically during server startup.

| Key (environment form) | Default | Meaning |
|---|---|---|
| `AcmeServer__Persistence` | `memory` | `memory`, `file` (existing `AcmeFileStore` settings), or `relational` |
| `Ca__Persistence` | `memory` | `memory` or `relational` |
| `ConnectionStrings__OpenCertServer` | unset | Standard named connection string used by the standalone host and default migration tooling; supply through a secret provider |

The mode settings belong to the standalone host, not the shared data registration API.
Embedded hosts explicitly register relational stores with an `IConfiguration` and connection
string name (`GetConnectionString`), or with a connection string directly.
The old per-section relational connection keys and `OCS_RELATIONAL_CONN` fallback are not read.
ACME and CA can select persistence independently. If both select relational storage,
their connections must match because they share one context/schema. Unsupported host selections
and missing connections/providers fail at registration rather than silently reverting to memory.
Existing `ExternalAccountBinding:Keys` configuration still installs the host's read-only
static external-account-key store; omit it when provisioning keys in the relational store.
Embedded hosts can instead reference `opencertserver.data.mssql` and register
`AddMsSqlStore()` from `OpenCertServer.Data.MsSql` before the same shared-store registrations.
It owns SQL Server configuration, atomic SQL and separate migrations. The standalone host
remains wired to PostgreSQL; it does not select an engine from a connection-string format.
See [the MSSQL adapter](../src/opencertserver.data.mssql/README.md).
Redis and further database providers are deferred.

**Runtime support:** untrimmed JIT deployments. Native AOT is not qualified after the
provider split; provider-specific compiled-model/query generation and runtime integration
are still required. Apply migrations separately with a JIT deployment tool using the
chosen adapter project, not the shared data project.

Accounts, orders and external-account keys use optimistic version checks, raising the
existing ACME `ConcurrencyException` for stale writes. Nonce consumption is one atomic
SQL delete. Certificates are stored as public PEM only, with UTC validity/revocation dates;
CA signing keys are **not** stored in this database.

Relational timestamps retain the selected database's precision. PostgreSQL stores
microseconds, so Npgsql truncates any sub-microsecond .NET ticks; the MSSQL adapter
preserves 100-nanosecond ticks.

See [the PostgreSQL setup guide](getting-started.md#postgresql-persistence) for schema
deployment, operational boundaries and the provider-table BDD tests.

The standalone `opencertserver.certserver` host applies these policies to every protocol,
including health checks:

| Policy | Behavior |
|---|---|
| TLS | TLS 1.2 and 1.3 only. On Linux/OpenSSL, an explicit allow-list permits TLS 1.3 AES-GCM/ChaCha20-Poly1305 and TLS 1.2 ECDHE-RSA/ECDHE-ECDSA AES-GCM/ChaCha20-Poly1305; CBC and static RSA key exchange are excluded. Other operating systems retain their cipher policy and emit a startup warning; the Linux container is the qualified deployment. |
| HSTS | HTTPS responses publish `Strict-Transport-Security: max-age=15552000` (180 days), including localhost. Subdomains and preload are not enabled. HTTP requests redirect to HTTPS. |
| Host filtering | Base and Hardened profiles default `AllowedHosts` to `localhost;127.0.0.1;[::1]`. Other hosts receive 400 before redirects or application endpoints. Configure the actual service names for deployment. |
| Request framing | Conflicting Content-Length/Transfer-Encoding is rejected with 400 before redirects/authentication. The Kestrel normalization marker `X-Content-Length` is reserved and also rejected. HTTP/1.x connections close without processing an appended request. Duplicate conflicting Content-Length is rejected by Kestrel. |
| Authentication | The default scheme selects JWT bearer when a Bearer header is present, otherwise certificate authentication. Default challenges use JWT bearer, so anonymous CA issuance receives 401 instead of an unconfigured-scheme 500. EST and revocation keep their explicit multi-scheme policies. |

Set the semicolon-separated `AllowedHosts` environment variable to every accepted hostname
without ports, for example `ca.example.com;opencertserver;localhost`. Include the Host used
by health probes, or set probes to send an approved Host explicitly. Avoid the unrestricted
`*` value, which disables host filtering. Standard configuration precedence applies:
command-line values override environment variables, which override environment-specific
JSON and then base JSON. The base file is not reapplied over deployment overrides.

These are production-host policies, not pentest-only settings.
[`CertificateServerSecurity.feature`](../tests/opencertserver.iq.tests/Features/CertificateServerSecurity.feature)
qualifies them using OpenSSL, Nmap, curl and raw TLS probes in Linux against the real server
container; the [IQ README](../tests/opencertserver.iq.tests/README.md#certificate-server-penetration-scenarios)
contains execution instructions.

---

## Certificate Authority (CA) endpoints

The CA endpoints are mounted by the `ca.server` handlers under `/ca` in the `certserver` host. They
are secured by TLS client-certificate authentication: Kestrel accepts a client certificate
(`ClientCertificateMode.AllowCertificate`, any certificate at the TLS layer) and the certificate
authentication handler (`CertificateAuthenticationDefaults.AuthenticationScheme` = `"Certificate"`)
validates it against the CA's own certificates. The TLS handshake proves possession of the
client's private key. Certificate headers, including `X-Client-Cert`, are ignored by default,
both in `certserver` and applications embedding `UseEstServer()`.

### Trusted client certificate forwarding

Forwarding is only appropriate for a TLS-terminating proxy that verifies the client's TLS
certificate and removes and replaces the certificate header on **every** incoming request.
A public certificate in an HTTP header is not proof of possession of its private key.
Prefer direct mTLS or TLS passthrough whenever possible.

The standalone host accepts forwarding only with explicit configuration:

```json
{
  "CertificateForwarding": {
    "Enabled": true,
    "CertificateHeader": "X-Client-Cert",
    "KnownProxies": ["192.0.2.10"],
    "KnownNetworks": []
  }
}
```

`Enabled` defaults to false. When enabled, a header name and at least one trusted proxy IP
or CIDR network are required; missing or malformed configuration fails at startup.
Environment equivalents include `CertificateForwarding__Enabled=true`,
`CertificateForwarding__CertificateHeader=X-Client-Cert`, and
`CertificateForwarding__KnownProxies__0=192.0.2.10`.
Keep allowed networks as narrow as possible: every host in them is trusted to assert identities.

Embedded hosts opt in with `AddTrustedCertificateForwarding(header, configureTrustedProxies)`
and `UseTrustedCertificateForwarding()`. The configure action uses
`ForwardedHeadersOptions.KnownProxies` / `KnownIPNetworks` (the .NET 10 network API).
This middleware must precede address forwarding and authentication: it checks the **original
connection peer**, not an attacker-controlled `X-Forwarded-For` value, and strips the configured
certificate header on untrusted requests without replacing a genuine TLS client certificate.
The ordinary forwarded-address configuration does not grant certificate-forwarding trust.

**Upgrade requirement.** Remove unconditional `UseCertificateForwarding()` from custom host
pipelines. Direct EST clients must present their certificate **and private key** through mTLS.
`EstClient` no longer sends `X-Client-Cert` during renewal. The default transport creates a fresh
TLS session when switching client identity, including from anonymous enrollment to renewal.
If supplying a custom `HttpMessageHandler`, the caller must configure mTLS and isolate its
connections by client identity; `EstClient` cannot configure an arbitrary external transport.

**Validity window.** When the caller does not request a `notBefore` - EST never does, ACME only when
the order carries one - an issued certificate is valid from midnight UTC of the day it is issued, for
the profile's `CertificateValidity`. The same applies to the CA's own self-signed certificates. This
does not depend on the server's local time zone
([CertificateValidity.feature](../tests/opencertserver.certserver.tests/Features/CertificateValidity.feature)).

### Profile configuration (certserver)

`certserver` builds one profile per key file pair (`--rsa`/`--rsa-key`, `--ec`/`--ec-key`) and
reads the rest of the profile from configuration under the profile's name (`rsa:…`, `ecdsa:…`;
as environment variables `rsa__…`):

| Key | Meaning |
|---|---|
| `PublishedPem` | Optional additional PEM certificates to publish alongside the issuing chain, e.g. rollover certificates (also `--rsa-published` / `--ec-published`). |
| `TrustAnchors` | PEM file path or array of paths containing explicit roots for EST client authentication against this profile only. Every certificate in these files is explicitly trusted. Default: none beyond the issuing chain's roots. |
| `AdditionalChainCertificates` | PEM file path or array of paths containing untrusted CA intermediates for this profile's EST client authentication. Does not establish trust. Default: none. |
| `CertificatePolicies` | Policy OIDs the CA asserts in every certificate from this profile; an array section (`rsa__CertificatePolicies__0=…`) or one value with the OIDs separated by commas. Default: none. |
| `KeyUsage` | Key usage flags fixed for every certificate, by name, several separated by commas (`DigitalSignature, KeyEncipherment`). Default: the CSR's. |
| `ExtendedKeyUsages` | Extended key usage OIDs fixed for every certificate, array section or comma-separated. Default: the CSR's. |

What the profile fixes replaces what the CSR asked for; see
[Implemented standards → Certificate content fixed by the profile](standards.md#certificate-content-fixed-by-the-profile-certificatepolicies-keyusage-extendedkeyusages).

The `--rsa` / `--ec` PEM file contains the active issuing certificate first, followed by its
intermediate chain and root. All of these certificates populate `CaProfile.CertificateChain`.
RFC 7030 section 4.1.3 requires `/cacerts` to include the current root and the intermediates needed
to validate issued certificates: `PublishedCertificateChain` supplements, never replaces, that chain.

**Key algorithms.** A profile signs requests of either key algorithm: an ECDSA profile issues for an
RSA key and the reverse. The issued certificate keeps the request's key and carries the signature
algorithm of the profile's CA key
([CertificateAuthority.feature](../tests/opencertserver.certserver.tests/Features/CertificateAuthority.feature),
"A profile signs requests of either key algorithm").

### GET /ca/crl

- Description: Retrieve the current Certificate Revocation List for the CA (or a profile).
- Paths: `/ca/crl` and `/ca/{profile}/crl`.
- Response: `application/pkix-crl` (DER). Cached for 12 hours.
- Scope: each profile's CRL lists only certificates issued under that profile; revocations from other profiles are never included.
- Partitioning: each CRL has a critical `issuingDistributionPoint` naming the profile's CRL URL, and issued certificates carry the same URL in `cRLDistributionPoints`. Use the `{profile}` token in `CaServer:CrlDistributionPoints` (e.g. `http://localhost:6001/ca/{profile}/crl`). With more than one profile, untokenized URLs are rejected (fail closed). The MCP `get_server_metadata` tool reports the raw templates, including `{profile}`.

### DELETE /ca/revoke

- Description: Revoke a certificate.
- Query parameters:
   - `sn` (hexadecimal string, required): the serial number of the certificate to revoke, in
     .NET `GetSerialNumberString()` form. Preserve any leading `00` ASN.1 INTEGER sign byte
     (OpenSSL's `x509 -serial` display omits it).
   - `reason` (string, required): the revocation reason (e.g. `keyCompromise`,
     `cessationOfOperation`).
   - `signature` (base64 string, required): a SHA-256 signature of `serialNumber + reason` produced
     with the private key of the certificate being presented (proof of key possession).
- Authorization: requires an authenticated user (policy `"ca_revoke"`). Two paths are accepted:
   - **Self-service** — the presented client certificate is the same certificate being revoked
     (serial number matches **and** thumbprint matches the copy stored in the CA's certificate
     store). This confirms the certificate was issued by this CA, not just any certificate that
     happens to share the same serial number.
   - **Administrative** — the caller's identity carries the claim `role = ca_admin`
     (see `RevocationAuthorizationConstants.CaAdminRole`). Admins may revoke any certificate.
   - Any other combination returns `403 Forbidden`.
- The standalone host explicitly authenticates this policy with its certificate and JWT bearer
  schemes. Self-service can use mTLS alone; administrators can present a signed JWT from the
  configured `--authority` with the configured `--audience` and `role = ca_admin`, alongside
  the client certificate and proof-of-possession signature. JWT authority settings are applied
  before the framework initializes OIDC discovery and signing-key retrieval.
- Response: `200` on success, `404` if the serial number is unknown, `401` if authentication
  fails, `403` if authorization fails.

### POST /ca/ocsp  and  GET /ca/ocsp/{base64url}

- Description: a signing OCSP responder ([RFC 6960](https://www.rfc-editor.org/rfc/rfc6960)).
- `POST /ca/ocsp` takes a DER-encoded OCSP request and returns
   `application/ocsp-response` with a signed `BasicOCSPResponse`.
- `GET /ca/ocsp/{base64url}` accepts a URL-safe base64-encoded request (RFC 6960 Appendix A).
- Malformed requests return `malformedRequest`; a refused service returns `unauthorized`; responder
   faults return `internalError` / `tryLater`.

> See [Implemented standards → OCSP](standards.md#ocsp--rfc-6960) for the full status-value,
> freshness, and extension behaviour, and `tests/…/Features/OcspConformance.feature` for the
> conformance scenarios.

### ACME directory and lifecycle

When ACME is mounted (`UseAcmeServer()`), the CA host also serves the ACME directory and order
lifecycle alongside the CA endpoints. See the ACME section below and
[Implemented standards → ACME](standards.md#acme--rfc-8555).

---

## EST endpoints

EST endpoints are mounted under `/.well-known/est` by `UseEstServer()`. The server authenticates a
request by either mutually-authenticated TLS (client certificate) or a JWT bearer token; the CA
chain is retrievable without authentication.

### EST client-certificate trust anchors

RFC 7030 section 3.3.2 defines the EST **server's** trust database used to authenticate clients.
Configure profile-specific trust on `CaProfile.TrustAnchors` and
`CaProfile.AdditionalChainCertificates` (or `rsa:TrustAnchors` / `rsa:AdditionalChainCertificates`
and the equivalent `ecdsa` settings in `certserver`). The selected profile's issuing chain remains
available: its self-issued root certificates establish trust; intermediates only help build paths.
The unlabelled EST URL uses the default profile, not a union of all profiles' trust.

Only certificates intentionally common to **every** EST profile belong in
`IEstTrustAnchorProvider` / `AddEstTrustAnchors`. The host configures those using
`Est:ExplicitTrustAnchors` (`Est:TrustedClientCerts` is an alias). These existing server-wide
settings accept a single PEM path or an array; within each file, list intermediates first and the
trust anchor last. Profile settings instead keep roots and intermediates in separate files/collections.
Trust anchors and additional chain certificates
must declare `Basic Constraints: CA:TRUE`; a present key-usage extension must permit certificate
signing. Missing files, malformed PEM, files without certificates, or invalid CA certificates fail
host startup rather than silently disabling the configured trust.

```json
{
  "rsa": {
    "TrustAnchors": ["/etc/opencertserver/rsa-client-root.pem"],
    "AdditionalChainCertificates": ["/etc/opencertserver/rsa-client-intermediate.pem"]
  },
  "Est": {
    "ExplicitTrustAnchors": [
      "/etc/opencertserver/est-client-root.pem"
    ]
  }
}
```

In environment-based configuration, use `rsa__TrustAnchors__0` for profile trust and
`Est__ExplicitTrustAnchors__0` for server-wide trust.
External anchors apply only to requests under `/.well-known/est`; CA and other endpoints continue
to validate client certificates against the CA's own chain. The server still checks the client
certificate's validity period and client-auth EKU, rejects CA certificates as client identities,
and applies the configured certificate revocation mode. `certserver` does not cache certificate
authentication results because trust is route-scoped; embedded hosts must not use a route-independent
certificate-authentication cache with EST trust anchors.

Client-authentication roots are **not** automatically published by `/cacerts`. Section 4.1.3
describes the issuing CA trust that clients use to validate issued certificates and subsequently
authenticate the EST server, not all third-party CAs permitted to enroll. Configure that publication
through `CaProfile.CertificateChain` and `PublishedCertificateChain`; the EST TLS certificate must
chain to the advertised issuing trust when clients switch to explicit trust. This refactor does
not enable OS/implicit client trust or change enrollment authorization policy.

### GET /.well-known/est/cacerts

- Description: Retrieve the CA certificate chain.
- Response: `application/pkcs7-mime; smime-type=certs-only`, containing base64-encoded DER
  PKCS#7 certificates (cached 30 days). No authentication required.

### GET /.well-known/est/csrattrs

- Description: Return a `CsrAttributesResponse` ([RFC 9908](https://www.rfc-editor.org/rfc/rfc9908))
   that tells the client the CSR template, key usage, and subject to fill in.
- Response: `application/csrattrs`.

The standalone `certserver` host publishes an optional file configured by
`Est:CsrAttributesFile` (`Est__CsrAttributesFile=/certs/csrattrs.der` in the environment).
The file contains a **nonempty DER CsrAttrs sequence**, which may include RFC 9908
`CertificationRequestInfoTemplate` values or legacy OID/attribute requirements. The same
response is used for all profiles and is base64-encoded on the wire. With no file configured,
the host returns HTTP 204 as before. The file is read on each request; unreadable, malformed
or empty configured content fails the request and is logged by the host, rather than silently
returning no requirements. Embedded hosts can still supply their own `ICsrTemplateLoader`.

### POST /.well-known/est/simpleenroll

- Description: Enroll a new certificate.
- Request body: a PKCS#10 CSR in PEM or DER (`Content-Type: application/pkcs10` or
   `application/x-pkcs10`).
- Authentication: a client certificate, a JWT bearer token, or - where users are configured - a
   user name and password (HTTP Basic, RFC 7030 §3.2.3; see [EST Basic authentication](#est-basic-authentication)).
- Identity binding: when the authenticated identity carries a name (`name`, `email`, `upn` or
   `preferred_username` claim - the certificate handler maps CN and E to the first two), every
   name the CSR asserts must be one of them: the common name, and every rfc822Name, dNSName and
   user principal name in the subject alternative names. A URI or IP address in the SAN is not an
   identity and is left to the profile's extension rules. The check is `AuthenticatedSubjectValidation`;
   `ICertificateRequestValueConverter` decides which CSR values are compared.
- Response: the issued leaf+chain, with the format negotiated from the `Accept` header —
   `application/pkix-cert` (leaf+chain DER), `application/pem-certificate-chain` (PEM), or
   `application/pkcs7-mime` (wrapped).

### POST /.well-known/est/simplereenroll

- Description: Re-enroll using an existing certificate or the server-key-generated key.
- Authentication: an accepted EST scheme (certificate, JWT or configured Basic), with the
   certificate being renewed supplied through mTLS or explicitly trusted-proxy forwarding.
- The certificate being renewed must have been signed by one of the profile's CA certificates
   (`OwnCertificateValidation` verifies the signature; a matching issuer name alone is not enough), and
   must not have been revoked by this CA (the store is asked by serial number). The CA also
   requires the certificate's current validity window, independently of JWT/Basic authentication:
   expired and not-yet-valid certificates cannot renew. Use fresh enrollment instead.
   A profile that holds only its issuing intermediate, without the root, works.
- **Profile binding:** the CA records the resolved issuing profile with each issued certificate.
   `OwnCertificateValidation` looks up that provenance by the exact certificate thumbprint and
   requires an ordinal, case-sensitive match with the resolved requested profile. This applies to
   both `/{profileName}/simplereenroll` and the default route, and to direct CA re-enrollment calls.
   Sharing a CA key/chain does not authorize moving between profiles.
- **Upgrade/custom-store behavior:** missing provenance fails closed, including imported certificates,
   certificates issued before profile tracking, and certificates lost from an in-memory store after
   restart. Custom `IStoreCertificates` implementations must persist the profile in the
   `AddCertificate(certificate, issuingProfile, cancellationToken)` overload and implement
   `GetIssuingProfile(thumbprint, cancellationToken)` to support renewal. The compatibility defaults
   still support issuance, but report unavailable provenance and therefore cannot authorize renewal.
   Use fresh enrollment when provenance cannot be recovered from trusted issuance records.
   EKUs/policies are not a substitute: different profiles can have identical extensions but different
   validity or enrollment requirements. Hosts intentionally allowing transitions or legacy renewal
   must replace `OwnCertificateValidation` with an explicit validator (retaining issuer-signature
   validity and revocation checks); adding a permissive validator alongside it does not override its rejection.
- Response: as `simpleenroll`.

### POST /.well-known/est/serverkeygen

- Description: The server generates the key pair on the client's behalf and enrolls the certificate.
- Authentication: a client certificate or a JWT.
- Response: a `multipart/mixed` bundle containing the issued certificate **and** the generated
   private key in PEM.

Per-profile variants of the above (`{profile}/cacerts`, `{profile}/csrattrs`, …) let one server act
as multiple logical CAs. For runnable client code (including `ServerKeyGeneration`) see
[Getting started → EST](getting-started.md#enroll-a-certificate-via-est-jwt-bearer-auth).

Profile-bound renewal is not enrollment authorization. `simpleenroll` and `serverkeygen` are
fresh issuance paths: their default policies require authentication, not membership in the
requested profile. Hosts using profiles as permission boundaries must supply appropriate
`enrollPolicy` and `serverKeyGenPolicy` authorization policies as well as restrict the CA CSR
routes described under [Authentication](#authentication).

> See [Implemented standards → EST](standards.md#est--rfc-7030) for the full RFC 7030 + RFC 8951 +
> RFC 9908 behaviour and the `EstConformance.feature` scenarios.

---

### EST Basic authentication

`certserver` accepts a user name and password for `simpleenroll`, `simplereenroll` and
`serverkeygen` once users are configured; without users the scheme is off and no challenge is
offered. The identity is the user name (`name` and `sub` claims) - with subject binding, a user
enrolls for its own name only. Passwords are stored as hashes; `opencert hash-password` makes them
(the password is read from standard input, never from the command line).

| Key | Meaning |
|---|---|
| `Est:BasicAuth:Users:<name>` | The user's password hash (`pbkdf2-sha256$…`). In the environment: `Est__BasicAuth__Users__<name>=…`. |
| `Est:BasicAuth:UsersFile` | A file with one `name:hash` per line (`#` starts a comment), read again whenever it changes - for a secret that should not sit in an environment variable. A file that exists but cannot be read (owner, mode) is logged once as an error and counts as empty until it changes. |
| `Est:BasicAuth:Realm` | The realm in the challenge. Default `EST`. |

A host that embeds the EST server registers the scheme with `AddEstBasicAuthentication(...)` and
lists `EstBasicAuthenticationDefaults.AuthenticationScheme` in the policies it passes to
`UseEstServer`; the default policies know certificates and tokens only.

Clients: `opencert est-enroll --user name:password …`, or any EST client that sends
`Authorization: Basic` - strongSwan's `pki --est --userpass name:password`, for example.

## SCEP endpoints

The SCEP server (RFC 8894) is mapped by `MapScepServer()` under `/scep`. Every operation is one
request to the same path with `?operation=`; SCEP clients authenticate with the challenge password
inside the request, not over HTTP, so the endpoint allows anonymous access. The reasoning, the
renewal rules and what Windows does differently are in
[Implemented standards → SCEP](standards.md#scep--rfc-8894).

| Method and path | Operation |
|---|---|
| `GET /scep?operation=GetCACaps` | Capabilities, `text/plain`. |
| `GET /scep?operation=GetCACert` | RA certificate and the profile's published chain, `application/x-x509-ca-ra-cert`. |
| `POST /scep?operation=PKIOperation` (or `GET …&message=`) | `PKCSReq` or `RenewalReq` in `application/x-pki-message`; the reply is a `CertRep` of the same type. |
| `/scep/{profile}` | The same for a named CA profile; `/scep` is the default profile. |
| `/scep/pkiclient.exe`, `/scep/{profile}/pkiclient.exe` | The same - Windows appends `/pkiclient.exe` to the configured URL. |

Malformed CMS messages, requests with an invalid `senderNonce`, and undefined message types
receive HTTP 400. A verified request whose decrypted payload is not a certificate request, or a
valid `CertPoll` request (message type `20`), receives a signed `FAILURE` `CertRep` with
`failInfo=badRequest`; pending requests are not stored.

The `transactionID` must contain 1 to 128 ASN.1 PrintableString characters (letters, digits,
space, and `'()+,-./:=?`), which includes hex and base64 IDs. UTF8String and IA5String encodings
remain accepted only when their values satisfy that constraint. Invalid IDs receive HTTP 400
before envelope processing or transaction logging, with one SCEP rejection warning that does
not echo the ID or include a stack trace. No `CertRep` is returned because it cannot safely echo
an invalid ID. Boundary and malformed-ID cases are covered in
[`ScepCompliance.feature`](../tests/opencertserver.scep.server.tests/Features/ScepCompliance.feature).

`PKIOperation` issues nothing until a challenge validator is configured; `GetCACaps` and
`GetCACert` return public information only.

### SCEP configuration (certserver)

| Key or argument | Meaning |
|---|---|
| `Scep:Challenge` | A shared challenge password for every request (`Scep__Challenge` in the environment - not a command-line argument, where it would show in the process list). Without it, and without `Scep:Intune`, nothing is issued. |
| `Scep:DefaultProfile` | The CA profile for `/scep` and `/scep/pkiclient.exe`. Default: the CA's default profile. |
| `--scep-ra <pem>` / `--scep-ra-key <pem>` | The RA certificate and its **RSA** private key. Without them a self-signed RA is created at start-up and changes with every restart; clients fetch `GetCACert` before each enrollment and tolerate that, but a deployment that pins the RA configures one. |

A host that embeds the server calls `AddScepServer(new ScepServerOptions { RaCertificate = … },
validator)` and `MapScepServer()`. `ScepServerOptions.TransactionIdWindow` (default 24 hours) is how
long an accepted request (transaction ID and senderNonce) is remembered for replay protection;
`MaxRememberedRequests` (default 100,000) bounds that store - only requests that passed their
checks are remembered, and when it is full a new request is refused.

### SCEP with Intune

With a `Scep:Intune` section, `certserver` validates every request with Intune instead of a shared
secret (`opencertserver.contrib.intune`) and maps the revocation sync:

| Key | Meaning |
|---|---|
| `Scep:Intune:TenantId` | The Entra tenant (GUID or domain). |
| `Scep:Intune:ClientId` | An app registration with the Intune application permission `scep_challenge_provider` and, for the sync, the Graph application permissions `User.Read.All`, `Device.Read.All` and `DeviceManagementManagedDevices.Read.All` - all with admin consent. |
| `Scep:Intune:ClientCertificateFile` + `ClientCertificateKeyFile` | The app's certificate credential (PEM, RSA key); only the public half goes to Entra. Preferred over a secret. |
| `Scep:Intune:ClientSecret` / `ClientSecretFile` | Alternatively the secret, or a file whose first line holds it. |
| `Scep:Intune:CallerInfo` | Shown in Intune's logs. Default `OpenCertServer`. |
| `Scep:Intune:LoginBase`, `GraphBase`, `IntuneResource` | Override for national clouds. |
| `Scep:Intune:ValidationEndpoint` | A fixed address of the validation service instead of Graph discovery. |
| `Scep:Intune:Timeout` | Per request to Intune or Graph. Default 30 seconds. |
| `Scep:Intune:MaxRevocationsPerSync` | A sync that would revoke more aborts. Default 25. |
| `Scep:Intune:SyncProfiles` | The CA profiles Intune issues through; the sync judges only certificates the store recorded as issued from one of them. Array (`SyncProfiles__0`) or comma-separated. Empty: the sync checks nothing. |

`POST /scep/intune/sync?dryRun=true|false` runs the revocation sync and returns its report (what
was revoked and why, what could not be checked); 409 while a run is in progress. It requires the
policy `scep_intune_sync`, which `certserver` grants to the `ca_admin` role over the same
authentication schemes as the CA endpoints.

## ACME endpoints

ACME endpoints are mounted by `UseAcmeServer()` and protected by RFC 8555 account-based JWS
authentication. Requests are signed with compact JWS ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515));
every error response is `application/problem+json` ([RFC 7807](https://www.rfc-editor.org/rfc/rfc7807)).

### GET /directory

- Description: The ACME directory. Advertises `newNonce`, `newAccount`, `newOrder`, `keyChange`,
   `revokeCert`, and — when device attestation is enabled — `meta.challengeTypesWithAdditionalContent`
   listing `http-01`, `dns-01`, and `device-attest-01`.

### HEAD/GET /new-nonce

- Description: Fetch a fresh nonce. Every mutating request consumes a nonce and a used nonce is never
   reused.

### POST /new-account

- Description: Create (or fetch) an ACME account. Supports external account binding (EAB, §6.7).
- Response: the account object with a `Location` (its `kid`).

### POST /new-order

- Description: Create an order for a set of identifiers (domains/SANs).
- Request body: a JWS payload containing `identifiers` and an optional `profile` field selecting a named CA profile.

### POST /order/{orderId}

- Description: Retrieve an order's current status and its authorizations (POST-as-GET).

### POST /order/{orderId}/auth/{authId}

- Description: Retrieve an authorization and its challenges (POST-as-GET).

### POST /order/{orderId}/auth/{authId}/chall/{challengeId}

- Description: Trigger (and re-trigger) a challenge validation. `http-01` is approved by the
  challenge middleware answering the domain's `/.well-known/acme-challenge/{token}`; `dns-01` is
  approved by the hosted validation service; `device-attest-01` by the device attestation
  validator. Responses include `Link: <authorization-url>;rel="up"`.


### POST /order/{orderId}/finalize

- Description: Submit a CSR to finalize the order once all authorizations are `valid`.
- Request body: a base64url-encoded PKCS#10 CSR.
- Response: the order with a `certificate` URL.

### POST /order/{orderId}/certificate

- Description: Retrieve the issued certificate for a completed order (POST-as-GET).
- Response: `application/pem-certificate-chain` — the end-entity certificate followed by its issuer
  certificates (RFC 8555 §7.4.2).

### POST /revoke-cert

- Description: Revoke a certificate, authenticated by the holder's key.
- Request body: `{ certificate, reason? }`.

For challenge types, CAA enforcement, and the `device-attest-01` validator, see
[Implemented standards → ACME / CAA / device attestation](standards.md#acme--rfc-8555).

---

## Device attestation (device-attest-01) challenge

`device-attest-01` is an ACME challenge type that replaces domain control with hardware identity.
The device submits an Attestation Identity Key (AIK) certificate and a TPM proof as the JSON
payload of its signed POST to the challenge URL. Fields are `nonce` (the challenge token),
`proof` (base64url TPM2B_ATTEST bytes), `signature` (base64url RSA-PKCS1v15/SHA-256 signature over
those bytes), and `aikCertificate` (base64url DER certificate). The server stores this evidence
in `challenge.ExtraData` before asynchronous validation; clients do not send an `extraData` wrapper.

**Security model (fail-closed).** The validator and the authorization factory are both gated on the
trust provider:

- With an **empty** `IAttestationTrustProvider` (the default after `AddAcmeServer`):
  - `DefaultAuthorizationFactory` **does not create** a `device-attest-01` challenge for any order,
    so it is not offered in authorizations. The directory still advertises support in
    `meta.challengeTypesWithAdditionalContent`.
  - If a client somehow submits a `device-attest-01` response, `DeviceAttestChallengeValidator`
    rejects it immediately with `invalid_attestation` — system trust is **never** used as a fallback.
- With a **non-empty** provider (manufacturer root CAs injected):
  - `device-attest-01` appears in orders and is validated against the injected roots only.
  - AIK revocation is checked online (`X509RevocationMode.Online`); explicitly revoked certs are
    rejected. Unknown status (e.g. no CDP/AIA in the manufacturer cert) is tolerated.

**Three validation checks** (mirrored by `device-attest-validation.feature`):
1. **Chain verification** — AIK must chain to an injected root under `CustomRootTrust` mode.
2. **Proof verification** — TPM magic, attestation type, and nonce-bind must match the challenge.
3. **Anti-replay** — consumed nonce rejected on second use with `replay_nonce`.

An additional evidence submission to an already processed device challenge returns HTTP 400
`application/problem+json`, type `urn:ietf:params:acme:error:replay_nonce`, even when the outer
ACME JWS nonce is fresh. Empty-payload POST-as-GET reads remain available and do not change the
original result. This device-specific behavior does not change `http-01` or `dns-01` submissions.

The standalone host loads manufacturer PEM bundles from `Attestation:TrustAnchors` (for example,
`Attestation__TrustAnchors__0=/certs/manufacturer.pem`). Without that setting it retains empty trust.
The Linux black-box [DeviceAttestation IQ feature](../tests/opencertserver.iq.tests/Features/DeviceAttestation.feature)
qualifies advertisement, offer gating, invalid proofs and replay rejection using disposable software
fixtures; it does not qualify hardware provenance.

To enable device attestation, replace the `IAttestationTrustProvider` singleton registered by
`AddAcmeServer`:

```csharp
services.AddSingleton<OpenCertServer.Acme.Abstractions.Services.IAttestationTrustProvider>(
    _ => new OpenCertServer.Acme.Server.Services.StaticAttestationTrustProvider(
        new X509Certificate2Collection { /* Apple Attestation CA, Intel ME, AMD PSP, … */ }));
```

- Backends and the `IAttestationProvider` / `IAttestationTrustProvider` contract:
   [opencertserver.attestation/README.md](../src/opencertserver.attestation/README.md).

See [Implemented standards → device attestation](standards.md#device-attestation-device-attest-01)
and `tests/…/Features/device-attest-*.feature`.

---

## MCP server

The `opencertserver.mcp` project exposes the CA over a Model Context Protocol stdio transport for AI
agents. It registers ten tools — `get_server_metadata`, `list_certificates`, `search_certificates`,
`get_certificate`, `get_ca_certificates`, `sign_certificate`, `revoke_certificate`,
`get_revocation_status`, `check_ocsp_status`, `get_crl` — each with a name, description, JSON Schema
input, and a `ReadOnly`/`Idempotent`/`Destructive` tag. Configuration is read from
`MCP_`-prefixed environment variables.

See [opencertserver.mcp/README.md](../src/opencertserver.mcp/README.md) and
`tests/opencertserver.mcp.tests`.

---

## Authentication

OpenCertServer authenticates differently per protocol:

- **EST** — mutually-authenticated TLS (client certificate) **or** a JWT bearer token, depending on
   the request scheme. `cacerts`/`csrattrs` are public; enrollment uses one of the two above. The
   `certserver` host configures client-certificate authentication via
   `CertificateAuthenticationDefaults`.
- **ACME** — RFC 8555 account-based authentication: the first request presents the account key as a
   JWS `jwk`; subsequent requests reference it via `kid`. External account binding (EAB) is
   supported via `IExternalAccountBindingService`, which verifies the EAB JWS signature.
- **CA signing endpoints** (`POST /ca/csr` and `POST /ca/{profileName}/csr`) require only an
   authenticated user under the host's authentication configuration, subject to the CA request
   validators. They do not enforce EST enrollment policies or profile-specific enrollment
   authorization. If the host's default authentication accepts EST Basic credentials, those users
   can also request certificates here in any profile. `AddCertificateAuthorityAuthorization`
   configures `/ca/revoke` only; it does not restrict signing. Hosts exposing `/ca` only for
   CRL/OCSP must explicitly block the CSR routes or map only the required responder endpoints.
- **CA revocation** (`DELETE /ca/revoke`) requires a client certificate and
   a SHA-256 signature over `serialNumber + reason` signed with the
   presented key (proof of possession), **and** enforces one of two authorization paths: the
   presented certificate must be the CA-issued certificate with that serial number (self-service),
   or the caller must hold the `ca_admin` role (administrative revocation). Register the default
   policy with `services.AddCertificateAuthorityAuthorization()`; the policy name constant is
   `RevocationAuthorizationConstants.RevocationPolicyName`.
- **YARP-accelerated ACME** — the YARP extension validates `http-01` by answering the domain's
   `/.well-known/acme-challenge/{token}` and can issue one cert per route selected by SNI.

---

## Storage backends

OpenCertServer ships a default in-memory store and an on-disk store, and defines extension points for
custom persistence:

- **ACME** — `AddAcmeInMemoryStore()` (default; good for testing) or
   `AddAcmeFileStore(configuration)` (persist accounts/orders/nonces to disk). Custom stores
   implement `IStoreAccounts`, `IStoreOrders`, and `INonceStore`.
- **CA** — certificates and CRLs are produced by the issuing profile's `ICaService`; the
   "inventory" is the in-memory issuance store used by the OCSP/CRL responders.
- **Device attestation trust** — trust roots are supplied by `IAttestationTrustProvider`; the
   default `StaticAttestationTrustProvider` starts empty and is filled with manufacturer roots at
   startup.

To bring your own store, implement the relevant `IStore*` interface and register it with
`AddAcmeServer(...).WithCertificateService(...)` / the ACME registration instead of the defaults.

---

## Related

- [Getting started](getting-started.md) — runnable enrollment samples for every protocol.
- [Implemented standards](standards.md) — every RFC and the tests that prove it.
- [Certification Practice Statement](opencertserver_cps.md) /
   [Certificate Policy](opencertserver_cp.md) — the trust model and operational rules.
- [OpenTelemetry metrics & traces](../OpenTelemetryMetricsTraces.md) — the telemetry surface.
- [SECURITY.md](../SECURITY.md) — how to report a vulnerability.
