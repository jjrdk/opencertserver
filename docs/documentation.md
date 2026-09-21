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
| Wire device attestation | [opencertserver.attestation/README.md](../src/opencertserver.attestation/README.md) |

This page keeps the concrete HTTP surface — methods, paths, content types, and authentication — so
you don't have to read handler source. The reasoning and the RFC citations for each protocol live in
[Implemented standards](standards.md); runnable code that exercises them is in
[Getting started](getting-started.md).

---

## Certificate Authority (CA) endpoints

The CA endpoints are mounted by the `ca.server` handlers under `/ca` in the `certserver` host. They
are secured by TLS client-certificate authentication (`certserver` runs `UseHttps` with
`UseHttpsClientCertificate` and
`CertificateAuthenticationDefaults.AuthenticationScheme` = `"Certificate"`).

### GET /ca/crl

- Description: Retrieve the current Certificate Revocation List for the CA (or a profile).
- Paths: `/ca/crl` and `/ca/{profile}/crl`.
- Response: `application/pkix-crl` (DER). Cached for 12 hours.

### DELETE /ca/revoke

- Description: Revoke a certificate.
- Query parameters:
   - `sn` (base64 string, required): the serial number of the certificate to revoke.
   - `reason` (string, required): the revocation reason (e.g. `keyCompromise`,
     `cessationOfOperation`).
   - `signature` (base64 string, required): a SHA-256 signature of `serialNumber + reason` produced
     with the private key of the certificate being revoked (proof of possession). Only the key
     holder or the CA itself can revoke the target.
- Response: `200` on success.

### GET /ca/inventory

- Description: Retrieve the inventory of issued certificates.
- Response: a JSON array of issued certificates and their details.

### GET /ca/certificate

- Description: Retrieve a specific issued certificate, or the CA certificate(s).
- Query parameters:
   - `id` (hex string, optional, multiple allowed): the serial numbers to retrieve.
   - `thumbprint` (string, optional, multiple allowed): the thumbprints to retrieve.
- Response: the requested certificate(s) in PEM.

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

### GET /.well-known/est/cacerts

- Description: Retrieve the CA certificate chain.
- Response: `application/pkcs7-certificates-path` (cached 30 days). No authentication required.

### GET /.well-known/est/csrattrs

- Description: Return a `CsrAttributesResponse` ([RFC 9908](https://www.rfc-editor.org/rfc/rfc9908))
   that tells the client the CSR template, key usage, and subject to fill in.
- Response: `application/csrattrs`.

### POST /.well-known/est/simpleenroll

- Description: Enroll a new certificate.
- Request body: a PKCS#10 CSR in PEM or DER (`Content-Type: application/pkcs10` or
   `application/x-pkcs10`).
- Authentication: a client certificate or a JWT bearer token.
- Response: the issued leaf+chain, with the format negotiated from the `Accept` header —
   `application/pkix-cert` (leaf+chain DER), `application/pem-certificate-chain` (PEM), or
   `application/pkcs7-mime` (wrapped).

### POST /.well-known/est/simplereenroll

- Description: Re-enroll using an existing certificate or the server-key-generated key.
- Authentication: the existing client certificate (mTLS) or a JWT.
- Response: as `simpleenroll`.

### POST /.well-known/est/serverkeygen

- Description: The server generates the key pair on the client's behalf and enrolls the certificate.
- Authentication: a client certificate or a JWT.
- Response: a `multipart/mixed` bundle containing the issued certificate **and** the generated
   private key in PEM.

Per-profile variants of the above (`{profile}/cacerts`, `{profile}/csrattrs`, …) let one server act
as multiple logical CAs. For runnable client code (including `ServerKeyGeneration`) see
[Getting started → EST](getting-started.md#enroll-a-certificate-via-est-jwt-bearer-auth).

> See [Implemented standards → EST](standards.md#est--rfc-7030) for the full RFC 7030 + RFC 8951 +
> RFC 9908 behaviour and the `EstConformance.feature` scenarios.

---

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
  validator.


### POST /order/{orderId}/finalize

- Description: Submit a CSR to finalize the order once all authorizations are `valid`.
- Request body: a base64url-encoded PKCS#10 CSR.
- Response: the order with a `certificate` URL.

### POST /order/{orderId}/certificate

- Description: Retrieve the issued certificate for a completed order (POST-as-GET).
- Response: `application/pem-certificate-chain` (or `application/pkix-cert`).

### POST /revoke-cert

- Description: Revoke a certificate, authenticated by the holder's key.
- Request body: `{ certificate, reason? }`.

For challenge types, CAA enforcement, and the `device-attest-01` validator, see
[Implemented standards → ACME / CAA / device attestation](standards.md#acme--rfc-8555).

---

## Device attestation (device-attest-01) challenge

`device-attest-01` is an ACME challenge type that replaces domain control with hardware identity.
The device submits an Attestation Identity Key (AIK) certificate and a TPM/SE proof inside
`challenge.extraData`; the validator (1) verifies the AIK chains to a configured root, (2) verifies
the proof magic/type/nonce-bind match the challenge, and (3) rejects a replayed nonce with
`replay_nonce`.

- Advertise it on the ACME directory; enable it with `UseAcmeServer()`.
- Supply real trust roots by replacing the `IAttestationTrustProvider` singleton with one that
   returns your manufacturer root CAs (Apple Attestation CA, Intel ME, AMD PSP, …).
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
- **CA endpoints** (`/ca/*`) — a client certificate over TLS. Revocation additionally requires a
   signature over `serialNumber + reason` from the target key (proof of possession).
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
   "inventory" is the in-memory issuance store used by `GET /ca/inventory`,
   `GET /ca/certificate`, and the OCSP/CRL responders.
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
