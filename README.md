# Introduction

## About

OpenCertServer is a modular certificate authority platform supporting the following open standards:

- **EST** – Enrollment over Secure Transport ([RFC 7030](https://datatracker.ietf.org/doc/html/rfc7030))
- **ACME** – Automatic Certificate Management Environment ([RFC 8555](https://www.rfc-editor.org/rfc/rfc8555))
- **OCSP** – Online Certificate Status Protocol ([RFC 6960](https://datatracker.ietf.org/doc/html/rfc6960))
- **CRL** – Certificate Revocation Lists ([RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280))

The ACME implementation is derived from the [PKISharp ACME Server](https://github.com/PKISharp/ACME-Server) and [FluffySpoon EncryptWeMust](https://github.com/ffMathy/FluffySpoon.AspNet.EncryptWeMust) projects, both MIT licensed.

## License

The project is licensed under the [MIT license](LICENSE).

---

## Building the Project

Run the appropriate build script from the repository root to compile and package all components:

```sh
# macOS / Linux
./build.sh

# Windows
./build.ps1
```

This produces NuGet packages and a self-contained server publish under `artifacts/`.

---

## Running the Certificate Server

The `certserver` application is configured entirely through **command-line arguments**, with optional fall-through to environment variables and `appsettings.json`. There are no required environment variables – all runtime configuration is passed directly on the command line.

### Mode 1 – Self-signed CA (quickstart)

Pass a Distinguished Name and let the server generate its own RSA and ECDSA root CA certificates at startup:

```sh
dotnet opencertserver.certserver.dll \
  --dn "CN=My Internal CA" \
  --port 5001 \
  --ocsp http://localhost:5001/ca/ocsp \
  --ca-issuer http://localhost:5001/ca/certificate
```

| Argument | Description |
|---|---|
| `--dn <name>` | Distinguished Name for the self-signed CA root. A `CN=` prefix is added automatically if omitted. |
| `--port <n>` | HTTPS port to listen on (default: `5001`). |
| `--ocsp <url>` | Repeatable. OCSP responder URL embedded in issued certificates. |
| `--ca-issuer <url>` | Repeatable. CA Issuers URL embedded in issued certificates' AIA extension. |
| `--authority <url>` | JWT token authority for bearer-token authentication (default: `https://identity.reimers.dk`). |

### Mode 2 – Existing CA certificates

Supply PEM-encoded certificate and private key files when you already have a root CA:

```sh
dotnet opencertserver.certserver.dll \
  --rsa   /path/to/rsa-ca.pem \
  --rsa-key /path/to/rsa-ca-key.pem \
  --ec    /path/to/ec-ca.pem \
  --ec-key  /path/to/ec-ca-key.pem \
  --port 5001 \
  --ocsp http://pki.example.com/ocsp \
  --ca-issuer http://pki.example.com/ca/certificate
```

| Argument | Description |
|---|---|
| `--rsa <path>` | Path to the RSA CA certificate PEM file. |
| `--rsa-key <path>` | Path to the RSA CA private key PEM file (optional if key is embedded in the cert file). |
| `--ec <path>` | Path to the ECDSA CA certificate PEM file. |
| `--ec-key <path>` | Path to the ECDSA CA private key PEM file (optional if key is embedded in the cert file). |

At least one of `--dn` or `--rsa`/`--ec` must be supplied; the server will throw on startup otherwise.

### ACME configuration (`appsettings.json`)

ACME server behaviour is driven by the `AcmeServer` section in `appsettings.json`:

```json
{
  "AcmeServer": {
    "WebsiteUrl": "https://pki.example.com",
    "TOS": {
      "RequireAgreement": false,
      "Url": "https://pki.example.com/tos",
      "LastUpdate": "2024-01-01T00:00:00Z"
    },
    "HostedWorkers": {
      "EnableValidationService": true,
      "EnableIssuanceService": false,
      "ValidationCheckInterval": 1,
      "IssuanceCheckInterval": 1
    }
  },
  "Cors": {
    "TrustedOrigins": [
      "https://app.example.com"
    ]
  }
}
```

---

## Integrating into a Custom ASP.NET Core Application

The server components are available as NuGet packages and can be embedded in any ASP.NET Core host.

### Service registration

```csharp
// 1. Certificate store (in-memory; swap for a persistent implementation in production)
services.AddInMemoryCertificateStore();

// 2a. Self-signed CA (generates RSA + ECDSA roots at startup)
services.AddSelfSignedCertificateAuthority(
    new X500DistinguishedName("CN=My Internal CA"),
    ocspUrls:      ["https://pki.example.com/ca/ocsp"],
    crlUrls:       [],
    caIssuersUrls: ["https://pki.example.com/ca/certificate"],
    certificateValidity: TimeSpan.FromDays(90));

// 2b. — OR — bring your own CA certificates
services.AddCertificateAuthority(
    new CaConfiguration(
        new CaProfileSet("default", rsaProfile, ecdsaProfile),
        ocspUrls:      ["https://pki.example.com/ca/ocsp"],
        crlUrls:       [],
        caIssuersUrls: ["https://pki.example.com/ca/certificate"]));

// 3. EST server (supply a CSR template loader implementation)
services.AddEstServer<MyCsrTemplateLoader>();

// 4. ACME server
services.AddAcmeServer(configuration)
        .AddAcmeInMemoryStore();   // or .AddAcmeFileStore(configuration)

// 5. Authentication – both certificate and JWT bearer are supported
services.AddAuthentication()
        .AddJwtBearer()
        .AddCertificate()
        .AddCertificateCache(options =>
        {
            options.CacheSize = 1024;
            options.CacheEntryExpiration = TimeSpan.FromMinutes(5);
        });
```

### Application pipeline

```csharp
app.UseHttpsRedirection()
   .UseForwardedHeaders()
   .UseAcmeServer()    // maps ACME endpoints
   .UseEstServer()     // maps EST endpoints + authentication/authorization middleware
   .UseCertificateAuthorityServer(); // maps /ca/* endpoints (CSR, OCSP, CRL, revocation)
```

### Endpoint summary

| Protocol | Path | Method | Auth required |
|---|---|---|---|
| EST | `/.well-known/est/cacerts` | GET | No |
| EST | `/.well-known/est/csrattrs` | GET | Yes |
| EST | `/.well-known/est/simpleenroll` | POST | Yes |
| EST | `/.well-known/est/simplereenroll` | POST | Yes |
| EST | `/.well-known/est/serverkeygen` | POST | Yes |
| EST | `/.well-known/est/{profile}/*` | — | As above (per-profile) |
| ACME | `/directory` | GET | No |
| ACME | `/new-nonce` | HEAD/GET | No |
| ACME | `/new-account` | POST | JWS |
| ACME | `/new-order` | POST | JWS |
| ACME | `/order/{id}/finalize` | POST | JWS |
| ACME | `/order/{id}/certificate` | POST | JWS |
| CA | `/ca/csr` | POST | Yes |
| CA | `/ca/inventory` | GET | No |
| CA | `/ca/revoke` | DELETE | Yes |
| CA | `/ca/crl` | GET | No |
| CA | `/ca/{profile}/crl` | GET | No |
| CA | `/ca/ocsp` | POST | No |
| CA | `/ca/certificate` | GET | No |

---

## RFC Compliance

### EST – RFC 7030

The EST implementation conforms to [RFC 7030](https://datatracker.ietf.org/doc/html/rfc7030):

- **`/cacerts` (Section 4.1):** Returns the current CA certificate chain in PKCS#7 `application/pkcs-mime` format. Responses are cached for 30 days.
- **`/simpleenroll` (Section 4.2):** Accepts a PKCS#10 CSR (PEM or DER) in the request body and returns the signed certificate. Both `application/pkix-cert` (DER/PKCS#7) and `application/pem-certificate-chain` responses are supported; the client selects via the `Accept` header.
- **`/simplereenroll` (Section 4.2.3):** Re-enrolls an existing certificate. The client authenticates using its current certificate (mTLS) or a JWT bearer token, and the server issues a new certificate preserving the original subject.
- **`/csrattrs` (Section 4.5):** Returns server-recommended CSR attributes as a DER-encoded `CsrAttrs` structure so clients can build conformant signing requests.
- **`/serverkeygen` (Section 4.4):** The server generates a new ECDSA key pair on behalf of the client, signs the corresponding certificate, and returns both the private key (PKCS#8) and the certificate as a `multipart/mixed` response.
- **Per-profile paths (Section 3.2.2):** All operations are available with an optional `/{profile}/` path segment, allowing a single server to act as multiple logical CAs.
- **Authentication:** Both TLS client certificate authentication and JWT bearer tokens are accepted, matching the dual-scheme requirement of the RFC.

### ACME – RFC 8555

The ACME implementation conforms to [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555):

- **Directory (`/directory`):** Advertises `newNonce`, `newAccount`, `newOrder`, `keyChange`, and optional `meta` (Terms of Service, website URL). All URLs are generated as absolute HTTPS URIs via ASP.NET Core `LinkGenerator`.
- **Replay-nonce protection:** Every mutating request must carry a fresh nonce obtained from `/new-nonce`; nonces are validated and discarded after use.
- **Account management (`/new-account`, key rollover):** Accounts are created and retrieved by public key. Key rollover is supported via the `key-change` endpoint.
- **Order lifecycle:** Clients create orders (`/new-order`), fulfil authorizations (http-01 and dns-01 challenges), finalize orders (`/order/{id}/finalize`), and download the issued certificate chain (`/order/{id}/certificate`).
- **Challenge validation:** http-01 challenges are validated over HTTP; dns-01 challenges are resolved via `DnsClient`. A background `HostedValidationService` processes pending validations asynchronously.
- **JWS request format:** All client requests use the compact JWS serialization with `alg`, `nonce`, `url`, and either `jwk` (new accounts) or `kid` (existing accounts) header parameters.
- **Certificate issuance:** After a successful finalize, the server issues a certificate chain signed by the configured CA. The certificate is returned as `application/pem-certificate-chain`.
- **Profile support:** Orders can carry an optional `profile` field that maps to a named CA profile, enabling multiple certificate types from a single ACME server.
- **Storage:** The server ships with an in-memory store (default) and a file-backed store (`AddAcmeFileStore`). Custom persistence can be provided by implementing `IStoreAccounts`, `IStoreOrders`, and `INonceStore`.

### OCSP – RFC 6960

The OCSP responder at `/ca/ocsp` conforms to [RFC 6960](https://datatracker.ietf.org/doc/html/rfc6960):

- **Request parsing:** Incoming POST requests contain a DER-encoded `OCSPRequest`. The request is decoded with `AsnReader` against the RFC 6960 ASN.1 schema.
- **Response signing:** Responses are DER-encoded `OCSPResponse` structures. The `BasicOCSPResponse` includes `ResponseData` with a `producedAt` timestamp, the responder ID, and one `SingleResponse` per certificate in the request.
- **Certificate status:** Each `SingleResponse` reports the certificate's current status (`good`, `revoked`, or `unknown`) by querying the certificate store.
- **Pluggable validation:** Zero or more `IValidateOcspRequest` services are resolved from DI and run before status lookup; a malformed request returns `OCSPResponseStatus.MalformedRequest`.
- **Content type:** Responses are returned with `Content-Type: application/ocsp-response`.
- **URL embedding:** OCSP responder URLs are embedded in the Authority Information Access (AIA) extension of every issued certificate when `--ocsp` arguments are supplied at startup.

### CRL – RFC 5280

- Certificate Revocation Lists are available at `/ca/crl` and `/ca/{profile}/crl`, returned with `Content-Type: application/pkix-crl`.
- CRL responses are cached for 12 hours.
- Revocation is performed via the authenticated `DELETE /ca/revoke` endpoint. The caller must present a valid client certificate and sign the serial number and reason code with the corresponding private key to prove possession.
- CRL Distribution Point URLs are embedded in issued certificates when `--crl` arguments are supplied.

---

## CLI Client

The `opencert` tool provides a command-line interface for key generation, CSR management, and EST enrollment. All commands follow the `opencert <command> [options]` pattern.

### `generate-keys` – Generate a key pair

```sh
opencert generate-keys \
  --algorithm rsa \          # rsa (default) or ecdsa
  --rsa-key-size 3072 \      # RSA key size in bits (minimum 2048, default 3072)
  --out keys/my-key          # writes my-key-private.pem and my-key-public.pem
```

Alternatively, specify paths explicitly:

```sh
opencert generate-keys \
  --algorithm ecdsa \
  --ecdsa-curve nistP256 \   # nistP256 (default), nistP384, or nistP521
  --private-key-out private.pem \
  --public-key-out public.pem
```

### `print-cert` – Inspect a certificate

```sh
opencert print-cert --cert path/to/cert.pem
```

Accepts PEM or DER-encoded X.509 certificates and prints the subject, issuer, validity dates, serial number, key usage, and extensions in a human-readable format.

### `create-csr` – Create a CSR from an existing private key

```sh
opencert create-csr \
  --private-key private.pem \
  --common-name "server.example.com" \
  --organization "Example Corp" \
  --country "US" \
  --san "server.example.com,alt.example.com" \
  --out server.csr.pem
```

| Option | Description |
|---|---|
| `--private-key` | PEM private key to sign the CSR (RSA or ECDSA) |
| `--common-name` | Subject common name |
| `--organization` | Subject organization |
| `--country` | Two-letter country code |
| `--state` | State or province |
| `--locality` | Locality/city |
| `--organizational-unit` | Organizational unit |
| `--email` | Email address |
| `--san` | Comma-separated Subject Alternative Names (DNS names) |
| `--key-usage` | Key usage flags |
| `--enhanced-key-usage` | Enhanced key usage OIDs |
| `--subject` | Full subject DN string (overrides individual fields) |
| `--out` | Output path (default: `csr.pem`) |

### `create-csr-from-keys` – Create a CSR from a separate key pair

```sh
opencert create-csr-from-keys \
  --private-key private.pem \
  --public-key public.pem \
  --common-name "device.example.com" \
  --out device.csr.pem
```

The private and public keys are validated to be a matching pair before the CSR is created.

### `sign-csr` – Sign a CSR with a local CA certificate

```sh
opencert sign-csr \
  --csr   request.csr.pem \
  --ca-cert ca.crt \
  --ca-key  ca.key \
  --out   issued.pem
```

Issues a certificate valid for one year, signed directly by the supplied CA key/certificate pair. Useful for offline signing workflows and testing.

### `est-enroll` – Enroll a new certificate via EST

```sh
opencert est-enroll \
  --url https://pki.example.com \
  --private-key private.pem \
  --common-name "client.example.com" \
  --san "client.example.com" \
  --auth "Bearer <token>" \
  --out  enrolled.pem
```

The command generates a CSR from the supplied private key and CSR fields, then submits it to the EST `/simpleenroll` endpoint. On success the issued certificate is written to `--out`.

For mTLS authentication, supply a PKCS#12 file that includes the private key:

```sh
opencert est-enroll \
  --url https://pki.example.com \
  --private-key private.pem \
  --client-cert client-auth.pfx \
  --common-name "client.example.com" \
  --out enrolled.pem
```

| Option | Description |
|---|---|
| `--url` | HTTPS base URL of the EST server (required) |
| `--private-key` | PEM private key used to sign the CSR |
| `--profile` | Optional EST profile name |
| `--client-cert` | PEM or PKCS#12 client certificate for mTLS authentication |
| `--auth` | `Authorization` header value, e.g. `Bearer <token>` |
| `--out` | Output path for the enrolled certificate (default: `est-cert.pem`) |

### `est-reenroll` – Re-enroll an existing certificate via EST

```sh
opencert est-reenroll \
  --url         https://pki.example.com \
  --private-key private.pem \
  --cert        current-cert.pem \
  --out         renewed.pem
```

The private key is validated against the current certificate's public key before the request is submitted. The server authenticates the client using the existing certificate (mTLS).

| Option | Description |
|---|---|
| `--url` | HTTPS base URL of the EST server (required) |
| `--private-key` | PEM private key matching the current certificate |
| `--cert` | Current certificate to re-enroll (PEM or DER) |
| `--profile` | Optional EST profile name |
| `--out` | Output path for the renewed certificate (default: `reenrolled.pem`) |

### `est-server-certificates` – Fetch the EST CA trust anchors

```sh
opencert est-server-certificates \
  --url https://pki.example.com
```

Retrieves the CA certificates from the EST `/cacerts` endpoint and prints them in PEM format. Useful for bootstrapping trust in a new environment.

---

## Reporting Issues and Bugs

When reporting issues and bugs, please provide a clear set of steps to reproduce the issue. The best way is to provide a failing test case as a pull request.

If that is not possible, please provide a set of steps which allow the bug to be reliably reproduced. These steps must also reproduce the issue on a computer that is not your own.

## Contributions

All contributions are appreciated. Please provide them as an issue with an accompanying pull request.

This is an open source project. Please respect the license terms and the fact that issues and contributions may not be handled as fast as you may wish. The best way to get your contribution adopted is to make it easy to pull into the code base.
