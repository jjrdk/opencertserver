# Getting started with OpenCertServer

This guide takes you from a fresh checkout to a running certificate authority and an enrolled
certificate in five steps. Every code sample below is drawn from the OpenCertServer source and its
client libraries, so you can copy and adapt it directly.

> **What this page is.** A practical "how" — the commands and the code to run the server and use the
> clients. For *what* each protocol does and the standards OpenCertServer conforms to, read
> [Implemented standards](standards.md). For the full endpoint list, read the
> [Documentation index](documentation.md).

---

## 1. Build the projects

```sh
# macOS / Linux
./build.sh

# Windows
./build.ps1
```

This produces the `opencert` CLI, the `certserver` web app, and the NuGet packages under
`artifacts/`.

---

## 2. Run the cert server

The `certserver` application is configured entirely through command-line arguments, with environment
variables and `appsettings.json` as fall-through. There are **no required environment variables**.

### Mode 1 — Self-signed CA (fastest way to try it)

Pass a Distinguished Name and the server generates its own RSA and ECDSA root CA certificates at
startup:

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
| `--ocsp <url>` | Repeatable. OCSP responder URL embedded in issued certificates' AIA extension. |
| `--ca-issuer <url>` | Repeatable. CA Issuer URL embedded in the AIA extension of issued certificates. |
| `--authority <url>` | JWT token authority for bearer-token authentication (default: `https://identity.reimers.dk`). |

### Mode 2 — Existing CA certificates

Supply PEM-encoded certificate and private key files when you already have a root CA:

```sh
dotnet opencertserver.certserver.dll \
   --rsa    /path/to/rsa-ca.pem \
   --rsa-key /path/to/rsa-ca-key.pem \
   --ec     /path/to/ec-ca.pem \
   --ec-key  /path/to/ec-ca-key.pem \
   --port 5001 \
   --ocsp   http://pki.example.com/ocsp \
   --ca-issuer http://pki.example.com/ca/certificate
```

| Argument | Description |
|---|---|
| `--rsa <path>` | Path to the RSA CA certificate PEM file. |
| `--rsa-key <path>` | Path to the RSA CA private key PEM file (optional if the key is embedded in the cert file). |
| `--ec <path>` | Path to the ECDSA CA certificate PEM file. |
| `--ec-key <path>` | Path to the ECDSA CA private key PEM file (optional if the key is embedded in the cert file). |

At least one of `--dn` or `--rsa`/`--ec` must be supplied; the server throws on startup otherwise.
The TLS listener is pinned to TLS 1.2/1.3 because EST (RFC 7030) requires TLS ≥ 1.1.

For a containerized or Kubernetes deployment, see [Docker](../Docker.md). The equivalent Docker
smoke test is:

```sh
curl -k https://localhost:8084/.well-known/est/cacerts
```

---

## 3. ACME server configuration

ACME behaviour is driven by the `AcmeServer` section of `appsettings.json`:

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
    "TrustedOrigins": [ "https://app.example.com" ]
  }
}
```

The server registers a background `HostedValidationService` that processes pending `http-01` /
`dns-01` challenge validations asynchronously, and (optionally) an issuance worker.

---

## 4. Use the `opencert` CLI

The `opencert` tool covers key generation, CSR creation, local signing, and EST enrollment. It is
built as an executable named `opencert` (project `opencertserver.cli`), with sub-commands
`generate-keys`, `create-csr`, `create-csr-from-keys`, `sign-csr`, `est-enroll`, `est-reenroll`,
`est-server-certificates`, and `print-cert`.

```sh
# Inspect a certificate (PEM or DER)
opencert print-cert --cert test.crt

# Generate a key pair (RSA 3072 by default, or ECDSA nistP256/nistP384/nistP521)
opencert generate-keys --algorithm rsa --out keys/my-key

# Create a CSR from an existing key pair (non-interactive).
# Subject / usage options match the CLI: --C --ST --L --O --OU --CN --E --san
# plus --key-usage --eku --basic-ca --rsa-padding.
opencert create-csr-from-keys \
    --private-key ca.key --public-key ca.crt --out server.csr.pem \
    --C US --ST CA --L "San Francisco" \
    --O "Example Corp" --OU "Security" --CN server.example.com \
    --E admin@example.com --san "server.example.com,alt.example.com" \
    --key-usage "digitalSignature,keyEncipherment" \
    --eku "serverAuth,clientAuth"

# Sign a CSR with a local CA key/cert pair (offline workflow, default one-year validity)
opencert sign-csr --csr request.csr.pem --ca-cert ca.crt --ca-key ca.key --out issued.pem

# Enroll a certificate via EST (JWT bearer auth).
# est-enroll takes the same subject / SAN options as create-csr-from-keys,
# plus --client-cert / --auth / --est-ca / --ta-mode for EST-side configuration.
opencert est-enroll \
    --url https://pki.example.com \
    --private-key private.pem \
    --C US --O "Example Corp" --CN client.example.com \
    --san client.example.com \
    --auth "Bearer <token>" \
    --out enrolled.pem

# Re-enroll an existing certificate pair via EST (mTLS or JWT auth)
opencert est-reenroll \
    --url         https://pki.example.com \
    --private-key private.pem \
    --cert        current-cert.pem \
    --out         renewed.pem

# Fetch the EST CA trust anchors (RFC 7030 /cacerts)
opencert est-server-certificates --url https://pki.example.com
```

For mTLS enrollment pass a client certificate file with `--client-cert`; for JWT bearer
authentication pass the Bearer string with `--auth`. The two EST trust-anchor behaviours are
selected with `--ta-mode { ImplicitOnly | ExplicitThenImplicit | RejectBootstrapTrust |
AcceptBootstrapTrust }` (see `EstClientOptions.cs`). The exact flag surface is exercised by the
BDD scenarios in `tests/opencertserver.cli.tests`
(`GenerateKeys`, `CreateCsrFromKeys`, `CreateCsrNonInteractive`, `OpenCertServerCli`).

---

## 5. Use the client libraries from code

### EST client

`opencertserver.est.client` (`OpenCertServer.Est.Client`) enrolls and re-enrolls certificates over
EST. The constructor requires an HTTPS host and returns a `(string? error, X509Certificate2Collection? certs)`
tuple.

```csharp
using OpenCertServer.Est.Client;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
var estHost = new Uri("https://pki.example.com");

// Trust anchors for the EST CA. Implicit trust uses the OS store; explicit trust pins specific roots
// (RFC 7030 §3.1). Bootstrap helpers (AcceptBootstrapTrust / RejectBootstrapTrust) let you decide at
// runtime whether to trust CA material fetched from the server.
var options = new EstClientOptions
{
    TrustAnchorMode  = EstTrustAnchorMode.ImplicitOnly, // or ExplicitThenImplicit
    RevocationMode   = X509RevocationMode.NoCheck,
    RevocationFlag   = X509RevocationFlag.ExcludeRoot,
};

using var key = RSA.Create(); // or ECDSA.Create(); the generic <TAlgorithm> is RSA or ECDsa

using var estClient = new EstClient(estHost, options, profileName: "rsa");

// 1. Bootstrap trust from the server's /cacerts, then decide.
var cacerts = await estClient.ServerCertificates();

// 2. Enroll a brand-new certificate.
// Enroll returns a (error, collection) tuple; the collection is the leaf
// followed by the issuer chain in certificate order, or null on failure.
var (error, certs) = await estClient.Enroll(
     distinguishedName: new X500DistinguishedName("CN=client.example.com"),
     key:              key,
     usageFlags:       X509KeyUsageFlags.DigitalSignature);

if (error is null && certs is not null)
{
     var leaf = certs[0];   // leaf is first; the rest is the issuer chain

     // 3. Re-enroll (renew) the leaf, preserving its subject and key usage.
     var (renewedError, renewed) = await estClient.ReEnroll(key, leaf);
}
```

The CLI wraps exactly these calls; `est-enroll` constructs `estClient.Enroll(...)` and writes the
returned chain to `--out`, while `est-reenroll` calls `estClient.ReEnroll(...)`.

### ACME client (ASP.NET Core, auto-renewal)

`opencertserver.acme.aspNetClient` provisions and renews a site's own certificate against an ACME
server (Let's Encrypt by default), serves the certificate to Kestrel by SNI, and serves `http-01`
challenge tokens. Register it and call `UseAcmeClient()`:

```csharp
using OpenCertServer.Acme.AspNetClient;
using OpenCertServer.Acme.AspNetClient.Certes;

var options = new LetsEncryptOptions
{
   Email = "you@example.com",
   UseStaging = false,                 // true => Let's Encrypt staging server
   AccountPassword = "change-me",
   TimeUntilExpiryBeforeRenewal = TimeSpan.FromDays(30),
   CertificateSigningRequest = new CsrInfo
      {
       CountryName = "US",
       Organization = "Example Corp",
       State = "CA",
       Locality = "San Francisco"
      }
};

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddHttpClient();   // the ACME client factory needs an HttpClient

builder.Services.AddAcmeClient(options)
      .AddAcmeFileCertificatePersistence("acme-certificates")   // survives restarts
      .AddAcmeFileChallengePersistence("acme-challenges");

var app = builder.Build();
app.UseAcmeClient();                // mints/renews the cert and installs the http-01 challenge middleware
app.Run();
```

The lower-level flow is `PlaceOrder` → `FinalizeOrder`, which is what the renewal service calls and
what the conformance tests drive:

```csharp
// IAcmeClient
var placed = await client.PlaceOrder(ChallengeType.Http01, ["localhost"]);
var (cert, keyPem, collection) = await client.FinalizeOrder(placed, "change-me");
// cert        : the issued leaf
// keyPem      : the PEM private key that signed the CSR
// collection : leaf followed by the issuer chain (persist this, not just the leaf)
```

By default the renewal engine answers `http-01` in-process (the
`AcmeChallengeApprovalMiddleware` serves `/.well-known/acme-challenge/{token}`). To answer `dns-01`
instead, set `ChallengeType` on the options and register a provider that publishes the
`_acme-challenge` TXT records into your DNS zone:

```csharp
using OpenCertServer.Acme.AspNetClient.Certes;

var options = new LetsEncryptOptions
{
    // ...
    ChallengeType = ChallengeType.Dns01   // publish _acme-challenge TXT records via a provider
};

builder.Services.AddAcmeClient(options, myDnsProviderFactory)   // Cloudflare / Route53 / Azure DNS / your own
        .AddAcmeFileCertificatePersistence("acme-certificates");
```

The provider implements `IDnsChallengeProvider` (`PlaceChallengesAsync` writes the TXT records
before the ACME server validates and `RemoveChallengesAsync` clears them afterwards). When no
provider is registered the no-op `NullDnsChallengeProvider` is used, so the `http-01` path is
unaffected unless `ChallengeType.Dns01` is selected.

Persistence strategies are pluggable: `AddAcmeFileCertificatePersistence` /
`AddAcmeFileChallengePersistence` for disk, `AddAcmeInMemoryCertificatesPersistence` /
`AddAcmeMemoryChallengePersistence` for testing, or `AddAcmeCertificatePersistence(...)` /
`AddAcmeChallengePersistence(...)` with your own delegates. `AddAcmeCertificateStorePersistence`
stores the leaf **with** its private key in the OS X.509 store.

### ACME client per YARP route

`opencertserver.acme.yarp` provisions one ACME certificate per YARP `RouteConfig` on a single HTTPS
listener, with SNI selecting the right leaf and each route renewed independently. Its full sample
(live in the source) is in
[`src/opencertserver.acme.yarp/README.md`](../src/opencertserver.acme.yarp/README.md); the shape is:

```csharp
builder.Services.AddAcmeClient(options)
      .AddAcmeFileCertificatePersistence("acme-certificates")
      .AddAcmeFileChallengePersistence("acme-challenges");

builder.Services.AddAcmeProxy()
      .WithAcmeRouteFilter()
      .LoadFromMemory(routes, clusters);       // each `acme`-tagged RouteConfig = one order

app.UseAcmeClient();
app.MapReverseProxy();                          // YARP 2.x registers the proxy as an endpoint
app.Run();
```

---

## 6. Embedding the server in your own app

The EST, ACME, and CA server pieces are independent extensions. The minimum to run a self-signed CA
with EST + ACME + the CA endpoints mirrors `opencertserver.certserver/Program.cs`:

```csharp
// 1. Store (in-memory for dev; swap for a persistent implementation in production)
services.AddInMemoryCertificateStore();

// 2a. Self-signed CA — generates RSA + ECDSA roots at startup
services.AddSelfSignedCertificateAuthority(
    new X500DistinguishedName("CN=My Internal CA"),
    ocspUrls:      ["https://pki.example.com/ca/ocsp"],
    crlUrls:       [],
    caIssuersUrls: ["https://pki.example.com/ca/certificate"],
    certificateValidity: TimeSpan.FromDays(90));

// 2b. — OR — bring your own CA certificates
// services.AddCertificateAuthority(new CaConfiguration(
//     new CaProfileSet("default", rsaProfile, ecdsaProfile),
//     ocspUrls, crlUrls, caIssuersUrls));

// 3. EST server (supply a CSR template loader implementation for RFC 9908 /csrattrs)
services.AddEstServer<MyCsrTemplateLoader>();

// 4. ACME server + store
services.AddAcmeServer(configuration)
        .AddAcmeInMemoryStore();           // or .AddAcmeFileStore(configuration)

// 5. Authentication — both certificate (mTLS) and JWT bearer are supported
services.AddAuthentication()
        .AddJwtBearer()
        .AddCertificate()
        .AddCertificateCache(options =>
        {
          options.CacheSize = 1024;
          options.CacheEntryExpiration = TimeSpan.FromMinutes(5);
        });
```

```csharp
app.UseHttpsRedirection()
    .UseForwardedHeaders()
    .UseAcmeServer()          // maps ACME endpoints
    .UseEstServer()           // maps EST endpoints + auth/authorization middleware
    .UseCertificateAuthorityServer(); // maps /ca/* (CSR, OCSP, CRL, revocation, inventory)
```

**Endpoint summary**

| Protocol | Path | Method | Auth |
|---|---|---|---|
| EST | `/.well-known/est/cacerts` | GET | No (allow-anon, cached 30d) |
| EST | `/.well-known/est/csrattrs` | GET | No (authorization optional — default anon) |
| EST | `/.well-known/est/simpleenroll` | POST | Yes (JWT or mTLS) |
| EST | `/.well-known/est/simplereenroll` | POST | Yes (JWT or mTLS) |
| EST | `/.well-known/est/serverkeygen` | POST | Yes (JWT or mTLS) |
| EST | `/.well-known/est/{profile}/*` | — | As the matching base endpoint above |
| ACME | `/directory` | GET | No |
| ACME | `/new-nonce` | HEAD/GET | No |
| ACME | `/new-account` | POST | JWS |
| ACME | `/new-order` | POST | JWS |
| ACME | `/order/{id}/finalize` | POST | JWS |
| ACME | `/order/{id}/certificate` | POST | JWS |
| CA | `/ca/csr` | POST | Yes |
| CA | `/ca/inventory` | GET | No |
| CA | `/ca/revoke` | DELETE | Yes |
| CA | `/ca/crl`, `/ca/{profile}/crl` | GET | No |
| CA | `/ca/ocsp`, `/ca/ocsp/{requestEncoded}` | POST/GET | No |
| CA | `/ca/certificate` | GET | No |

See the [Documentation index](documentation.md) for request/response detail and
[Implemented standards](standards.md) for the behaviour each endpoint guarantees.

---

## 7. Device attestation (`device-attest-01`)

OpenCertServer adds a `device-attest-01` ACME challenge type (see
[`ChallengeTypes`](../src/CertesSlim/Acme/Resource/ChallengeTypes.cs)) so a certificate can be
issued to a hardware-backed device rather than a domain. Enablement is two service registrations:

```csharp
// The ACME server already registers an empty trust provider and the device-attest validator:
//   services.AddSingleton<IAttestationTrustProvider>(new StaticAttestationTrustProvider([]));
//   services.AddScoped<IValidateDeviceAttestChallenges, DeviceAttestChallengeValidator>();

// Supply your manufacturer trust roots (e.g. Apple Attestation CA, Intel ME, AMD PSP):
services.AddSingleton<OpenCertServer.Acme.Abstractions.Services.IAttestationTrustProvider>(
    _ => new OpenCertServer.Acme.Server.Services.StaticAttestationTrustProvider(
        new X509Certificate2Collection { /* manufacturer root CAs */ }));
```

The validator performs three checks (mirrored by
`tests/opencertserver.certserver.tests/Features/device-attest-validation.feature`): **chain
verification** (the submitted AIK certificate must chain to an injected trusted root — a self-signed
AIK is rejected), **proof verification** (a TPM proof with the correct magic value/attestation type
matching the challenge nonce — garbage or wrong-magic fails), and **anti-replay** (a consumed nonce is
rejected on second use with `replay_nonce`). The directory advertises the type under
`meta.challengeTypesWithAdditionalContent`.

For the hardware attestation providers themselves (AMD SEV-SNP, Intel SGX, Apple Secure Element),
see [Implemented standards → Device attestation](standards.md#device-attestation-device-attest-01).

---

## 8. MCP server (expose the CA to an AI agent)

`opencertserver.mcp` runs a stdio Model Context Protocol server that exposes ten CA tools
(`get_server_metadata`, `list_certificates`, `search_certificates`, `get_certificate`,
`get_ca_certificates`, `sign_certificate`, `revoke_certificate`, `get_revocation_status`,
`check_ocsp_status`, `get_crl`). Build and run it as the entry point of
`opencertserver.mcp/Program.cs`; it reads JSON-RPC from stdin and writes to stdout, and takes its
CA configuration from the `MCP_`-prefixed environment variables (`CA_DN`, …). See
[`src/opencertserver.mcp/README.md`](../src/opencertserver.mcp/README.md) and the coverage in
`tests/opencertserver.mcp.tests`.

From an MCP client, the tools behave like this — for example, list certificates and check one's
status:

```csharp
// Using the official ModelContextProtocol .NET client (stdio transport)
using ModelContextProtocol.Server; // client side: the client SDK / your MCP host

// List every certificate the CA has issued
var listed = await client.CallToolAsync("list_certificates",
     JsonSerializer.SerializeToNode(new { /* no required parameters */ }));

// Check the revocation status of a single subject
var status = await client.CallToolAsync("check_ocsp_status",
     JsonSerializer.SerializeToNode(new { serialNumber = "0A1B2C3D" }));
// ReadOnly tools (list_/get_/check_/search_) are marked Idempotent; sign_certificate and
// revoke_certificate are the two Destructive tools and are the only ones a well-formed client
// should confirm before calling.
```

Each tool has a unique name, a non-empty description, and a JSON Schema input schema, and an
unknown tool name returns a failed result with error code
`McpErrorCode.ToolNotFound` (the JSON-RPC "method not found" code, `-32601`) — all asserted by
`McpServerTools.feature` and the per-tool features in `tests/opencertserver.mcp.tests`.

---

## 9. Operational tooling

* **Telemetry.** EST, ACME, OCSP, CRL, and CA operations emit OpenTelemetry
  counters/successes/failures/durations under the `opencertserver.*` namespace. See
  [OpenTelemetry metrics & traces](../OpenTelemetryMetricsTraces.md).
* **TPM-backed CA keys.** `opencertserver.tpm` / `opencertserver.tss.net` can provision the CA
  private key *inside* a TPM so it never leaves the hardware. See [Implemented standards → TPM](standards.md#tpm-backed-ca-keys).
* **Lambda / serverless.** `opencertserver.lambda2` is the AWS Lambda entry point.
* **Web UI.** The `web` Angular project is the management frontend; see `web/README.md`.

---

## Next steps

* [Implemented standards](standards.md) — every RFC, what OpenCertServer does, and the tests that prove it.
* [Documentation index](documentation.md) — the endpoint reference.
* [Certification Practice Statement](opencertserver_cps.md) and
   [Certificate Policy](opencertserver_cp.md) — the trust model and operational rules.
