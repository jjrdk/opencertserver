# opencertserver.ca.client

The outbound half of the "trusted connection" to a backing certificate authority.
It is the HTTP client that a remote ACME issuer, a registration authority (RA), or a
standalone SCEP host uses to sign CSRs and revoke certificates **without hosting a CA
key**. Registering this client turns a host's `ICertificateAuthority` into a
[`RemoteCertificateAuthority`](RemoteCertificateAuthority.cs) — the same type the
in-process CA core implements — so `acme.server`, `est.server` and `scep.server`
consume it unchanged and swap the local authority for a remote one by wiring alone.

The CA stays authoritative for scope and identity: this client never makes a local
scope decision, and the CA's second, authoritative check is the one that matters
(see [`docs/architecture-separation.md`](../../docs/architecture-separation.md)).

## What runs here

- **`CaClient`** — the HTTP client. `SignCsr` submits a PKCS#10 request and returns
  the signed chain (`SignCertificateResponse.Success`) or a typed rejection
  (`SignCertificateResponse.Error`); `Revoke` signs the revocation proof-of-possession
  with the revoke identity and calls `DELETE /ca/revoke`; `GetRootCertificates`,
  `GetPublishedCertificates`, `GetProfiles` and `GetRevocationList` fetch the CA's
  published material over the wire.
- **`CaClientOptions`** — the `Ca` configuration section, read by hand (no `Bind`) so
  the client stays AOT-safe and trimmable. A non-HTTPS `BaseUrl` is rejected.
- **`CaClientServiceCollectionExtensions.AddCaClient`** — registers `CaClient` and
  exposes `RemoteCertificateAuthority` as the host's `ICertificateAuthority`.
- **`RemoteCertificateAuthority`** — the `ICertificateAuthority` that delegates every
  operation to `CaClient`. A remote SCEP/EST renewal carries the previous certificate
  as the `X-Reenrolling-From` header so the CA can supersede-revoke it.

The "trusted connection" is enforced end-to-end: pin the CA's trust anchor
(`Ca:Trust`, a PEM bundle) into the outbound TLS handler so a server certificate that
does not chain to a pinned anchor is rejected even when the system store would trust
it (`X509ChainTrustMode.CustomRootTrust`).

## Configuration (`Ca` section)

| Key | Required | Meaning |
|---|---|---|
| `Ca:RemoteUrl` (or `Ca:BaseUrl`) | yes | Absolute HTTPS URL of the backing CA. |
| `Ca:Profile` | no | Issuance profile name; empty uses the CA's default. |
| `Ca:Profiles` | no | Comma-separated delegated profile set; empty means **all** profiles the CA supports. Refreshable via `CaClient.GetProfiles`. |
| `Ca:DelegatedScope` | no | Delegated DNS scope sent as the `X-Delegated-Subject` header; the CA enforces it. |
| `Ca:BearerToken` | no | Shared secret / bearer for the trusted connection. |
| `Ca:Trust` | no | Path to a PEM bundle of CA trust anchors pinned into the outbound TLS handler. |
| `Ca:ClientCert` + `Ca:ClientCertPassword` | no | PFX client certificate for mTLS and for signing the revocation proof-of-possession. |
| `Ca:RootsPath` | no | Root-certificate path relative to the base URL (default `cacerts`). |
| `Ca:RevocationListPath` | no | Revocation-list path relative to the base URL (default `ca/crl`). |

As environment variables these read as `Ca__RemoteUrl`, `Ca__ClientCert`, and so on.

## Usage

Register the client from configuration before building the service provider; the host
then issues and revokes through the backing CA instead of an in-process CA:

```csharp
// A remote ACME / RA / SCEP host registers its backing CA exactly this way.
services.AddCaClient(CaClientOptions.FromConfiguration(configuration));
// or with explicit options:
services.AddCaClient(new CaClientOptions
{
    BaseUrl = new Uri("https://ca.example.com"),
    Profile = "rsa",
    BearerToken = "...",
    TrustCertPath = "/path/to/ca-bundle.pem",
    ClientCertPath = "/path/to/ra-client.pfx",
});
```

For a pure-library use, build a `CaClient` over an `HttpClient` and call it directly:

```csharp
using var client = new CaClient(httpClient, new CaClientOptions { BaseUrl = caUrl }, logger);
var response = await client.SignCsr(csrPem, profile: "rsa");
```

## OpenTelemetry

`CaClient` publishes counters under the `opencertserver.ca.client` meter with a
`result` tag (`success`, `rejected`, `not_found`, `revoked`, `error`), so operators
can distinguish a CA rejection from a transport error. The host subscribes to this
meter only when OTLP export is enabled; it is inert otherwise.

## Dependencies

- `opencertserver.ca.protocol` — the shared RA/CA wire contract (`RaProtocol` paths and
  headers).
- `opencertserver.ca.utils` — `ICertificateAuthority`, `SignCertificateResponse` and
  PKI helpers.
- `Microsoft.Extensions.Http`, `Microsoft.Extensions.Configuration`,
  `Microsoft.Extensions.DependencyInjection.Abstractions`,
  `Microsoft.Extensions.Logging.Abstractions`.

This project is a library, not an application. The hosts that run it are
[`opencertserver.acme`](../opencertserver.acme/README.md),
[`opencertserver.ra.server`](../opencertserver.ra.server/README.md) and
[`opencertserver.scep`](../opencertserver.scep/README.md).
