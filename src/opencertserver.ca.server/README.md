# opencertserver.ca.server

The ASP.NET Core HTTP layer for the certificate authority. It maps the CA's request
handlers under a single `/ca` endpoint group and guards them with certificate and JWT
authentication, so the CA can be deployed as a web service and called by remote peers
(RA, ACME, SCEP hosts) over a trusted HTTPS connection.

## Endpoints

`MapCertificateAuthorityServer()` maps the following under `/ca` (call
`UseCertificateAuthorityServer()` to wire routing + endpoints):

| Method + path | Handler | Auth | Purpose |
|---|---|---|---|
| `POST /ca/csr` | `CsrHandler` | required | Sign a CSR against the default profile. |
| `POST /ca/{profileName}/csr` | `CsrHandler` | required | Sign a CSR against a named profile. |
| `GET /ca/profiles` | `ProfilesHandler` | required | List the profile names the CA supports (names only). |
| `DELETE /ca/revoke` | `RevocationHandler` | required | Revoke by serial number, with a signed proof-of-possession. |
| `GET /ca/crl` / `GET /ca/{profileName}/crl` | `CrlHandler` | — | Publish the (delta) certificate revocation list. |
| `GET /ca/published` / `GET /ca/{profileName}/published` | `PublishedCertificatesHandler` | — | Publish the full chain (root + issuing CA + intermediates). |
| `POST /ca/ocsp` / `GET /ca/ocsp/{**requestEncoded}` | `OcspHandler` | anonymous | OCSP responder (RFC 6960). |

The `X-Reenrolling-From` header on `POST /ca/csr` carries the previous certificate so the
CA can supersede-revoke it on a remote SCEP/EST renewal.

## RA bindings

The CA authorizes remote registration authorities through
[`opencertserver.ca.protocol`](../opencertserver.ca.protocol/README.md).
`AddRa` / `AddPublicRa` register the RA binding store (`IStoreRas`) that checks an RA's
delegated scope and profile set; `AddCertificateAuthorityAuthorization` wires the CA's
authentication scheme (JWT bearer or client certificate).

## Authentication

Certificate and JWT bearer. The monolith's `certserver` registers a policy scheme that
forwards to JWT for `Bearer` tokens and to certificate authentication otherwise, and
rejects certificate-authenticated results from authorizing the CA surface (EST trust
anchors must not authorize the same certificate on CA endpoints).

## Usage

```csharp
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCertificateAuthority(...)   // CA core, from opencertserver.ca
    .AddRa(builder.Configuration)               // RA binding store, if RAs are authorized
    .AddCertificateAuthorityAuthorization(policy => policy
        .AddAuthenticationSchemes(
            JwtBearerDefaults.AuthenticationScheme,
            CertificateAuthenticationDefaults.AuthenticationScheme));

var app = builder.Build();
app.UseHttpsRedirection()
    .UseAuthentication()
    .UseAuthorization()
    .UseCertificateAuthorityServer();           // = UseRouting().UseEndpoints(MapCertificateAuthorityServer())
app.Run();
```

## Dependencies

- `opencertserver.ca` — the core CA logic.
- `opencertserver.ca.protocol` — the shared RA/CA wire contract (bindings, claims, paths).
- `Microsoft.AspNetCore.Authentication.Certificate`
- `Microsoft.AspNetCore.Authentication.JwtBearer`
- `Microsoft.Extensions.DependencyInjection.Abstractions`

This is a library; the executable host is
[`opencertserver.certserver`](../opencertserver.certserver/README.md).
