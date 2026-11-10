# opencertserver.est.client

The EST (Enrollment over Secure Transport, RFC 7030) client. It enrolls and
re-enrolls X.509 certificates through a running EST server over HTTPS, and reads
the server's published CA bundle and CSR attributes. This is the outbound half of
the EST flow; the server it talks to is
[`opencertserver.est.server`](../opencertserver.est.server/README.md).

## What runs here

- **`EstClient`** — the client. The constructor requires an HTTPS `Uri`; a non-HTTPS
  host throws `ArgumentException`. It drives the RFC 7030 endpoints:
  - `Enroll<TAlgorithm>(distinguishedName, key, usageFlags, ...)` — builds a
    PKCS#10 request and `POST`s it to `simpleenroll` (or `{profile}/simpleenroll`).
    Returns `(string? error, X509Certificate2Collection? certs)`: a non-null `error`
    is the server's plain-text reason, `certs` is the signed chain on success.
  - `ReEnroll<TAlgorithm>(key, certificate, ...)` — `POST`s to `simplereenroll`,
    signing with the existing certificate's key so a different renewal key can be
    attached; the SAN is carried over to the new request.
  - `ServerCertificates()` — `GET`s `cacerts` and returns the server's PKCS#7-signed
    CA bundle (RFC 7030 §3.1 bootstrap trust).
  - `GetCsrAttributes(authenticationHeader)` — `GET`s `csrattrs` (RFC 9908) and
    returns the `CertificateSigningRequestTemplate`, or an empty template on 204/404.
- **`EstClientOptions`** — trust and transport knobs (see below). Defaults favour the
  operating-system trust store.
- **`EstBootstrapTrust`** — the provisional trust material captured during bootstrap
  (source URI, certificates, SHA-256 fingerprints), accepted or rejected before any
  other exchange continues.

The client never forwards a client certificate in an HTTP header; mTLS identity is
presented on the TLS connection. It disables automatic redirects and follows only
same-origin redirects, re-validating the server identity on each hop.

## Trust model

`EstClientOptions.TrustAnchorMode` selects how the server certificate is validated:

| Mode | Meaning |
|---|---|
| `ImplicitOnly` (default) | Use the operating-system trust store. |
| `ExplicitOnly` | Validate only against `ExplicitTrustAnchors`; the system store is ignored. |
| `ExplicitThenImplicit` | Try the explicit anchors first, then fall back to the system store. |

With `ExplicitOnly` and no anchors, the client can bootstrap: a `cacerts`/`fullcmc`
response is captured into `PendingBootstrapTrust` instead of being trusted. The caller
then accepts or rejects it before continuing:

```csharp
using var client = new EstClient(
    new Uri("https://est.example.com"),
    new EstClientOptions
    {
        TrustAnchorMode = EstTrustAnchorMode.ExplicitOnly,
        AllowBootstrapCaCertsWithoutTrustedServer = true,
    });

var certs = await client.ServerCertificates();      // captures pending bootstrap trust
if (client.PendingBootstrapTrust != null)
{
    // Inspect the fingerprints, then:
    client.AcceptBootstrapTrust();                   // or client.RejectBootstrapTrust()
}
```

While bootstrap trust is pending, any other EST exchange throws — the operator must
decide on the new anchor first.

## Usage

```csharp
using OpenCertServer.Est.Client;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using var key = RSA.Create(3072);
using var estClient = new EstClient(
    new Uri("https://est.example.com"),
    new EstClientOptions { TrustAnchorMode = EstTrustAnchorMode.ImplicitOnly });

// Enroll a new certificate.
var (error, chain) = await estClient.Enroll(
    new X500DistinguishedName("CN=service.example.com"),
    key,
    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
    authenticationHeader: new("Bearer", "<token>"));

if (error is null && chain is { Count: > 0 })
{
    var leaf = chain[0];
}

// Re-enroll an existing certificate (renewal).
var (renewError, renewed) = await estClient.ReEnroll(key, existingCertificate);

// Pull the published CA bundle.
var ca = await estClient.ServerCertificates();
```

For mTLS enrollment, pass a client certificate that carries its private key via
`Enroll(..., certificate: clientCert)`.

## Dependencies

- `opencertserver.ca.utils` — X.509/PKI helpers, the PKCS#7 (`Ca.Utils.Pkcs7`) and
  CSR-template (`Ca.Utils.X509.Templates`) types the client reads from the server.

This project is a library, not an application. It is consumed by
[`opencertserver.cli`](../opencertserver.cli/README.md) for the `est-enroll`,
`est-reenroll` and `est-server-certificates` commands.
