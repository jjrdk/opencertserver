# opencertserver.acme.remote

The ACME side of separating the ACME server from the CA. It is a
`IIssueCertificates` implementation — `RemoteIssuer` — that delegates every ACME order
to a backing certificate authority over a trusted HTTPS connection, through the
[`CaClient`](../opencertserver.ca.client/README.md). A host that references this
project (instead of the CA core) issues through the CA and hosts no CA key.

## What runs here

- **`RemoteIssuer`** — the `IIssueCertificates` that ACME's `DefaultOrderService`
  consumes. It signs each order's CSR through `CaClient.SignCsr` and returns the
  signed chain as a PEM. A CA rejection is surfaced as an `AcmeError` (`Type:
  "multiple"`, the rejection reasons joined by commas) so the ACME order fails cleanly
  instead of throwing. The requestor identity is **not** forwarded: the backing CA
  authenticates this process over the trusted connection (mTLS or bearer), and the
  delegated scope, when any, comes from the client configuration.
- **`AcmeRemoteServiceCollectionExtensions.AddAcmeRemoteCa`** — registers the backing-CA
  `CaClient` (and, for ACME revocation, the `ICertificateAuthority` it exposes as a
  `RemoteCertificateAuthority`) plus the `RemoteIssuer`. This is the wiring selected by
  `AcmeServer:Issuer=remote` in the
  [`opencertserver.certserver`](../opencertserver.certserver/README.md) monolith, and
  the issuer the standalone [`opencertserver.acme`](../opencertserver.acme/README.md)
  host always uses.

## Usage

Select the remote issuer by reading the `Ca` configuration section:

```csharp
// certserver: AcmeServer:Issuer=remote routes ACME issuance through a backing CA.
services.AddAcmeRemoteCa(configuration);          // reads CaClientOptions from the "Ca" section

// or with explicit options:
services.AddAcmeRemoteCa(new CaClientOptions
{
    BaseUrl = new Uri("https://ca.example.com"),
    Profile = "rsa",
    BearerToken = "...",
});
```

## Configuration

`AddAcmeRemoteCa(IConfiguration)` reads the same `Ca` section as the CA client —
`Ca:RemoteUrl` (required, HTTPS), `Ca:Profile`, `Ca:DelegatedScope`,
`Ca:BearerToken` / `Ca:ClientCert`, and the trust-pinning options. See
[`opencertserver.ca.client`](../opencertserver.ca.client/README.md) for the full list.

## Dependencies

- `opencertserver.acme.server` — the ACME server that consumes `IIssueCertificates`.
- `opencertserver.ca.client` — the backing-CA HTTP client and `ICertificateAuthority`.

This project is a library, not an application.
