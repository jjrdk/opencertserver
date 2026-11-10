# opencertserver.acme

A standalone **ACME (RFC 8555) server that hosts no CA core**. It issues and revokes
through a backing certificate authority over a trusted HTTPS connection, exactly like
the RA and SCEP hosts. This is the "ACME ↔ backing CA" topology from
[`docs/architecture-separation.md`](../../docs/architecture-separation.md): the ACME
protocol surface runs as its own process while the CA stays authoritative for scope and
identity.

## What runs here

- **ACME server.** `AddAcmeServer` plus `AddAcmeInMemoryStore` and `UseAcmeServer()`
  expose the RFC 8555 directory, account, order, challenge and revocation endpoints.
- **Remote issuer.** `AddAcmeRemoteCa` registers the backing-CA
  [`CaClient`](../opencertserver.ca.client/README.md) and the
  [`RemoteIssuer`](../opencertserver.acme.remote/README.md) as this host's
  `IIssueCertificates`, so every ACME order is signed by the backing CA, not by a local
  key. The host always uses the remote issuer; it has no in-process CA.
- **Default CSR validator.** `DefaultCsrValidator` checks that the proof-of-possession
  CSR carries at least one DNS `subjectAltName` and that its identifiers exactly match
  the order's identifiers. Scope authority remains with the backing CA, which re-checks
  scope on the delegated request.
- **Authentication.** JWT bearer (issuer + audiences from `AcmeServer:Authority` /
  `AcmeServer:Audiences`) plus certificate authentication, with authorization.

## Configuration

| Key | Required | Meaning |
|---|---|---|
| `Ca:RemoteUrl` | yes | Absolute HTTPS URL of the backing CA (read by `CaClientOptions`). |
| `Ca:Profile` | no | Default issuance profile forwarded to the CA. |
| `Ca:DelegatedScope` | no | Delegated scope the CA enforces on the ACME's requests. |
| `Ca:BearerToken` / `Ca:ClientCert` | no | Trusted-connection secret / mTLS identity. |
| `AcmeServer:Authority` | no | JWT issuer; when set, tokens are validated against it and `AcmeServer:Audiences`. |
| `AcmeServer:Audiences` | no | Allowed token audiences (array). |

See [`opencertserver.ca.client`](../opencertserver.ca.client/README.md) for the full
`Ca` section. As environment variables these read as `Ca__RemoteUrl`,
`AcmeServer__Authority`, and so on.

## Run

```sh
dotnet run --project src/opencertserver.acme -- --urls https://0.0.0.0:7100
```

Point `Ca:RemoteUrl` at a running backing CA (`opencertserver.ca.server` /
`opencertserver.certserver`) and supply a trusted-connection secret or client
certificate. The ACME host serves RFC 8555 over HTTPS and delegates issuance to the CA;
see [`docs/architecture-separation.md`](../../docs/architecture-separation.md)
§"Topologies" for the deployment.

## Dependencies

- `opencertserver.acme.remote` — the remote issuer and `AddAcmeRemoteCa` wiring.
- `opencertserver.acme.server` (transitive) — the ACME server.
- `opencertserver.ca.client` (transitive) — the backing-CA HTTP client.
- `Microsoft.AspNetCore.Authentication.Certificate`,
  `Microsoft.AspNetCore.Authentication.JwtBearer`,
  `Microsoft.IdentityModel.JsonWebTokens`, `Microsoft.IdentityModel.Protocols`
  (framework reference `Microsoft.AspNetCore.App`).
- `OpenTelemetry` / `OpenTelemetry.Extensions.Hosting` — exported when enabled.

This is an application host, not a library.
