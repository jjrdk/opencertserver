# opencertserver.ra

The registration-authority (RA) side of the RA/CA split: an **outbound-only** peer
client plus the policy that lets one RA delegate enrollment to a central certificate
authority. The RA does not host or expose an inbound CA endpoint; it forwards a
proof-of-possession PKCS#10 request to a trusted backing CA and returns the signed
chain. Scope and identity authority stay with the CA; the RA adds policy and audit
around the delegated request.

This project is the library a RA host
([`opencertserver.ra.server`](../opencertserver.ra.server/README.md)) wires in; it is
also used by the monolith's RA peer wiring (`AddRa` / `AddPublicRa` in
`opencertserver.ca.server`).

## What runs here

- **`RaPeerClient`** — the outbound peer client, HTTPS-only (a non-HTTPS `PeerUrl`
  throws in the constructor). It delegates to the CA over
  [`opencertserver.ca.protocol`](../opencertserver.ca.protocol/README.md):
  - `EnrollAsync(csr, profile)` — `POST ca/csr` (or `ca/{profile}/csr`); `profile`
    falls back to the peer's configured default.
  - `GetSupportedProfiles()` — `GET ca/profiles`; returns only profile **names**, so an
    RA can offer the full set the CA supports and refresh it on demand.
  - `RenewAsync(csr)` — re-enrollment via `EnrollAsync` with the configured profile.
  - `RevokeAsync(identity, serial, reason)` — `DELETE ca/revoke` with the configured
    profile and a proof-of-possession signature over `serial + reason` (the canonical
    message lives in `RaProtocol.BuildRevocationMessage` so both sides agree). A `404`
    returns `false`; any other non-success throws.
- **`RaPeerOptions`** — the `Ra` configuration section, read by hand (no `Bind`) so the
  client stays AOT-safe. A non-HTTPS `PeerUrl` or a blank `Scope` is rejected.
- **`RaPeerServiceCollectionExtensions.AddRaPeerClient`** — registers the client and
  optionally configures its outbound TLS handler (for example to present an RA client
  certificate).

The RA declares its delegated scope on every request with the `X-Delegated-Subject`
header; the CA checks it against the RA's stored binding. The bearer token, when set,
authenticates the RA to the CA.

## Configuration (`Ra` section)

| Key | Required | Meaning |
|---|---|---|
| `Ra:PeerUrl` | yes | Absolute HTTPS URL of the backing CA (the "peer"). |
| `Ra:Scope` | yes | The delegated DNS suffix this RA acts for. |
| `Ra:Profile` | no | CA profile used when a request names none. |
| `Ra:Profiles` | no | Comma-separated delegated profile set; empty means **all** profiles the CA supports. Refreshable via `RaPeerClient.GetSupportedProfiles`. |
| `Ra:BearerToken` | no | Shared secret / bearer used to authenticate the RA to the CA. |

As environment variables these read as `Ra__PeerUrl`, `Ra__Scope`, and so on.

## Usage

```csharp
// Wire the RA peer client from configuration; a non-HTTPS PeerUrl or blank Scope throws.
services.AddRaPeerClient(RaPeerOptions.FromConfiguration(configuration),
    configureHandler: handler => { /* present an RA mTLS client certificate, if any */ });

// Or build one directly over an HttpClient and delegate a single enrollment:
using var client = new RaPeerClient(
    httpClient,
    new RaPeerOptions { PeerUrl = new Uri("https://ra.example.com"), Scope = "tenant-a.example.com" });
var certPem = await client.EnrollAsync(csrPem, profile: "rsa");
var profiles = await client.GetSupportedProfiles();   // names only
```

The RA host that consumes this client is
[`opencertserver.ra.server`](../opencertserver.ra.server/README.md). The shared RA/CA
wire contract (paths, headers, the revocation message, protocol version) lives in
[`opencertserver.ca.protocol`](../opencertserver.ca.protocol/README.md). See
[`docs/architecture-separation.md`](../../docs/architecture-separation.md)
§"opencertserver.ra peer client" for the topology.

## Dependencies

- `opencertserver.ca.protocol` — the shared RA/CA wire contract.
- `Microsoft.Extensions.Http`, `Microsoft.Extensions.Configuration`,
  `Microsoft.Extensions.DependencyInjection.Abstractions`.

This project is a library, not an application.
