# opencertserver.ca.protocol

The shared **registration authority ↔ certificate authority wire contract**: the single
source of truth that an outbound RA ([`opencertserver.ra`](../opencertserver.ra/README.md))
and a backing CA ([`opencertserver.ca.server`](../opencertserver.ca.server/README.md)) both
compile against. Because neither side depends on the other — only on this package — the two
can be deployed as independent processes and still agree on paths, claims, headers, the
revocation signature and the protocol version. Changing the contract on one side cannot
silently desynchronize the other.

This is a small, dependency-free leaf library: pure constants, claims and
request/response records. It ships no HTTP client, no handler and no store of its own.

## What runs here

- **`RaProtocol`** — the wire constants both sides read *by reference* (never by copy):
  the request paths, claim and header names, the revocation proof-of-possession message,
  and the negotiated protocol version.
- **`RaBinding` / `IStoreRas` / `InMemoryRaStore`** — what a CA authorizes an RA for: an
  RA identity (`RaId`) plus the DNS scopes and CA profiles it may act on.
- **`RaClaimTypes`** — the RA identity claim and the delegated-scope claim/header, aliased
  to `RaProtocol` so both sides resolve to the same string.
- **`RaEnrollRequest` / `RaEnrollResponse`, `RaRevokeRequest` / `RaRevokeResponse`** — the
  typed contracts for the two delegated operations: enrollment and revocation.

## The wire contract

### Paths

| Constant | Value | Meaning |
|---|---|---|
| `CsrPath` | `ca/csr` | Sign a CSR against the default profile. |
| `ProfileCsrPathFormat` | `ca/{0}/csr` | Sign a CSR against a named profile (use `CsrPathFor`). |
| `RevokePath` | `ca/revoke` | Revoke by serial number with a signed proof-of-possession. |
| `CrlPath` / `ProfileCrlPathFormat` | `ca/crl` / `ca/{0}/crl` | Publish the (delta) revocation list. |
| `PublishedPath` / `ProfilePublishedPathFormat` | `ca/published` / `ca/{0}/published` | Publish the full chain (root + issuing CA). |
| `ProfilesPath` | `ca/profiles` | List the profile **names** the CA supports. |

`CsrPathFor(profile)` and `PublishedPathFor(profile)` pick the profile-specific path when a
profile is named and fall back to the default-profile path when it is empty; the profile is
`Uri.EscapeDataString`-encoded into the path.

### Headers, claims and query parameters

| Constant | Value | Meaning |
|---|---|---|
| `RaProtocolVersionHeader` | `X-Ra-Protocol-Version` | Optional RA-declared protocol version. |
| `RaIdClaim` | `ra` | The authenticated RA identifier claim (from the auth provider). |
| `DelegatedSubjectClaim` / `DelegatedSubjectHeader` | `delegated-subject` / `X-Delegated-Subject` | The delegated DNS scope the RA acts for; the header is only a request selector the CA checks against the stored binding. |
| `ReenrollingFromHeader` | `X-Reenrolling-From` | PEM of the certificate being re-enrolled from, so the CA supersede-revokes it on a remote SCEP/EST renewal. |
| `QuerySn` / `QueryReason` / `QuerySignature` | `sn` / `reason` / `signature` | Serial (hex), revocation reason, and the base64 proof-of-possession signature for `DELETE ca/revoke`. |
| `CsrMimeType` | `application/pkcs10` | MIME type of a PKCS#10 request body. |

The RA identity claim (`ra`) **must** come from the configured authentication provider; the
delegated-scope header is untrusted input that the CA validates against the RA's
`RaBinding`.

### Revocation proof-of-possession

A revocation carries a signature over the canonical message
`RaProtocol.BuildRevocationMessage(serialNumberHex, reasonName)` — the serial (hex) and the
reason name concatenated with **no separator**, digested with `SignatureHashAlgorithm`
(`SHA256`). Both sides compute the identical string from this one method, which is why it
lives here and not in either implementation.

### Protocol versioning

`RaProtocolVersion` is `"1"`. `SupportedVersions` is the additive set the CA accepts;
`IsSupportedVersion(declared)` returns `true` for any supported version **and for an empty
declaration** (the CA treats an absent `X-Ra-Protocol-Version` as the current version for
backwards compatibility).

## Usage

The CA side binds an RA and enforces its scope/profiles through the binding store:

```csharp
// opencertserver.ca.server
var bindings = new InMemoryRaStore([
    new RaBinding("ra-tenant-a",
        new HashSet<string>(["tenant-a.example.com"], StringComparer.Ordinal),
        new HashSet<string>(["rsa", "ecdsa"], StringComparer.Ordinal))
]);
builder.Services.AddSingleton<IStoreRas>(bindings);
// The CA's CsrHandler/RevocationHandler read RaProtocol.CsrPath / RaProtocol.RevokePath and
// check the X-Delegated-Subject header against the binding from IStoreRas.
```

The RA side reads the same constants to build its outbound requests
(see [`opencertserver.ra`](../opencertserver.ra/README.md) `RaPeerClient`, which posts to
`RaProtocol.CsrPath` / `RevokePath` and signs the revocation with
`RaProtocol.BuildRevocationMessage`).

## Dependencies

None. This is a leaf package in the dependency graph — both the RA and the CA reference it,
and it references neither, so it is the only thing the two share. The project's
`Description` (used for the NuGet package) states this contract explicitly.
