# opencertserver.ca.utils

The foundational X.509 / PKI helper library and the home of the **core CA contracts** that
the rest of the OpenCertServer stack compiles against. It is a dependency-free leaf
library (no package or project references): every CA-dependent project —
[`opencertserver.ca`](../opencertserver.ca/README.md),
[`opencertserver.ca.server`](../opencertserver.ca.server/README.md),
[`opencertserver.ca.client`](../opencertserver.ca.client/README.md),
[`opencertserver.est.server`](../opencertserver.est.server/README.md),
[`opencertserver.scep.server`](../opencertserver.scep.server/README.md),
[`opencertserver.tpm`](../opencertserver.tpm/README.md),
[`opencertserver.mcp`](../opencertserver.mcp/README.md),
[`opencertserver.cli`](../opencertserver.cli/README.md) and others — references this one, so
it is the common ground for certificate issuance, revocation, OCSP and CRL handling.

## What is in here

- **`Ca` — the authority contracts.** `ICertificateAuthority` is the central abstraction:
  `SignCertificateRequest` / `SignCertificateRequestPem` (sign a CSR against a profile,
  with optional requestor, re-enrollment anchor and validity window),
  `GetRootCertificates`, `GetPublishedCertificates`, `GetSupportedProfiles`,
  `RevokeCertificate` and `GetRevocationList`. The result type is `SignCertificateResponse`
  (`Success` carries the issued certificate plus issuer chain; `Error` carries the rejection
  messages). Supporting contracts: `IStoreCaProfiles` (`GetProfile(name)` / `GetProfiles()`),
  `IStoreCertificates` (add / revoke / paging, and the issuing-profile provenance used for
  profile-bound re-enrollment), `IValidateCertificateRequests` +
  `ICertificateRequestValueConverter` (identity checks), `CaProfile`, and
  `InMemoryCertificateStore`.
- **`Ocsp` — RFC 6960 OCSP.** Request/response models (`OCSPRequest`, `OcspResponse`,
  `OcspBasicResponse`, `SingleResponse`, `RevokedInfo`), responder identifiers by key or by
  name, and `IValidateOcspRequest` / `IResponderId`.
- **`Pkcs7` — CMS / PKCS#7 (RFC 5652).** `EnvelopedData`, `SignedData`, `SignerInfo`,
  recipient and content info, and the algorithm/identifier types used to build and read CMS
  structures.
- **`X509` and `X509/Templates` — ASN.1 and name encoding.** `X509Name`, the ASN.1 value
  types (`AsnString`, `AsnOctetString`, `GeneralNames`, `AttributeTypeValue`, …) and the
  `X509CertificateTemplate`-style builders for CSRs and extensions.
- **`X509Extensions` — extension helpers.** CRL number, delta-CRL indicator, freshest-CRL,
  issuer-alt-name, certificate-policies and raw-extension builders, plus
  `X509CertificatesExtensions`.
- **`Validation` — certificate-identity validation.** `CertificateIdentityValidator`,
  `IdentityMatcher`, `ServiceIdentity` / `ILookUpServiceProvider`, and the
  failure/result types.
- **Shared value types:** `Oids`, `TypeVersion`, `PasswordHash`, `EncodingExtensions`,
  `CertificateExtensions`, `CertificateRequestsExtensions`, `NameTemplate`,
  `RDNSequenceTemplate`, `RevokedCertificate`.

## How to use it

This is a library, not an application. You depend on it to implement or consume a CA. The
primary seam is `ICertificateAuthority`, which the in-process CA core
(`opencertserver.ca`) implements and which `opencertserver.ca.client` implements remotely as
`RemoteCertificateAuthority`:

```csharp
using OpenCertServer.Ca.Utils.Ca;

// In-process: sign through the CA core that implements ICertificateAuthority.
Task<SignCertificateResponse> SignCertificateRequestPem(
    string csrPem,
    string? profileName = null,
    ClaimsIdentity? requestor = null,
    X509Certificate2? reenrollingFrom = null,
    DateTimeOffset? notBefore = null,
    DateTimeOffset? notAfter = null,
    CancellationToken cancellationToken = default);

// A Success carries the issued leaf plus the issuer chain; an Error carries the reasons.
var response = await authority.SignCertificateRequestPem(csrPem, profile: "rsa");
```

To back an authority you implement `IStoreCaProfiles` and `IStoreCertificates` (or use
`InMemoryCertificateStore` for tests) and hand them to the CA core in
`opencertserver.ca`; `opencertserver.data` supplies the relational stores.

## OpenTelemetry

CA-facing helpers that publish telemetry do so through fixed operation names only
(for example `sign_certificate`, `revoke_certificate`, `get_revocation_list`) and never
attach certificate requests, subjects, serial numbers, thumbprints, profile names or
exception messages. The subscribing host owns the meter/activity-source export.

## Dependencies

None at the package or project level — this is the leaf of the dependency graph. It depends
only on the BCL (`System.Security.Cryptography`, `System.Security.Cryptography.X509Certificates`,
`System.Text`, …) and `Microsoft.Extensions.*` abstractions it consumes indirectly. Every
other CA project references it, not the reverse.

## Related

- [`opencertserver.ca`](../opencertserver.ca/README.md) — the core CA logic built on these
  contracts.
- [`docs/standards.md`](../../docs/standards.md) — the RFCs (OCSP, CRL, CAA, …) these
  helpers implement.
