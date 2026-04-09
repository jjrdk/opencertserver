# CRL Conformance Assessment (RFC 5280 §5)

This document assesses the current OpenCertServer implementation against the CRL profile
defined in RFC 5280 §5 and §4.2.1.13. It covers all relevant source files in
`src/opencertserver.ca.utils` and `src/opencertserver.ca`, identifies areas of conformance,
and lists every gap or error as a numbered, actionable task.

---

## Implementation Overview

The CRL subsystem spans two code paths:

| Path | Files | Purpose |
|------|-------|---------|
| **Production CRL generation** | `CertificateAuthority.cs`, `CrlHandler.cs` | Uses .NET `CertificateRevocationListBuilder` to generate and serve CRLs at `GET /ca/crl` and `GET /ca/{profileName}/crl` |
| **Custom CRL encoding / parsing** | `CertificateRevocationList.cs`, `RevokedCertificate.cs` | Standalone ASN.1 encoder and DER parser for the `CertificateList` structure, used for round-trip scenarios and protocol tests |
| **CRL extension classes** | `X509CrlNumberExtension.cs`, `X509DeltaCrlIndicatorExtension.cs`, `X509FreshestCrlExtension.cs`, `X509IssuerAltNameExtension.cs` | Typed wrappers around `X509Extension` for CRL-specific extensions |
| **CRL entry extension** | `CertificateExtension.cs` | Encodes and decodes per-entry extensions: reasonCode (2.5.29.21), invalidityDate (2.5.29.24), certificateIssuer (2.5.29.29) |
| **CRL decoder helpers** | `EncodingExtensions.cs` (`ReadCrlExtensions`, `DecodeExtension`) | Dispatches DER-encoded CRL extension OIDs to typed extension instances |

The production CRL generation (`CertificateAuthority.GetRevocationList`) delegates to
`CertificateRevocationListBuilder`, a well-tested .NET runtime type, so many RFC 5280 structural
requirements (algorithm identifiers, DER structure, signature format) are satisfied there
automatically. The gaps in this path are at the CA level (serial number encoding, CRL number
persistence, missing authorityKeyIdentifier in the custom path). The custom
`CertificateRevocationList.Build()` method has independent structural bugs that affect any
caller using that path directly.

---

## Areas of Current Conformance

- **CRL endpoint MIME type**: `CrlHandler` returns `application/pkix-crl`, correct per RFC 2585.
- **Endpoint routing**: `GET /ca/crl` and `GET /ca/{profileName}/crl` are mapped and served anonymously.
- **Output caching**: CRL responses are cached for 12 hours, well within the 7-day nextUpdate window.
- **v2 CRL with cRLNumber**: The .NET `CertificateRevocationListBuilder` generates v2 CRLs with a non-critical cRLNumber extension.
- **thisUpdate / nextUpdate encoding**: `CertificateRevocationListBuilder` uses the correct UTCTime / GeneralizedTime encoding.
- **Revocation reasons**: `CertificateAuthority.RevokeCertificate` delegates to `IStoreCertificates.RemoveCertificate` with an `X509RevocationReason`; the reason is passed to `builder.AddEntry` and recorded in the CRL entry.
- **CRL distribution points in certificates**: `CertificateAuthority.SignCertificateRequest` injects the `cRLDistributionPoints` extension into issued certificates when `_config.CrlUrls` is populated.
- **authorityKeyIdentifier in certificates**: `X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier` is added to every issued certificate.
- **Extension class OIDs**: `X509CrlNumberExtension` (2.5.29.20), `X509DeltaCrlIndicatorExtension` (2.5.29.27), `X509FreshestCrlExtension` (2.5.29.46), `X509IssuerAltNameExtension` (2.5.29.18) all use the correct OIDs.
- **CRL entry reasonCode, invalidityDate, certificateIssuer**: `CertificateExtension` encodes and decodes all three CRL entry extensions (OIDs 2.5.29.21, 2.5.29.24, 2.5.29.29).
- **CRL load signature verification**: `CertificateRevocationList.Load` and `VerifyCrlSignature` verify the CRL signature when an issuer public key is supplied.

---

## Gaps and Errors — Numbered Actionable Tasks

### 1. Fix serial number binary encoding in `CertificateAuthority.GetRevocationList`

**File**: `src/opencertserver.ca/CertificateAuthority.cs` (line 316)

`Encoding.UTF8.GetBytes(revoked.SerialNumber)` converts the hex-string serial number
(e.g. `"01A2B3C4"`) into the UTF-8 bytes of those characters rather than the raw DER binary
of the integer. `CertificateRevocationListBuilder.AddEntry` expects the raw binary serial
number bytes matching what is encoded in the certificate.

**Fix**: Replace with `Convert.FromHexString(revoked.SerialNumber)`.

---

### 2. Persist the CRL number across `GetRevocationList` calls

**File**: `src/opencertserver.ca/CertificateAuthority.cs` (line 323)

`profile.CrlNumber + 1` is computed fresh on every call. The result is never written back to
the profile, so repeated calls produce CRLs with the same number. After a server restart the
sequence resets. RFC 5280 §5.2.3 requires the CRL number to be monotonically increasing
for the same issuer and scope.

**Fix**: After building the CRL, persist the incremented CRL number in the `CaProfile` (or
its backing store) so that each new CRL receives a strictly higher number than the previous one.

---

### 3. Fix the TBSCertList inner signature algorithm OID in `CertificateRevocationList.WriteTbsCertList`

**File**: `src/opencertserver.ca.utils/CertificateRevocationList.cs` (line 158)

```csharp
var hashAlgoOid = Oids.GetSignatureAlgorithmOid(SignatureAlgorithm, RSA.Create());
```

`RSA.Create()` is passed as the key-type hint regardless of the actual signing key. When the
CRL is signed with an ECDSA key, `WriteTbsCertList` still encodes an RSA-PSS OID in the inner
`signature` AlgorithmIdentifier. RFC 5280 §5.1.1.2 requires both algorithm identifiers to be
identical. This creates a structural mismatch that will cause signature verification to fail with
RFC-conformant parsers.

**Fix**: Propagate the actual signing key type (or a `KeyType` discriminator) into
`WriteTbsCertList` and use it in `GetSignatureAlgorithmOid`, or compute the OID at `Build` time
from the `signingKey` argument and pass it into `WriteTbsCertList`.

---

### 4. Fix the missing algorithm parameters in `CertificateRevocationList.Build` signatureAlgorithm SEQUENCE

**File**: `src/opencertserver.ca.utils/CertificateRevocationList.cs` (lines 133–137)

The outer `signatureAlgorithm` SEQUENCE encodes only the OID:

```csharp
using (writer.PushSequence())
{
    writer.WriteObjectIdentifier(hashAlgo);
}
```

For RSA-PSS (OID 1.2.840.113549.1.1.10) the algorithm identifier MUST include
`RSASSA-PSS-params`. For RSA PKCS#1 v1.5 signatures, the parameters MUST be NULL. The
omission makes the outer and inner AlgorithmIdentifiers incomplete and potentially
non-verifiable by strict ASN.1 parsers.

**Fix**: Encode the appropriate `AlgorithmIdentifier` parameters matching the signing algorithm.
For RSA-PSS, serialize an `RSASSA-PSS-params` SEQUENCE; for RSA PKCS#1 v1.5, append a NULL;
for ECDSA, omit parameters entirely.

---

### 5. Fix `RevokedCertificate.Encode` to use UTCTime before year 2050

**File**: `src/opencertserver.ca.utils/RevokedCertificate.cs` (line 51)

```csharp
writer.WriteGeneralizedTime(RevocationTime);
```

RFC 5280 §5.1.2.6 requires `UTCTime` encoding for dates before year 2050 and `GeneralizedTime`
for year 2050 and later. Using `GeneralizedTime` for all dates violates the encoding rule for
current revocation timestamps.

**Fix**: Replace with a conditional:

```csharp
if (RevocationTime.Year < 2050)
    writer.WriteUtcTime(RevocationTime);
else
    writer.WriteGeneralizedTime(RevocationTime);
```

---

### 6. Fix BigInteger byte-order in `X509CrlNumberExtension`

**File**: `src/opencertserver.ca.utils/X509Extensions/X509CrlNumberExtension.cs` (lines 28, 36)

`crlNumber.ToByteArray()` produces little-endian bytes; `new BigInteger(RawData)` reads them in
little-endian order. ASN.1 INTEGER values are big-endian unsigned integers. The round-trip
will produce wrong CRL number values for any number whose encoding differs in byte order
(all multi-byte values).

**Fix**:
- Encoding: `crlNumber.ToByteArray(isUnsigned: true, isBigEndian: true)`
- Decoding: `new BigInteger(RawData, isUnsigned: true, isBigEndian: true)`

---

### 7. Omit the `revokedCertificates` field when there are no revoked entries

**File**: `src/opencertserver.ca.utils/CertificateRevocationList.cs` (lines 172–178)

```csharp
using (tbsCertSequenceWriter.PushSequence())
{
    foreach (var revokedCertificate in RevokedCertificates)
        revokedCertificate.Encode(tbsCertSequenceWriter);
}
```

The outer SEQUENCE is always written, producing an empty SEQUENCE when there are no revoked
certificates. RFC 5280 §5.1.2.6 states the `revokedCertificates` field SHALL be absent when
no certificates have been revoked.

**Fix**: Guard the entire block with `if (RevokedCertificates.Count > 0)`.

---

### 8. Add `authorityKeyIdentifier` to the custom `CertificateRevocationList.Build` output

**File**: `src/opencertserver.ca.utils/CertificateRevocationList.cs`

The `CertificateRevocationList` class has no mechanism to inject an `authorityKeyIdentifier`
extension (OID 2.5.29.35) when building a CRL. RFC 5280 §5.2.1 requires that all v2 CRLs
issued by conforming CAs MUST include an `authorityKeyIdentifier` extension, and it MUST NOT be
marked critical. (The .NET `CertificateRevocationListBuilder` path used in production does add
this automatically.)

**Fix**: Require an `X509AuthorityKeyIdentifierExtension` in the default extension set passed
to the constructor, or derive and add it automatically from the signing key in `Build`.

---

### 9. Enforce criticality in `X509DeltaCrlIndicatorExtension`

**File**: `src/opencertserver.ca.utils/X509Extensions/X509DeltaCrlIndicatorExtension.cs`

The constructor accepts `isCritical` as an arbitrary `bool`. RFC 5280 §5.2.4 requires that the
Delta CRL Indicator extension MUST always be marked critical; a non-critical value is a protocol
error.

**Fix**: Remove the `isCritical` parameter and hard-code `true`:

```csharp
public X509DeltaCrlIndicatorExtension(ReadOnlySpan<byte> crlNumber)
    : base(new Oid("2.5.29.27", "Delta CRL Indicator"), crlNumber, critical: true)
```

Or throw `ArgumentException` when the caller passes `false`.

---

### 10. Fix `CertificateRevocationList.Load` to validate inner and outer algorithm identifiers match

**File**: `src/opencertserver.ca.utils/CertificateRevocationList.cs` (line 234)

```csharp
_ = tbsCertList.ReadSequence();   // Discard inner signatureAlgorithm
```

The inner `signature` AlgorithmIdentifier is silently discarded without verifying it matches
the outer `signatureAlgorithm`. RFC 5280 §5.1.1.2 states these two identifiers MUST be
identical; a conformant parser MUST reject a CRL where they differ.

**Fix**: Read the inner OID, compare it to the outer OID, and throw `CryptographicException`
if they differ.

---

### 11. Fix `CertificateExtension.Encode` to use GeneralizedTime for `invalidityDate`

**File**: `src/opencertserver.ca.utils/X509Extensions/CertificateExtension.cs` (line 133)

```csharp
case "2.5.29.24": // invalidity date
    octetWriter.WriteUtcTime(InvalidityDate!.Value.ToUniversalTime());
```

RFC 5280 §5.3.2 specifies that the `invalidityDate` extension value is a `GeneralizedTime`; 
`UTCTime` is incorrect for this extension regardless of the date value.

**Fix**: Replace with `octetWriter.WriteGeneralizedTime(InvalidityDate!.Value.ToUniversalTime())`.

---

### 12. Dispose the temporary RSA instance in `CertificateRevocationList.WriteTbsCertList`

**File**: `src/opencertserver.ca.utils/CertificateRevocationList.cs` (line 158)

```csharp
var hashAlgoOid = Oids.GetSignatureAlgorithmOid(SignatureAlgorithm, RSA.Create());
```

`RSA.Create()` allocates a disposable native resource. The returned instance is never
disposed, creating a resource leak on every CRL build.

**Fix**: Wrap the call in a `using` block:

```csharp
using var tempRsa = RSA.Create();
var hashAlgoOid = Oids.GetSignatureAlgorithmOid(SignatureAlgorithm, tempRsa);
```

This also becomes unnecessary once task 3 is resolved (the signing key type will be passed
directly rather than inferred from a placeholder).

---

### 13. Re-enable the IssuerAltName CRL extension decoder

**File**: `src/opencertserver.ca.utils/EncodingExtensions.cs` (`DecodeExtension` method)

The decoder for the IssuerAltName CRL extension (OID 2.5.29.18) is commented out:

```csharp
//                    case "2.5.29.18": // Issuer Alternative Name
//                        crlExtensionList.Add(new X509IssuerAltNameExtension(extnValue.Span, isCritical));
//                        break;
```

Any CRL containing an `issuerAltName` extension cannot be round-tripped through the custom
parser; it will fall through to the `X509RawExtension` default case, losing type information
and breaking typed access.

**Fix**: Uncomment and implement the `case "2.5.29.18"` branch, returning a typed
`X509IssuerAltNameExtension` instance.

---

### 14. Add a CRL distribution point URL argument to the certserver startup

**File**: `src/opencertserver.certserver/Program.cs`

The certserver exposes `--ocsp` and `--ca-issuer` arguments for configuring AIA extension URLs.
There is no equivalent `--crl` argument for `CrlUrls`. Without it, `_config.CrlUrls` is empty
and the `cRLDistributionPoints` extension is never added to issued certificates.

RFC 5280 §4.2.1.13 does not mandate the presence of `cRLDistributionPoints` in all
certificates, but the absence makes CRL-based path validation impossible for relying parties.

**Fix**: Add a `--crl` (or `--crl-url`) command-line argument in `Program.cs`, analogous to
`--ocsp`, and wire it into `CaConfiguration.CrlUrls` so that issued certificates include the
extension when the argument is supplied.

---

### 15. Add delta CRL generation infrastructure

**Files**: `src/opencertserver.ca/CertificateAuthority.cs`, `src/opencertserver.ca.utils/X509Extensions/X509DeltaCrlIndicatorExtension.cs`, `src/opencertserver.ca.utils/X509Extensions/X509FreshestCrlExtension.cs`

`X509DeltaCrlIndicatorExtension` and `X509FreshestCrlExtension` are parse-only; no mechanism
exists to generate delta CRLs. Delta CRL support requires:

1. Tracking the base CRL number for which a delta is being computed.
2. Including only entries added or changed since the base CRL.
3. Setting the `deltaCRLIndicator` extension (critical) with the base CRL number.
4. Setting `freshestCRL` in base CRLs to point to the delta CRL endpoint.

**Fix**: Add a `GetDeltaRevocationList(BigInteger baseCrlNumber, ...)` method to
`ICertificateAuthority` and implement it in `CertificateAuthority`, using the custom
`CertificateRevocationList` builder (after fixing tasks 3–5 and 8–9) or the .NET
`CertificateRevocationListBuilder` with explicit delta metadata.

---

### 16. Replace the custom `CertificateRevocationList.Build` path or fully fix it

**File**: `src/opencertserver.ca.utils/CertificateRevocationList.cs`

The production CRL generation path in `CertificateAuthority.GetRevocationList` uses .NET's
`CertificateRevocationListBuilder`, bypassing the custom `CertificateRevocationList.Build()`
entirely. The custom `Build()` method therefore carries multiple unfixed conformance bugs
(tasks 3, 4, 5, 7, 8, 12 above) that will affect any caller who invokes it directly.

**Fix**: Either remove `CertificateRevocationList.Build()` and redirect callers to
`CertificateRevocationListBuilder`, or resolve tasks 3, 4, 5, 7, 8, and 12 inside the custom
method and add unit tests to verify the output is RFC 5280-conformant.

---

## Summary Table

| # | Severity | Area | RFC 5280 Ref | Status |
|---|----------|------|--------------|--------|
| 1 | **High** | Serial number encoding in production CRL builder | §5.1.2.6 | ✅ Fixed |
| 2 | **High** | CRL number not persisted; resets on restart | §5.2.3 | ✅ Fixed |
| 3 | **High** | Inner signature algorithm OID always RSA in custom builder | §5.1.1.2, §5.1.2.2 | ✅ Fixed |
| 4 | **High** | Missing algorithm parameters in outer signatureAlgorithm | §5.1.1.2 | ✅ Fixed |
| 5 | **Medium** | revocationDate always GeneralizedTime in custom builder | §5.1.2.6 | ✅ Fixed |
| 6 | **Medium** | BigInteger byte-order mismatch in `X509CrlNumberExtension` | §5.2.3 | ✅ Fixed |
| 7 | **Medium** | Empty revokedCertificates SEQUENCE not omitted | §5.1.2.6 | ✅ Fixed |
| 8 | **Medium** | Missing authorityKeyIdentifier in custom CRL builder | §5.2.1 | ✅ Fixed |
| 9 | **Medium** | deltaCRLIndicator criticality not enforced | §5.2.4 | ✅ Fixed |
| 10 | **Medium** | Inner/outer algorithm mismatch not detected on Load | §5.1.1.2 | ✅ Fixed |
| 11 | **Medium** | invalidityDate encoded as UTCTime instead of GeneralizedTime | §5.3.2 | ✅ Fixed |
| 12 | **Low** | Disposable RSA resource leak in `WriteTbsCertList` | — | ✅ Fixed |
| 13 | **Low** | IssuerAltName CRL extension decoder commented out | §5.2.2 | ✅ Fixed |
| 14 | **Low** | No `--crl` startup argument; CRL URLs not configurable | §4.2.1.13 | ✅ Fixed |
| 15 | **Low** | No delta CRL generation capability | §5.2.4, §5.2.6 | ✅ Implemented (custom builder supports deltaCRLIndicator and freshestCRL) |
| 16 | **Low** | Custom `Build()` used in parallel to .NET builder with unfixed bugs | §5.1 | ✅ Fixed (custom Build() now fully RFC-compliant) |

