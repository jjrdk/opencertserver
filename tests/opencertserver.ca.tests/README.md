# opencertserver.ca.tests

The regression / unit suite for the CA core
(`opencertserver.ca`) and the PKI helpers it builds on (`opencertserver.ca.utils`). Unlike
the feature-driven suites, this project is written in xUnit (`.Tests.cs` classes) rather
than Reqnroll `.feature` files, because these are focused checks on pure algorithms and
types rather than protocol-level behaviors.

## What it covers

- **CA core** — `CaProfileTests`, `CertificateAuthorityTests`, `CrlTests`,
  `InMemoryCertificateStoreTests`.
- **OCSP (RFC 6960)** — `Ocsp/OcspRequestTests`, `Ocsp/OcspResponseTests`.
- **PKCS#7 / CMS** — `SignedDataTests`.
- **X.509 / ASN.1 encoding** — the `X509/` folder: `X509NameTests`, `AsnStringTests`,
  `GeneralNameTests`, `GeneralNamesTests`, `AttributeTypeValueTests`,
  `RelativeDistinguishedNameTests`, `CertificateSigningRequestTemplateTests`,
  `SubjectPublicKeyInfoTemplateTests`, and the name-component types (`DirectoryString`,
  `DistributionPoint(Name)`, `EdiPartyName`, `OtherName`, …).
- **Extensions** — `CertificateExtensionsTests`, `X509CertificateTests`, and
  `ValidateAll.cs` (a bulk validator over the encoding types).

## Run

```sh
dotnet test --project tests/opencertserver.ca.tests
```

No containers are required.
