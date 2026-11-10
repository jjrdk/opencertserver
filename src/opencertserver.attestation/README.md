# opencertserver.attestation

The hardware-trust layer for OpenCertServer. It abstracts platform-specific
attestation backends behind a single `IAttestationProvider` contract so the CA and the
`device-attest-01` ACME challenge can accept device identities without knowing which
hardware is present. Three backends ship today: **Intel SGX**, **AMD SEV-SNP** and
**Apple Secure Element** (Apple App Attest).

This is a library, not an application: a host registers the attestation services with
`AddAttestationServices` and then selects a provider through `GlobalAttestationService`.

## What runs here

- **`IAttestationProvider`** — the backend contract:
  `VendorName`, `GetDeviceIdAsync()`,
  `RetrieveDeviceCertificateAsync(deviceId)` and
  `GenerateAndSignQuoteAsync(cert, nonce)`.
- **`SgxProvider`** (`VendorName = "Intel"`) — Intel SGX DCAP quotes over the native
  `libsgx_dcap_ql` library (supplied by
  [`OpenCertServer.Sgx.Native`](../OpenCertServer.Sgx.Native/README.md)).
- **`AmdSnpProvider`** (`VendorName = "AMD"`) — AMD SEV-SNP quotes over the native
  `amd_snp_driver` library (supplied by
  [`OpenCertServer.Amd.Native`](../OpenCertServer.Amd.Native/README.md)).
- **`AppleSeProvider`** (`VendorName = "Apple"`) — Apple App Attest. When
  `AppleSE:UseDeviceAttestation` is `true` (the device case, macOS 11+ / iOS 14+) it drives
  the native `DCAppAttestService` to generate an attestation object on-device; when it is
  `false` (the default, the server case) the `nonce` argument to
  `GenerateAndSignQuoteAsync` is the raw CBOR attestation object received from an iOS/macOS
  client, which is forwarded to Apple's verification endpoint.
- **`GlobalAttestationService`** — selects a provider by `AttestationOptions.VendorPreference`
  when set, otherwise by the default vendor for the configured `CloudContext`
  (`Azure`→Intel, `AWS`→Intel, `Client`→Apple, `Local`→Intel). `GetProvider()` resolves it
  from the registered `IAttestationProvider` set; `GetEndpointForVendor(vendor)` returns the
  vendor's primary verification endpoint for the active cloud context.
- **Native interop (`Native/`)** — the platform-specific P/Invoke shims
  (`SgxNativeInterop`, `AmdSnpNativeInterop`, and for Apple a `SecurityFramework` direct
  interop on macOS, a shim-based interop elsewhere) behind `ISgxNativeInterop` /
  `IAmdSnpNativeInterop` / `IAppleAttestNativeInterop`.
- **`TrustStore`** and **`InMemoryCertificateCache`** — the root-trust store and the
  shared device-certificate cache.

## Configuration

`AddAttestationServices(configuration)` binds the top-level `Global` section and the
per-vendor `Providers:*` sections into `AttestationOptions`:

| Section | Key | Default | Meaning |
|---|---|---|---|
| `Global` | `CloudContext` | `Local` | Cloud context driving default vendor selection. |
| `Global` | `VendorPreference` | *(unset)* | Force a vendor (`Intel` / `AMD` / `Apple`); otherwise selection is by `CloudContext`. |
| `Global` | `RevocationMode` | `Online` | CRL/OCSP check mode; set `NoCheck` in test environments where test certs have no distribution points. |
| `Providers:IntelSgx` | `PccsUrl` | `https://pccs.confidentialcomputing.azure.com` | Intel PCCS endpoint. |
| `Providers:IntelSgx` | `RootCA` | `intel_root.cer` | Intel root certificate file. |
| `Providers:IntelSgx` | `CertificateCacheTtl` | `24h` | Device-certificate cache lifetime. |
| `Providers:AmdSevSnp` | `VpsUrl` | `https://amd-vps.confidentialcomputing.azure.com` | AMD VPS endpoint. |
| `Providers:AmdSevSnp` | `RootCA` | `amd_root.cer` | AMD root certificate file. |
| `Providers:AmdSevSnp` | `CertificateCacheTtl` | `24h` | Device-certificate cache lifetime. |
| `Providers:AppleSE` | `TeamId` / `AppId` | *(empty)* | Apple developer team / app identifiers. |
| `Providers:AppleSE` | `VerifyUrl` | `https://appattest.apple.com` | Apple App Attest verification endpoint. |
| `Providers:AppleSE` | `UseDeviceAttestation` | `false` | `true` generates on-device quotes; `false` verifies client-supplied CBOR objects. |

As environment variables these read as `Global__CloudContext`,
`Providers__IntelSgx__PccsUrl`, and so on.

## Usage

```csharp
using OpenCertServer.Attestation;

// After services.AddOptions():
services.AddAttestationServices(configuration);

// Resolve and use a provider for the current environment:
var attestation = serviceProvider.GetRequiredService<GlobalAttestationService>();
var provider = attestation.GetProvider();           // picks Intel/AMD/Apple per config
var quote = await provider.GenerateAndSignQuoteAsync(deviceCert, nonce);
```

## Dependencies

- `opencertserver.ca.utils` — shared PKI / crypto helpers.
- `OpenCertServer.Sgx.Native` / `OpenCertServer.Amd.Native` — the RID-based native binary
  packages (referenced with `ReferenceOutputAssembly="false"`; the `.so` files are populated
  on a Linux CI agent by the packages' `fetch-native-*.sh` scripts and are not committed).
- `Microsoft.Extensions.Configuration(.Json)`, `Microsoft.Extensions.DependencyInjection(.Abstractions)`,
  `Microsoft.Extensions.Http`, `Microsoft.Extensions.Logging.Abstractions`.

The project uses `AllowUnsafeBlocks` for the native P/Invoke shims. It is a supporting
library for attestation-aware certificate and key workflows, not an application.
