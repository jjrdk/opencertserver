# opencertserver.attestation.Tests

Reqnroll BDD coverage for the
[`opencertserver.attestation`](../../src/opencertserver.attestation/README.md) hardware-trust
layer. The native backends are **mocked** at the interop boundary
(`Mocks/Mock{Sgx,AmdSnp,AppleAttest}NativeInterop.cs`), so the suite runs without real
TPM/SGX/Apple hardware.

## Feature suites

- `Features/SgxAttestation.feature` / `SgxNativeAttestation.feature` / `SgxFailureModes.feature`
  — Intel SGX quote generation, native interop and failure handling.
- `Features/AmdSnpAttestation.feature` / `AmdSnpNativeAttestation.feature` /
  `AmdSnpFailureModes.feature` — AMD SEV-SNP quotes, native interop and failure handling.
- `Features/AppleAttestationValidation.feature` / `AppleNativeAttestation.feature` /
  `AppleSeAttestation.feature` / `AppleAttestFailureModes.feature` — Apple Secure Element
  (App Attest): device-mode quote generation, server-mode CBOR verification, native
  interop and failure modes.
- `Features/GlobalServiceMapping.feature` — `GlobalAttestationService` provider selection by
  `VendorPreference` and by `CloudContext`.
- `Features/Config.feature` — binding the `Global` / `Providers:*` configuration sections.
- `Features/TrustStore.feature` / `TrustStoreEdgeCases.feature` — the root-trust store.

## Run

```sh
dotnet test --project tests/opencertserver.attestation.Tests
```

No containers are required — the native layer is replaced by the mocks in `Mocks/`.
