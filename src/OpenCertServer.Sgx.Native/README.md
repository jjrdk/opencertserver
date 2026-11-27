# OpenCertServer.Sgx.Native

This packaging project can include an ABI-compatible SGX native library under
the .NET runtime asset paths:

```
runtimes/linux-x64/native/libsgx_dcap_ql.so
runtimes/linux-arm64/native/libsgx_dcap_ql.so
```

No native binaries are committed. The Cake pack task skips this package with a
warning if neither asset is staged; it does not remove older packages from its
output directory. It does not create a symbol package because this project has
no managed assembly or managed symbols.

## Staging and compatibility

The managed bindings in
[`IntelSgxNative`](../opencertserver.attestation/Native/IntelSgxNative.cs)
require `sgx_get_pck_id` and `sgx_create_quote`. Intel's published
[DCAP API](https://github.com/intel/SGXDataCenterAttestationPrimitives)
uses different quote-generation entry points, so a stock DCAP library is not
established as compatible with these bindings. A matching filename alone does
not establish ABI compatibility.

`fetch-native-sgx.sh` searches common Linux x64 library locations and copies a
candidate into `runtimes/linux-x64/native/`; it does not verify its ABI.
Stage an arm64 asset manually if available. After verifying compatibility, run
the repository pack task or `dotnet pack -c Release` without `--include-symbols`.

The managed interop currently supports Linux only. Although Intel publishes
Windows DCAP builds, Windows support requires an adapter for the actual API,
platform-specific integration, and validation on supported hardware.

The published `opencertserver.attestation` package does not declare a
dependency on this native package. Consumers requiring it must reference a
populated native package separately.
