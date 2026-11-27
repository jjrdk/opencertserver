# OpenCertServer.Amd.Native

This packaging project can include an ABI-compatible AMD SEV-SNP native library
under the .NET runtime asset paths:

```
runtimes/linux-x64/native/amd_snp_driver.so
runtimes/linux-arm64/native/amd_snp_driver.so
```

No native binaries are committed. The Cake pack task skips this package with a
warning if neither asset is staged; it does not remove older packages from its
output directory. It does not create a symbol package because this project has
no managed assembly or managed symbols.

## Staging and compatibility

Supply a library implementing `snp_get_vcek_chipid` and `snp_generate_report`
with the signatures expected by
[`AmdSnpNative`](../opencertserver.attestation/Native/AmdSnpNative.cs).
The [AMD SEV repository](https://github.com/AMDESE/AMDSEV) does not establish
that it provides this custom ABI. A library with a matching filename is not
necessarily compatible.

`fetch-native-amd.sh` searches common Linux x64 library locations and copies a
candidate into `runtimes/linux-x64/native/`; it does not verify its ABI.
Stage an arm64 asset manually if available. After verifying compatibility, run
the repository pack task or `dotnet pack -c Release` without `--include-symbols`.

The managed interop currently supports Linux only. Windows would require an
ABI-compatible implementation, platform-specific integration, and validation
on supported hardware; simply supplying a DLL is insufficient.

The published `opencertserver.attestation` package does not declare a
dependency on this native package. Consumers requiring it must reference a
populated native package separately.
