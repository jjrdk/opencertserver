# OpenCertServer.Sgx.Native

A RID-based NuGet asset that ships the **Intel SGX DCAP** native library
(`libsgx_dcap_ql.so`) so that
[`opencertserver.attestation`](../opencertserver.attestation/README.md) can load it on Linux
without managed code in between. This project contains **no managed assembly** — it is a
packaging project whose only job is to deliver the correct `runtimes/{rid}/native/` binary
to consumers automatically.

## What it ships

```
runtimes/linux-x64/native/libsgx_dcap_ql.so
runtimes/linux-arm64/native/libsgx_dcap_ql.so
```

The binaries are owned by Intel and are **not committed** to source control; only
`.gitkeep` placeholders live in the `runtimes/` tree. The project builds cleanly on
macOS/Windows developer machines because the `None`/`Content` items are guarded with
`Condition="Exists(...)"` — the files are packed or copied only when present.

## How the binaries get populated

The Intel DCAP `.so` is obtained from the distro package or Intel's
[DCAP](https://github.com/intel/SGXDataCenterAttestationPrimitives) source. The
`fetch-native-sgx.sh` script in this directory copies it into the RID layout from the common
Ubuntu/Debian/Fedora install locations:

```sh
cd src/OpenCertServer.Sgx.Native
./fetch-native-sgx.sh          # populates runtimes/linux-{x64,arm64}/native/
dotnet pack -c Release         # then pack with the native asset included
```

## How it is consumed

[`opencertserver.attestation`](../opencertserver.attestation/README.md) references this
project with `ReferenceOutputAssembly="false"` (there is no managed assembly to reference),
which makes MSBuild propagate the `runtimes/{rid}/native/*.so` into the consumer's output on
publish so the .NET runtime discovers it at load time.

## Dependencies

None managed. It relies on Intel DCAP binaries placed under
`runtimes/.../native/` and targets `.NET 10` as a packaging/deployment support project, not
an application entry point.
