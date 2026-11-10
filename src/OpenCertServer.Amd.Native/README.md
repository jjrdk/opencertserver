# OpenCertServer.Amd.Native

A RID-based NuGet asset that ships the **AMD SEV-SNP** user-space driver
(`amd_snp_driver.so`) so that
[`opencertserver.attestation`](../opencertserver.attestation/README.md) can load it on Linux
without managed code in between. This project contains **no managed assembly** — it is a
packaging project whose only job is to deliver the correct `runtimes/{rid}/native/` binary
to consumers automatically.

## What it ships

```
runtimes/linux-x64/native/amd_snp_driver.so
runtimes/linux-arm64/native/amd_snp_driver.so
```

The binaries are owned by AMD and are **not committed** to source control; only
`.gitkeep` placeholders live in the `runtimes/` tree. The project builds cleanly on
macOS/Windows developer machines because the `None`/`Content` items are guarded with
`Condition="Exists(...)"` — the files are packed or copied only when present.

## How the binaries get populated

The AMD SEV-SNP driver is built from
[AMDESE/AMDSEV](https://github.com/AMDESE/AMDSEV) or taken from a distro package. The
`fetch-native-amd.sh` script in this directory copies it into the RID layout from the common
install locations:

```sh
cd src/OpenCertServer.Amd.Native
./fetch-native-amd.sh          # populates runtimes/linux-{x64,arm64}/native/
dotnet pack -c Release         # then pack with the native asset included
```

## How it is consumed

[`opencertserver.attestation`](../opencertserver.attestation/README.md) references this
project with `ReferenceOutputAssembly="false"` (there is no managed assembly to reference),
which makes MSBuild propagate the `runtimes/{rid}/native/*.so` into the consumer's output on
publish so the .NET runtime discovers it at load time.

## Dependencies

None managed. It relies on native binaries supplied by AMD and placed under
`runtimes/{rid}/native/`, and targets `.NET 10` as a packaging project rather than an
application entry point.
