# opencertserver.tss.net

A vendored copy of Microsoft's **TSS.NET** TPM 2.0 library
(https://github.com/microsoft/TSS.MSR), snapshot 2022-04-22, MIT-licensed. It is the
managed TPM 2.0 primitive layer behind `opencertserver.tpm`.

## Why it is vendored

The published `Microsoft.TSS 2.1.1` NuGet package ships a cross-platform (`netstandard2.0`)
assembly compiled against Windows BCrypt P/Invoke, and its `linux-x64` runtime-specific
assembly is x64-only and not loadable on macOS arm64. This vendored build uses **managed
.NET crypto only — no BCrypt dependency** — so it loads and runs on macOS, Linux and
Windows. The root namespace is `OpenCertServer.Tpm2Lib` (with a `Tpm2Lib` namespace
carried over from the source).

## Functionality

- Managed TPM 2.0 command/session primitives (e.g. `Tpm2Lib` command processing,
  `AuthSession`, `KDF`, `RawRsa`, `Prng`, `CommandProcessor`, `PolicyTree`).
- The underlying TPM operations used by OpenCertServer's TPM and attestation features.
- Consumed by `opencertserver.tpm` (its `TssTpmKeyProvider` implements `ITpmKeyProvider`
  over `OpenCertServer.Tpm2Lib`) and referenced by `opencertserver.acme.server`.

## Build notes

- No project or package references: this is the vendored third-party source itself.
- `IsAotCompatible` and `IsTrimmable` are **false** — it is a vendored library and is
  never trimmed or AOT-compiled; it is not safe for Native AOT.
- Warnings are not escalated to errors for this project, and a set of
  nullable/obsolete diagnostics from the large vendored source are suppressed (`NoWarn`).

The consuming host (`opencertserver.tpm`, `opencertserver.acme.server`) builds against the
repository's target framework (`net10.0` via `Directory.Build.props`); treat this assembly
as AnyCPU managed code rather than as a native or AOT artifact.

This assembly is a compatibility layer that keeps TPM support portable across
development and deployment environments.
