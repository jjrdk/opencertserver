# opencertserver.tpm

TPM-backed CA key storage for OpenCertServer.  Private keys are generated once inside the
TPM chip and **never leave it**.  Certificates are stored in the standard OS certificate store
(`X509Store(CurrentUser, My)`) so no elevated permissions are required.

---

## Contents

- [How it works](#how-it-works)
- [Prerequisites](#prerequisites)
  - [Linux (production)](#linux-production)
  - [Windows (production)](#windows-production)
  - [macOS / CI (simulator)](#macos--ci-simulator)
- [Quick start](#quick-start)
- [Configuration reference](#configuration-reference)
- [Key rollover](#key-rollover)
- [Architecture: the ITpmKeyProvider swap seam](#architecture-the-itmkeyprovidder-swap-seam)
- [Migration guide: replacing the vendored TSS.Net implementation](#migration-guide-replacing-the-vendored-tssnet-implementation)
  - [Why you might need to migrate](#why-you-might-need-to-migrate)
  - [Checking for known vulnerabilities](#checking-for-known-vulnerabilities)
  - [Option A — Pkcs11Interop + tpm2-pkcs11](#option-a--pkcs11interop--tpm2-pkcs11)
  - [Option B — Vendor the TSS.Net source](#option-b--vendor-the-tssnet-source)
  - [Option C — Custom native P/Invoke](#option-c--custom-native-pinvoke)

---

## How it works

```
┌─────────────────────────────────────────────────────────────────────┐
│  ASP.NET Core DI                                                    │
│                                                                     │
│  AddTpmCertificateAuthority(opts =>                                 │
│  {                                                                  │
│      opts.Mode = TpmMode.Linux;          // or Windows / Simulator  │
│      opts.CaSubjectName = "CN=My CA";                               │
│  })                                                                 │
│         │                                                           │
│         ▼                                                           │
│  TpmCaProfileFactory                                                │
│    ├─ EnsureRsaKey(0x81000001)  ──────► TPM persistent handle       │
│    ├─ EnsureEcDsaKey(0x81000002)──────► TPM persistent handle       │
│    ├─ SelfSignCaCertificate()   (first run only)                    │
│    └─ StoreCertificate()        ──────► X509Store(CurrentUser, My)  │
│         │                                                           │
│         ▼                                                           │
│  CaProfile { PrivateKey = TpmRsa / TpmEcDsa }                       │
│    └─ SignHash(hash) ─────────────────► TPM Sign command            │
└─────────────────────────────────────────────────────────────────────┘
```

1. **First run** — keys are created inside the TPM and persisted at fixed handles.
   A self-signed CA certificate is written to the OS certificate store.
2. **Subsequent runs** — `ReadPublic` confirms the handles already exist (no-op).
   The CA certificate is loaded from the OS certificate store.
3. **Signing** — every certificate, CRL, and OCSP response is signed by calling the
   TPM's `Sign` command.  The RSA / ECDsa private key material never exists in process
   memory.

---

## Prerequisites

### Linux (production)

The application must be able to access the TPM resource manager device:

```
/dev/tpmrm0      # kernel TPM resource manager (preferred, Linux ≥ 4.12)
```

Ensure the user running the application is a member of the `tss` group:

```bash
sudo usermod -aG tss "$USER"
# re-login or: newgrp tss
```

No additional packages are required — the vendored `OpenCertServer.TSS.Net.Managed` library
communicates with the kernel device directly via `TssTpmKeyProvider`.

### Windows (production)

The Windows TPM Base Services (TBS) driver is always present on Windows 8+ systems with a
TPM.  No additional setup is needed.  Run the application as a standard user account; TBS
access does not require administrator rights for the `CurrentUser` hierarchy.

### macOS / CI (simulator)

Physical TPMs are not generally accessible on macOS.  Use the IBM TPM2 software simulator:

```bash
# Start the simulator (listens on TCP port 2321 and 2322 by default)
docker run --rm -d -p 2321:2321 -p 2322:2322 \
    --name tpm-simulator \
    ghcr.io/jjrdk/ibm-tpm2-simulator:latest
```

Set environment variables so the test suite can find it:

```bash
export TPM_SIMULATOR_HOST=localhost
export TPM_SIMULATOR_PORT=2321
```

All `TpmFact`-attributed tests skip automatically when the simulator is not reachable, so CI
pipelines without Docker pass cleanly.

---

## Quick start

### 1. Register in Program.cs

```csharp
builder.Services
    .AddInMemoryCertificateStore()          // or your IStoreCertificates implementation
    .AddTpmCertificateAuthority(opts =>
    {
        opts.Mode            = TpmMode.Linux;
        opts.CaSubjectName   = "CN=My Production CA, O=Example Corp";
        opts.RsaKeyHandle    = 0x81000001;  // change if handle conflicts with existing TPM usage
        opts.EcDsaKeyHandle  = 0x81000002;
        opts.CaCertificateValidity   = TimeSpan.FromDays(5 * 365);
        opts.IssuedCertificateValidity = TimeSpan.FromDays(90);
    },
    ocspUrls:  ["https://ca.example.com/ocsp"],
    crlUrls:   ["https://ca.example.com/crl"]);
```

### 2. Expose the CA endpoints

```csharp
app.UseAuthentication();
app.UseAuthorization();
app.MapCertificateAuthorityServer();
```

### 3. First-run behaviour

On the first start the application:

1. Calls `TPM2_CreatePrimary` to generate the RSA-2048 and P-256 keys inside the TPM.
2. Calls `TPM2_EvictControl` to persist them at the configured handles.
3. Self-signs a CA certificate using each key.
4. Writes the public certificates to `X509Store(CurrentUser, My)`.

On every subsequent start it loads the certificates from the store and resumes signing
immediately — no key re-generation occurs.

---

## Configuration reference

| Property | Default | Description |
|---|---|---|
| `Mode` | `Linux` | TPM connection mode: `Linux`, `Windows`, or `Simulator` |
| `SimulatorHost` | `localhost` | TCP host for the IBM TPM2 simulator |
| `SimulatorPort` | `2321` | TCP port for the simulator |
| `RsaKeyHandle` | `0x81000001` | Persistent TPM handle for the RSA-2048 signing key |
| `EcDsaKeyHandle` | `0x81000002` | Persistent TPM handle for the P-256 ECDsa signing key |
| `CaSubjectName` | `CN=TPM CA` | X.500 DN for the self-signed CA certificate |
| `CaCertificateValidity` | 5 years | Lifetime of the CA certificate |
| `IssuedCertificateValidity` | 90 days | Lifetime of leaf certificates issued by this CA |
| `OcspFreshnessWindow` | 1 hour | OCSP response freshness window |
| `CertStoreName` | `My` | OS certificate store used to persist the public CA cert |
| `CertStoreLocation` | `CurrentUser` | Certificate store location (no elevated permissions needed) |

**Handle collisions** — if `0x81000001` or `0x81000002` are already occupied by another
application on the target TPM, set `RsaKeyHandle` / `EcDsaKeyHandle` to any free handle in
the persistent object range `0x81000000`–`0x81FFFFFF`.  You can inspect occupied handles with:

```bash
tpm2_getcap handles-persistent    # tpm2-tools on Linux
```

---

## Key rollover

Rollover produces the four cross-signed certificates required for a seamless trust anchor
transition (RFC 5914 §4.1):

| Certificate | Meaning |
|---|---|
| **NewWithNew** | New CA cert, self-signed by the new key — the new active cert |
| **OldWithOld** | Old CA cert, public-only copy — for clients still trusting the old CA |
| **OldWithNew** | Old CA subject, signed by the new key — bridge from old to new |
| **NewWithOld** | New CA subject, signed by the old key — bridge from new to old |

To perform a rollover, provision a new key at a different handle, create a new profile, and
call `CaProfile.RollOver`:

```csharp
// 1. Provision a new key pair at a new handle
var newOptions = new TpmCaOptions { RsaKeyHandle = 0x81000003, ... };
using var newFactory = new TpmCaProfileFactory(newOptions);
var newProfile = newFactory.CreateOrLoadRsaProfile("default-new");

// 2. Attach the new cert and key to the existing active profile
existingProfile.RollOver(newProfile.CertificateChain[0], newProfile.PrivateKey);
// CaProfile.PublishedCertificateChain now contains all four rollover certificates.

// 3. After the rollover window has elapsed, close the publication window
existingProfile.CloseRolloverWindow();
```

---

## Architecture: the `ITpmKeyProvider` swap seam

```
┌────────────────────────────────────────────────────────────────────┐
│  TpmRsa : RSA          TpmEcDsa : ECDsa                            │
│    SignHash() ─────►  ITpmKeyProvider                              │
│    ExportParameters()    ▲          ▲                              │
│                          │          │                              │
│              TssTpmKeyProvider   (your replacement)                │
│     (OpenCertServer.TSS.Net.Managed) Pkcs11TpmKeyProvider          │
│                                  MockTpmKeyProvider (tests)        │
└────────────────────────────────────────────────────────────────────┘
```

`ITpmKeyProvider` is the **only** place that references the vendored `OpenCertServer.TSS.Net.Managed` library.  `TpmRsa`,
`TpmEcDsa`, `TpmCaProfileFactory`, and `TpmCaExtensions` are all library-agnostic.
Replacing the backing library requires:

1. Create a class that implements `ITpmKeyProvider`.
2. Register it instead of `TssTpmKeyProvider` (see [migration guide](#migration-guide-replacing-the-vendored-tssnet-implementation)).

---

## Migration guide: replacing the vendored TSS.Net implementation

This project already vendors a snapshot of the TSS.Net library as
`OpenCertServer.TSS.Net.Managed` to avoid platform-specific NuGet package dependencies.
If you need to swap this out (e.g. to consume a newer upstream version or use a different TPM
stack entirely), the options below apply.

### Why you might need to migrate

| Trigger | Action |
|---|---|
| CVE found in the vendored `OpenCertServer.TSS.Net.Managed` source | Apply the upstream patch from [TSS.MSR](https://github.com/microsoft/TSS.MSR) to the vendored copy, then pick an option below if no patch is available |
| Need a newer upstream TSS.Net version | Re-vendor from the upstream repo (see [Option B](#option-b--re-vendor-from-upstream-tssnet)) |
| .NET TFM upgrade breaks the vendored code | Test on the new TFM first; if broken, follow [Option A](#option-a--pkcs11interop--tpm2-pkcs11) |
| Organisational policy bans vendored copies | [Option A](#option-a--pkcs11interop--tpm2-pkcs11) or [Option B](#option-b--re-vendor-from-upstream-tssnet) |

### Checking for known vulnerabilities

Inspect the vendored source against upstream advisories:

```bash
# Compare your vendored copy against the upstream tag
git -C external/TSS.MSR log --oneline v<current-tag>..HEAD
```

Or use the GitHub Dependabot / OSV scanner in CI on the project as a whole:

```bash
# OSV Scanner (https://google.github.io/osv-scanner/)
osv-scanner --lockfile packages.lock.json
```

If a vulnerability is found in the vendored `OpenCertServer.TSS.Net.Managed` code:

1. Check whether a fix has been merged upstream in [TSS.MSR](https://github.com/microsoft/TSS.MSR).
2. If a fix exists, apply the relevant patch to the vendored copy under `src/OpenCertServer.TSS.Net.Managed/`.
3. If no fix exists or is insufficient, follow one of the options below.

### Option A — Pkcs11Interop + tpm2-pkcs11

This is the **recommended migration path**.  `Pkcs11Interop` is actively maintained (last
release 2023), vendor-neutral, and works across Linux, Windows, and macOS.  On Linux it
communicates with the TPM via the `tpm2-pkcs11` daemon; on macOS/CI it uses `softhsm2`.

**Step 1 — install system dependencies (Linux)**

```bash
sudo apt install tpm2-pkcs11 tpm2-tools     # Ubuntu / Debian
# or
sudo dnf install tpm2-pkcs11 tpm2-tools     # Fedora / RHEL
```

**Step 2 — initialise the PKCS#11 token (once per machine)**

```bash
tpm2_ptool init
tpm2_ptool addtoken --pid=1 --sopin=mysosecret --userpin=myusersecret --label=opencertserver
tpm2_ptool addkey --label=opencertserver --userpin=myusersecret --algorithm=rsa2048
tpm2_ptool addkey --label=opencertserver --userpin=myusersecret --algorithm=ecc256
```

**Step 3 — add the NuGet package**

```bash
dotnet add src/opencertserver.tpm package Pkcs11Interop
```

**Step 4 — implement `ITpmKeyProvider`**

Create `Pkcs11TpmKeyProvider.cs`:

```csharp
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

public sealed class Pkcs11TpmKeyProvider : ITpmKeyProvider
{
    private readonly IPkcs11Library _lib;
    private readonly ISession _session;

    public Pkcs11TpmKeyProvider(string pkcs11LibraryPath, string userPin)
    {
        var factories = new Pkcs11InteropFactories();
        _lib = factories.RoPkcs11LibraryFactory.LoadRoPkcs11Library(factories, pkcs11LibraryPath, AppType.MultiThreaded);
        // Open a session on the first slot with the "opencertserver" token
        var slot = _lib.GetSlotList(SlotsType.WithTokenPresent)
            .First(s => s.GetTokenInfo().Label.Trim() == "opencertserver");
        _session = slot.OpenSession(SessionType.ReadWrite);
        _session.Login(CKU.CKU_USER, userPin);
    }

    public void EnsureRsaKey(uint handle)   { /* key was created via tpm2_ptool */ }
    public void EnsureEcDsaKey(uint handle) { /* key was created via tpm2_ptool */ }

    public byte[] SignRsa(uint handle, byte[] hash, HashAlgorithmName alg, RSASignaturePadding pad)
    {
        var keyHandle = FindKeyByLabel(_session, "rsa-ca-key");
        var mechanism = pad == RSASignaturePadding.Pss
            ? new Mechanism(CKM.CKM_RSA_PKCS_PSS, BuildPssParams(alg))
            : new Mechanism(CKM.CKM_RSA_PKCS);
        return _session.Sign(mechanism, keyHandle, hash);
    }

    public byte[] SignEcDsa(uint handle, byte[] hash, HashAlgorithmName alg)
    {
        var keyHandle = FindKeyByLabel(_session, "ecdsa-ca-key");
        var sig = _session.Sign(new Mechanism(CKM.CKM_ECDSA), keyHandle, hash);
        return ToDerOrP1363(sig); // convert as needed
    }

    public RSAParameters ExportRsaPublicParameters(uint handle) { /* read CKA_MODULUS, CKA_PUBLIC_EXPONENT */ }
    public ECParameters  ExportEcDsaPublicParameters(uint handle) { /* read CKA_EC_POINT */ }

    public void Dispose() { _session.Dispose(); _lib.Dispose(); }
}
```

**Step 5 — swap the registration**

In `Program.cs`, replace the default `TssTpmKeyProvider` by supplying a custom provider
to `TpmCaProfileFactory`:

```csharp
builder.Services.AddSingleton<ITpmKeyProvider>(sp =>
    new Pkcs11TpmKeyProvider("/usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so", userPin: "myusersecret"));

builder.Services.AddSingleton<TpmCaProfileFactory>(sp => new TpmCaProfileFactory(
    sp.GetRequiredService<TpmCaOptions>(),
    sp.GetRequiredService<ITpmKeyProvider>()));   // ← uses your Pkcs11TpmKeyProvider

// Then call the rest of the normal CA registration:
builder.Services.AddTpmCertificateAuthority(opts => { ... });
// Note: AddTpmCertificateAuthority checks whether ITpmKeyProvider is already registered
// and will skip re-registering TssTpmKeyProvider if you do this in the right order.
```

Alternatively, extract the inner registrations directly (copy the body of
`AddTpmCertificateAuthority` and swap the `ITpmKeyProvider` line).

**Testing with softhsm2 (macOS / CI)**

```bash
brew install softhsm
softhsm2-util --init-token --slot 0 --label opencertserver \
    --so-pin mysosecret --pin myusersecret
```

Pass the softhsm2 library path:

```
/usr/local/lib/softhsm/libsofthsm2.so      # Linux
/opt/homebrew/lib/softhsm/libsofthsm2.so   # macOS (Apple Silicon)
```

---

### Option B — Re-vendor from upstream TSS.Net

This project already uses a vendored copy (`src/OpenCertServer.TSS.Net.Managed`).  If you
need a newer upstream revision, refresh it from the upstream repository:

1. Clone the upstream source:
   ```bash
   git clone https://github.com/microsoft/TSS.MSR /tmp/TSS.MSR
   ```
2. Copy the updated C# files over the vendored copy:
   ```bash
   cp -r /tmp/TSS.MSR/TSS.Net/. src/OpenCertServer.TSS.Net.Managed/
   ```
3. Review and reconcile any conflicts against the local patches in `src/OpenCertServer.TSS.Net.Managed/`.
4. Rebuild and run tests to confirm the updated copy compiles and passes.

---

### Option C — Custom native P/Invoke

On Linux, the `tpm2-tss` library (`libtss2-esys.so`) is actively maintained by the Linux
Foundation.  A thin P/Invoke wrapper can replace `Microsoft.TSS` entirely:

```csharp
[DllImport("libtss2-esys.so")]
private static extern TSS2_RC Esys_Sign(
    IntPtr esysContext, ESYS_TR keyHandle, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3,
    ref TPM2B_DIGEST digest, ref TPMT_SIG_SCHEME inScheme, ref TPMT_TK_HASHCHECK validation,
    out IntPtr signature);
```

This is the lowest-level option and requires the most maintenance.  It is only recommended
if both the vendored `OpenCertServer.TSS.Net.Managed` and `Pkcs11Interop` are unavailable or unsuitable.

---

## Security considerations

- **Handle ownership** — TPM persistent handles in the `0x81xxxxxx` range are owned by the
  Owner hierarchy.  Ensure the Owner hierarchy is properly authorised on the target machine.
- **No key export** — the key attributes include `FixedTPM | FixedParent` which prevents the
  keys from being duplicated or exported, even by the owner.
- **Dictionary attack prevention** — the `NoDA` flag is set on signing keys so that repeated
  failed authorisation attempts do not lock the key.  On a production system, consider
  removing `NoDA` and setting an `authValue` for the key if the threat model includes
  physical access to the machine.
- **Certificate store access** — public CA certificates are stored in
  `X509Store(CurrentUser, My)` and are accessible to the user account running the
  application only.  They contain no private key material.

