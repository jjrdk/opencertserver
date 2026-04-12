using OpenCertServer.Tpm2Lib;

namespace OpenCertServer.Tpm;

using System;
using System.Security.Cryptography;

/// <summary>
/// <see cref="ITpmKeyProvider"/> implementation backed by the vendored <b>TSS.NET</b> library
/// (https://github.com/microsoft/TSS.MSR, snapshot 2022-04-22, MIT-licensed).
/// <para>
/// Migration note: if the vendored TSS.NET is updated or replaced, the only change needed is
/// swapping the <see cref="TcpTpmDevice"/>/<see cref="LinuxTpmDevice"/>/<see cref="TbsDevice"/>
/// construction and the <see cref="Tpm2"/> usage. The interface contract exposed via
/// <see cref="ITpmKeyProvider"/> is unchanged.
/// </para>
/// </summary>
public sealed class TssTpmKeyProvider : ITpmKeyProvider
{
    // P-256 coordinate size in bytes
    private const int EcCoordSize = 32;

    /// <summary>
    /// Tracks which simulator endpoints have already been powered on and started within
    /// the current process.  The IBM SW TPM2 simulator stays in a running state after
    /// a <c>SessionEnd</c> command (i.e. after <see cref="Dispose"/> is called), so only
    /// the <em>first</em> connection to a given endpoint needs <c>SignalPowerOn</c> +
    /// <c>TPM2_Startup</c>.  Subsequent connections must skip <c>SignalPowerOn</c>;
    /// otherwise the simulator re-initialises and all persistent handles are wiped.
    /// </summary>
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, bool>
        _initializedSimulatorEndpoints = new();

    private static readonly ObjectAttr SigningKeyAttributes =
        ObjectAttr.Sign
        | ObjectAttr.FixedParent
        | ObjectAttr.FixedTPM
        | ObjectAttr.SensitiveDataOrigin
        | ObjectAttr.UserWithAuth
        | ObjectAttr.NoDA; // unrestricted — no ticket required to sign external digests

    private readonly Tpm2Device _device;
    private readonly Tpm2 _tpm;
    private readonly object _lock = new();

    /// <summary>
    /// Creates a provider that connects using the mode and options specified in <paramref name="options"/>.
    /// </summary>
    public TssTpmKeyProvider(TpmCaOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

            _device = options.Mode switch
            {
                TpmMode.Linux => new LinuxTpmDevice(),
                TpmMode.Windows => new TbsDevice(),
                TpmMode.Simulator => options.SimulatorPlatformPort.HasValue
                    ? new TcpTpmDevice(options.SimulatorHost, options.SimulatorPort, options.SimulatorPlatformPort.Value)
                    : new TcpTpmDevice(options.SimulatorHost, options.SimulatorPort),
                _ => throw new InvalidOperationException($"Unknown TpmMode '{options.Mode}'.")
            };

        // The newer TSS.NET requires an explicit Connect() call; the old NuGet package
        // (Microsoft.TSS 2.1.1) handled this lazily. For Linux and Windows the device
        // implementations open the kernel/TBS handle inside Connect().
        _device.Connect();

        _tpm = new Tpm2(_device);

        // The IBM SW TPM2 simulator starts in a powered-off state and must be
        // initialised before any commands are accepted.  On real hardware (Linux
        // kernel driver or Windows TBS) the OS handles power and startup.
        if (options.Mode == TpmMode.Simulator)
        {
            var tcp = (TcpTpmDevice)_device;

            // Build an endpoint key using host + command port so we can detect whether
            // this is the first connection to this particular simulator instance within
            // the current process.  After a SessionEnd the IBM simulator stays running
            // with all persistent handles intact — only the very first connection needs
            // PowerOn() + Startup(Clear).  Calling PowerOn() on a subsequent connection
            // would reinitialise the simulator and wipe all keys, forcing expensive
            // re-provisioning on every test scenario.
            var endpointKey = $"{options.SimulatorHost}:{options.SimulatorPort}";
            bool isFirstConnection = _initializedSimulatorEndpoints.TryAdd(endpointKey, true);

            if (isFirstConnection && tcp.PlatformAvailable() && tcp.PowerCtlAvailable())
            {
                tcp.PowerOn();
            }

            // Always call Startup with _AllowErrors so that:
            //  • First connection:  Startup(Su.Clear) succeeds → TPM initialised.
            //  • Subsequent conns:  Startup(Su.Clear) returns TPM_RC_INITIALIZE → cleared.
            _tpm._AllowErrors();
            _tpm.Startup(Su.Clear);
            _tpm._GetLastResponseCode(); // clear the error flag
        }
    }

    // -----------------------------------------------------------------
    // Key provisioning
    // -----------------------------------------------------------------

    /// <inheritdoc />
    public void EnsureRsaKey(uint persistentHandle)
    {
        lock (_lock)
        {
            if (KeyExists(persistentHandle))
            {
                return;
            }

            var template = new TpmPublic(
                TpmAlgId.Sha256,
                SigningKeyAttributes,
                null,
                new RsaParms(
                    new SymDefObject(TpmAlgId.Null, 0, TpmAlgId.Null),
                    new NullAsymScheme(),
                    2048,
                    0),
                new Tpm2bPublicKeyRsa());

            var keyHandle = _tpm.CreatePrimary(
                TpmHandle.RhOwner,
                new SensitiveCreate(),
                template,
                null,
                [],
                out _,
                out _,
                out _,
                out _);

            _tpm.EvictControl(TpmHandle.RhOwner, keyHandle, PersistentHandle(persistentHandle));
            _tpm.FlushContext(keyHandle);
        }
    }

    /// <inheritdoc />
    public void EnsureEcDsaKey(uint persistentHandle)
    {
        lock (_lock)
        {
            if (KeyExists(persistentHandle))
            {
                return;
            }

            var template = new TpmPublic(
                TpmAlgId.Sha256,
                SigningKeyAttributes,
                null,
                new EccParms(
                    new SymDefObject(TpmAlgId.Null, 0, TpmAlgId.Null),
                    new NullAsymScheme(),
                    EccCurve.NistP256,
                    new NullKdfScheme()),
                new EccPoint());

            var keyHandle = _tpm.CreatePrimary(
                TpmHandle.RhOwner,
                new SensitiveCreate(),
                template,
                null,
                [],
                out _,
                out _,
                out _,
                out _);

            _tpm.EvictControl(TpmHandle.RhOwner, keyHandle, PersistentHandle(persistentHandle));
            _tpm.FlushContext(keyHandle);
        }
    }

    // -----------------------------------------------------------------
    // Signing
    // -----------------------------------------------------------------

    /// <inheritdoc />
    public byte[] SignRsa(uint persistentHandle, byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        lock (_lock)
        {
            ISigSchemeUnion scheme = padding == RSASignaturePadding.Pss
                ? new SchemeRsapss(ToTpmAlgId(hashAlgorithm))
                : (ISigSchemeUnion)new SchemeRsassa(ToTpmAlgId(hashAlgorithm));

            var signature = _tpm.Sign(
                PersistentHandle(persistentHandle),
                hash,
                scheme,
                TpmHashCheck.Null());

            return ((SignatureRsa)signature).sig;
        }
    }

    /// <inheritdoc />
    public byte[] SignEcDsa(uint persistentHandle, byte[] hash, HashAlgorithmName hashAlgorithm)
    {
        lock (_lock)
        {
            var scheme = new SchemeEcdsa(ToTpmAlgId(hashAlgorithm));
            var signature = _tpm.Sign(
                PersistentHandle(persistentHandle),
                hash,
                scheme,
                TpmHashCheck.Null());

            var eccSig = (SignatureEcc)signature;

            // Convert TPM raw (R, S) to IEEE P1363 format: R‖S each zero-padded to EcCoordSize bytes.
            return ToP1363(eccSig.signatureR, eccSig.signatureS, EcCoordSize);
        }
    }

    // -----------------------------------------------------------------
    // Public key export
    // -----------------------------------------------------------------

    /// <inheritdoc />
    public RSAParameters ExportRsaPublicParameters(uint persistentHandle)
    {
        lock (_lock)
        {
            var pub = _tpm.ReadPublic(PersistentHandle(persistentHandle), out _, out _);
            var rsaUnique = (Tpm2bPublicKeyRsa)pub.unique;
            var rsaParms = (RsaParms)pub.parameters;

            var modulus = rsaUnique.buffer;
            var exponent = rsaParms.exponent == 0
                ? [0x01, 0x00, 0x01] // 65537
                : BitConverter.GetBytes(rsaParms.exponent);

            return new RSAParameters
            {
                Modulus = modulus,
                Exponent = exponent
            };
        }
    }

    /// <inheritdoc />
    public ECParameters ExportEcDsaPublicParameters(uint persistentHandle)
    {
        lock (_lock)
        {
            var pub = _tpm.ReadPublic(PersistentHandle(persistentHandle), out _, out _);
            var eccUnique = (EccPoint)pub.unique;

            // Pad X and Y to EcCoordSize bytes
            return new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = PadOrTrim(eccUnique.x, EcCoordSize),
                    Y = PadOrTrim(eccUnique.y, EcCoordSize)
                }
            };
        }
    }

    // -----------------------------------------------------------------
    // IDisposable
    // -----------------------------------------------------------------

    /// <inheritdoc />
    public void Dispose()
    {
        _tpm.Dispose();
        _device.Dispose();
    }

    // -----------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------

    private bool KeyExists(uint persistentHandle)
    {
        try
        {
            _tpm.ReadPublic(PersistentHandle(persistentHandle), out _, out _);
            return true;
        }
        catch (TpmException)
        {
            return false;
        }
    }

    /// <summary>
    /// Creates a <see cref="TpmHandle"/> for a persistent handle given its full raw value
    /// (e.g. 0x81010001).  The new TSS.NET <c>TpmHandle.Persistent(index)</c> factory
    /// method adds <c>0x81000000</c> to the index using addition, which overflows when the
    /// caller already supplies the fully-qualified persistent handle value.  Using
    /// <c>new TpmHandle(rawValue)</c> avoids the issue by setting the handle directly.
    /// </summary>
    private static TpmHandle PersistentHandle(uint rawHandleValue) => new TpmHandle(rawHandleValue);

    private static TpmAlgId ToTpmAlgId(HashAlgorithmName hashAlgorithm)
    {
        if (hashAlgorithm == HashAlgorithmName.SHA256)
        {
            return TpmAlgId.Sha256;
        }

        if (hashAlgorithm == HashAlgorithmName.SHA384)
        {
            return TpmAlgId.Sha384;
        }

        if (hashAlgorithm == HashAlgorithmName.SHA512)
        {
            return TpmAlgId.Sha512;
        }

        if (hashAlgorithm == HashAlgorithmName.SHA1)
        {
            return TpmAlgId.Sha1;
        }

        throw new NotSupportedException($"Hash algorithm '{hashAlgorithm.Name}' is not supported by this TPM provider.");
    }

    /// <summary>
    /// Converts TPM ECDsa (R, S) byte arrays to IEEE P1363 format: R‖S, each zero-padded
    /// to <paramref name="coordSize"/> bytes (big-endian).
    /// </summary>
    private static byte[] ToP1363(byte[] r, byte[] s, int coordSize)
    {
        var result = new byte[coordSize * 2];
        // R: right-aligned in first half
        var rSrc = r.Length <= coordSize ? r : r.AsSpan(r.Length - coordSize).ToArray();
        rSrc.AsSpan().CopyTo(result.AsSpan(coordSize - rSrc.Length));
        // S: right-aligned in second half
        var sSrc = s.Length <= coordSize ? s : s.AsSpan(s.Length - coordSize).ToArray();
        sSrc.AsSpan().CopyTo(result.AsSpan(coordSize * 2 - sSrc.Length));
        return result;
    }

    /// <summary>
    /// Pads (or trims a leading zero byte from) an array to exactly <paramref name="size"/> bytes.
    /// </summary>
    private static byte[] PadOrTrim(byte[] value, int size)
    {
        if (value.Length == size)
        {
            return value;
        }

        if (value.Length < size)
        {
            var padded = new byte[size];
            value.AsSpan().CopyTo(padded.AsSpan(size - value.Length));
            return padded;
        }

        // Strip leading zero bytes (BigInteger sign byte)
        return value.AsSpan(value.Length - size).ToArray();
    }
}

