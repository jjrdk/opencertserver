using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace OpenCertServer.Attestation.Native;

/// <summary>
/// <see cref="IAppleAttestNativeInterop"/> implementation that calls Apple's
/// Security.framework directly via P/Invoke — no native shim package required.
///
/// <para><b>Key generation</b> first tries the Secure Enclave
/// (<c>kSecAttrTokenIDSecureEnclave</c>). If the SE is not available (e.g., Intel Mac
/// without T1/T2 chip), it falls back to a software-based EC P-256 key pair.
/// Either way a native Security.framework call is made.</para>
///
/// <para><b>Attestation</b> signs the caller-supplied SHA-256 digest using
/// <c>kSecKeyAlgorithmECDSASignatureDigestX962SHA256</c> and returns the raw attestation
/// bytes as: <c>[4-byte-LE sigLen][DER signature][X9.63 public key]</c>.</para>
///
/// <para>Only functional on macOS 10.12+ and iOS 10+.</para>
/// </summary>
public sealed class SecurityFrameworkAppleAttestInterop : IAppleAttestNativeInterop, IDisposable
{
    // kSecKeyAlgorithmECDSASignatureDigestX962SHA256 value from Security.framework
    private const string EcdsaDigestAlgorithm = "algid:sign:ECDSA:digest-X962:SHA256";

    // Maps hex(SHA-256(pubKeyBytes)) → native SecKeyRef (private key)
    private readonly ConcurrentDictionary<string, IntPtr> _keys = new(StringComparer.OrdinalIgnoreCase);

    // ── IAppleAttestNativeInterop ─────────────────────────────────────────────

    /// <inheritdoc/>
    public async Task<string> GenerateKeyAsync()
    {
        GuardPlatform();
        return await Task.Run(GenerateKeySync);
    }

    /// <inheritdoc/>
    public async Task<byte[]> AttestKeyAsync(string keyId, ReadOnlyMemory<byte> clientDataHash)
    {
        GuardPlatform();
        if (clientDataHash.Length != SHA256.HashSizeInBytes)
            throw new ArgumentException(
                $"clientDataHash must be {SHA256.HashSizeInBytes} bytes (SHA-256).", nameof(clientDataHash));

        if (!_keys.TryGetValue(keyId, out var privateKey))
            throw new InvalidOperationException(
                $"Key '{keyId}' not found. Call GenerateKeyAsync() first.");

        return await Task.Run(() => BuildAttestationObject(privateKey, clientDataHash.ToArray()));
    }

    // ── Core logic ────────────────────────────────────────────────────────────

    private string GenerateKeySync()
    {
        // Attempt Secure Enclave key first; fall back to software EC key.
        var key = TryCreateKey(useSecureEnclave: true)
                  ?? TryCreateKey(useSecureEnclave: false)
                  ?? throw new AttestationException(
                         "SecKeyCreateRandomKey failed for both SE and software EC key. " +
                         "Ensure macOS 10.12+ or iOS 10+ and that the process is not sandboxed.");

        // Derive keyId from SHA-256 of the public key bytes.
        var keyId = DeriveKeyId(key);
        _keys[keyId] = key; // Transfer ownership: do NOT CFRelease here.
        return keyId;
    }

    private static IntPtr? TryCreateKey(bool useSecureEnclave)
    {
        var lease = new List<IntPtr>();
        try
        {
            var @params = AppleCF.MakeKeyGenParams(useSecureEnclave, lease);
            var key = AppleSecurity.SecKeyCreateRandomKey(@params, out var error);

            if (error != IntPtr.Zero)
            {
                var desc = AppleCF.DescribeCF(error);
                AppleCF.CFRelease(error);
                // Log for diagnostics (don't throw — let the fallback run)
                System.Diagnostics.Debug.WriteLine(
                    $"[AppleAttest] SecKeyCreateRandomKey failed (SE={useSecureEnclave}): {desc}");
                return null;
            }

            if (key == IntPtr.Zero)
                return null;

            return key;
        }
        catch (DllNotFoundException ex)
        {
            throw new NativeLibraryException("Security.framework", ex);
        }
        finally
        {
            foreach (var p in lease) AppleCF.CFRelease(p);
        }
    }

    private static string DeriveKeyId(IntPtr privateKey)
    {
        var pubKey = AppleSecurity.SecKeyCopyPublicKey(privateKey);
        if (pubKey == IntPtr.Zero)
            throw new AttestationException("SecKeyCopyPublicKey returned null.");

        try
        {
            var pubData = AppleSecurity.SecKeyCopyExternalRepresentation(pubKey, out var err);
            if (err != IntPtr.Zero) AppleCF.CFRelease(err);
            if (pubData == IntPtr.Zero)
                throw new AttestationException("SecKeyCopyExternalRepresentation returned null.");

            try
            {
                var bytes = AppleCF.CFDataToBytes(pubData);
                return Convert.ToHexString(SHA256.HashData(bytes));
            }
            finally { AppleCF.CFRelease(pubData); }
        }
        finally { AppleCF.CFRelease(pubKey); }
    }

    private static byte[] BuildAttestationObject(IntPtr privateKey, byte[] digest)
    {
        // Sign the digest
        var algCF = AppleCF.MakeCFString(EcdsaDigestAlgorithm);
        var dataCF = AppleCF.MakeCFData(digest);

        IntPtr signatureCF;
        try
        {
            signatureCF = AppleSecurity.SecKeyCreateSignature(privateKey, algCF, dataCF, out var signErr);
            if (signErr != IntPtr.Zero) AppleCF.CFRelease(signErr);
        }
        finally
        {
            AppleCF.CFRelease(algCF);
            AppleCF.CFRelease(dataCF);
        }

        if (signatureCF == IntPtr.Zero)
            throw new AttestationException("SecKeyCreateSignature returned null. " +
                "Verify the key supports ECDSA signing.");

        byte[] signature;
        try { signature = AppleCF.CFDataToBytes(signatureCF); }
        finally { AppleCF.CFRelease(signatureCF); }

        // Extract public key (X9.63 uncompressed: 0x04 ‖ X ‖ Y, 65 bytes for P-256)
        var pubKey = AppleSecurity.SecKeyCopyPublicKey(privateKey);
        if (pubKey == IntPtr.Zero)
            throw new AttestationException("SecKeyCopyPublicKey returned null while building attestation.");

        byte[] pubKeyBytes;
        try
        {
            var pubData = AppleSecurity.SecKeyCopyExternalRepresentation(pubKey, out var pubErr);
            if (pubErr != IntPtr.Zero) AppleCF.CFRelease(pubErr);
            if (pubData == IntPtr.Zero)
                throw new AttestationException("SecKeyCopyExternalRepresentation returned null.");
            try { pubKeyBytes = AppleCF.CFDataToBytes(pubData); }
            finally { AppleCF.CFRelease(pubData); }
        }
        finally { AppleCF.CFRelease(pubKey); }

        // Attestation object layout:
        //   [4 bytes LE: sig length][DER ECDSA signature][X9.63 EC public key]
        var result = new byte[4 + signature.Length + pubKeyBytes.Length];
        BitConverter.TryWriteBytes(result.AsSpan(0, 4), signature.Length);
        signature.CopyTo(result, 4);
        pubKeyBytes.CopyTo(result, 4 + signature.Length);
        return result;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static void GuardPlatform()
    {
        if (!OperatingSystem.IsMacOS() && !OperatingSystem.IsIOS())
            throw new PlatformNotSupportedException(
                "SecurityFrameworkAppleAttestInterop requires macOS 10.12+ or iOS 10+.");
    }

    /// <summary>
    /// Parses an attestation object produced by <see cref="AttestKeyAsync"/> and verifies
    /// the ECDSA signature using .NET's managed crypto stack.
    /// Returns <c>true</c> if the signature is valid.
    /// </summary>
    public static bool VerifyAttestationObject(byte[] attestationObject, byte[] originalDigest)
    {
        if (attestationObject is null || attestationObject.Length < 4)
            throw new ArgumentException("Attestation object is too short.", nameof(attestationObject));

        int sigLen = BitConverter.ToInt32(attestationObject, 0);
        if (sigLen <= 0 || 4 + sigLen >= attestationObject.Length)
            throw new ArgumentException($"Invalid sigLen={sigLen} in attestation object.", nameof(attestationObject));

        var signature = attestationObject.AsSpan(4, sigLen);
        var pubKeyBytes = attestationObject.AsSpan(4 + sigLen);

        if (pubKeyBytes.Length != 65 || pubKeyBytes[0] != 0x04)
            throw new ArgumentException(
                $"Unexpected public key format (expected 65-byte uncompressed P-256, got {pubKeyBytes.Length} bytes).",
                nameof(attestationObject));

        var ecParams = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = pubKeyBytes.Slice(1, 32).ToArray(),
                Y = pubKeyBytes.Slice(33, 32).ToArray()
            }
        };
        using var ecdsa = ECDsa.Create(ecParams);
        return ecdsa.VerifyHash(originalDigest, signature.ToArray(), DSASignatureFormat.Rfc3279DerSequence);
    }

    // ── IDisposable ───────────────────────────────────────────────────────────

    public void Dispose()
    {
        foreach (var (_, key) in _keys)
            if (key != IntPtr.Zero)
                AppleCF.CFRelease(key);
        _keys.Clear();
    }
}
