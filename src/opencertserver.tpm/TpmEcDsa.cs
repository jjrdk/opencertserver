namespace OpenCertServer.Tpm;

using System;
using System.Security.Cryptography;

/// <summary>
/// An <see cref="ECDsa"/> implementation whose private key lives permanently in the TPM.
/// This is a drop-in replacement for software ECDsa keys in <c>CaProfile.PrivateKey</c>
/// and all call-sites that switch on <c>RSA / ECDsa</c> — no caller changes are required.
/// </summary>
public sealed class TpmEcDsa : ECDsa
{
    // P-256 coordinate size in bytes
    private const int CoordSize = 32;

    private readonly ITpmKeyProvider _provider;
    private readonly uint _handle;
    private ECParameters? _cachedPublicParams;

    /// <summary>
    /// Creates a new <see cref="TpmEcDsa"/> wrapper for the key at <paramref name="persistentHandle"/>.
    /// The key must already exist (call <see cref="ITpmKeyProvider.EnsureEcDsaKey"/> first).
    /// </summary>
    public TpmEcDsa(ITpmKeyProvider provider, uint persistentHandle)
    {
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
        _handle = persistentHandle;

        // LegalKeySizes must be initialised before calling set_KeySize (the setter iterates
        // over LegalKeySizes; without this the base AsymmetricAlgorithm.LegalKeySizesValue
        // field is null and the setter throws NullReferenceException).
        LegalKeySizesValue = [new KeySizes(CoordSize * 8, CoordSize * 8, 0)];
        KeySize = CoordSize * 8; // 256 for P-256
    }

    // -----------------------------------------------------------------
    // Abstract ECDsa members
    // -----------------------------------------------------------------

    /// <inheritdoc />
    public override ECParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters)
        {
            throw new CryptographicException(
                "The private key of a TPM-backed ECDsa key cannot be exported.");
        }

        return _cachedPublicParams ??= _provider.ExportEcDsaPublicParameters(_handle);
    }

    /// <inheritdoc />
    public override void ImportParameters(ECParameters parameters)
        => throw new NotSupportedException("TPM-backed ECDsa keys do not support ImportParameters.");

    /// <inheritdoc />
    public override void GenerateKey(ECCurve curve)
        => throw new NotSupportedException("TPM-backed ECDsa keys are provisioned via ITpmKeyProvider.EnsureEcDsaKey.");

    // -----------------------------------------------------------------
    // HashData — software hashing, TPM receives the pre-computed hash
    // -----------------------------------------------------------------

    /// <inheritdoc />
    protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
    {
        using var ih = IncrementalHash.CreateHash(hashAlgorithm);
        ih.AppendData(data, offset, count);
        return ih.GetHashAndReset();
    }

    /// <inheritdoc />
    protected override byte[] HashData(System.IO.Stream data, HashAlgorithmName hashAlgorithm)
    {
        using var ih = IncrementalHash.CreateHash(hashAlgorithm);
        var buffer = new byte[4096];
        int read;
        while ((read = data.Read(buffer, 0, buffer.Length)) > 0)
        {
            ih.AppendData(buffer, 0, read);
        }

        return ih.GetHashAndReset();
    }

    // -----------------------------------------------------------------
    // Signing — delegates to TPM; result is IEEE P1363 (R‖S)
    // -----------------------------------------------------------------

    /// <inheritdoc />
    public override byte[] SignHash(byte[] hash)
        => _provider.SignEcDsa(_handle, hash, InferHashAlgorithm(hash));

    // -----------------------------------------------------------------
    // Verification — software path using the exported public key
    // -----------------------------------------------------------------

    /// <inheritdoc />
    public override bool VerifyHash(byte[] hash, byte[] signature)
    {
        using var softEcdsa = ECDsa.Create(ExportParameters(false));
        return softEcdsa.VerifyHash(hash, signature);
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /// <summary>
    /// Infers the <see cref="HashAlgorithmName"/> from the byte length of a pre-computed hash.
    /// </summary>
    private static HashAlgorithmName InferHashAlgorithm(byte[] hash) =>
        hash.Length switch
        {
            32 => HashAlgorithmName.SHA256,
            48 => HashAlgorithmName.SHA384,
            64 => HashAlgorithmName.SHA512,
            20 => HashAlgorithmName.SHA1,
            _ => HashAlgorithmName.SHA256
        };
}

