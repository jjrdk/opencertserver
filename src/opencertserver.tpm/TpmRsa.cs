namespace OpenCertServer.Tpm;

using System;
using System.Security.Cryptography;

/// <summary>
/// An <see cref="RSA"/> implementation whose private key lives permanently in the TPM.
/// This class is a drop-in replacement for any software <see cref="RSA"/> instance used in
/// <c>CaProfile.PrivateKey</c> and all call-sites that switch on <c>RSA / ECDsa</c> (e.g.
/// <c>X509SignatureGenerator.CreateForRSA</c>) — no caller changes are required.
/// </summary>
public sealed class TpmRsa : RSA
{
    private readonly ITpmKeyProvider _provider;
    private readonly uint _handle;
    private RSAParameters? _cachedPublicParams;

    /// <summary>
    /// Creates a new <see cref="TpmRsa"/> wrapper for the key at <paramref name="persistentHandle"/>.
    /// The key must already exist (call <see cref="ITpmKeyProvider.EnsureRsaKey"/> first).
    /// </summary>
    public TpmRsa(ITpmKeyProvider provider, uint persistentHandle)
    {
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
        _handle = persistentHandle;

        // Populate KeySize from the actual key in the TPM.
        // LegalKeySizes must be initialised before calling set_KeySize (the setter iterates
        // over LegalKeySizes; without this the base AsymmetricAlgorithm.LegalKeySizesValue
        // field is null and the setter throws NullReferenceException).
        var pub = _provider.ExportRsaPublicParameters(_handle);
        var bits = (pub.Modulus?.Length ?? 256) * 8;
        LegalKeySizesValue = [new KeySizes(bits, bits, 0)];
        KeySize = bits;
    }

    // -----------------------------------------------------------------
    // Abstract RSA members
    // -----------------------------------------------------------------

    /// <inheritdoc />
    public override RSAParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters)
        {
            throw new CryptographicException(
                "The private key of a TPM-backed RSA key cannot be exported.");
        }

        return _cachedPublicParams ??= _provider.ExportRsaPublicParameters(_handle);
    }

    /// <inheritdoc />
    public override void ImportParameters(RSAParameters parameters)
        => throw new NotSupportedException("TPM-backed RSA keys do not support ImportParameters.");

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
    // Signing — delegates to TPM
    // -----------------------------------------------------------------

    /// <inheritdoc />
    public override byte[] SignHash(
        byte[] hash,
        HashAlgorithmName hashAlgorithmName,
        RSASignaturePadding padding)
        => _provider.SignRsa(_handle, hash, hashAlgorithmName, padding);

    // -----------------------------------------------------------------
    // Verification — software path using the exported public key
    // -----------------------------------------------------------------

    /// <inheritdoc />
    public override bool VerifyHash(
        byte[] hash,
        byte[] signature,
        HashAlgorithmName hashAlgorithmName,
        RSASignaturePadding padding)
    {
        using var softRsa = RSA.Create();
        softRsa.ImportParameters(ExportParameters(false));
        return softRsa.VerifyHash(hash, signature, hashAlgorithmName, padding);
    }
}

