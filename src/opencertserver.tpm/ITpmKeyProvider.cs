namespace OpenCertServer.Tpm;

using System;
using System.Security.Cryptography;

/// <summary>
/// Abstracts all communication with the TPM hardware or simulator.
/// This is the sole swap seam between the TPM-backed crypto layer and any particular
/// TPM communication library (currently <see cref="TssTpmKeyProvider"/> backed by
/// Microsoft.TSS; a Pkcs11Interop-based implementation can replace it by implementing
/// this interface without changing <see cref="TpmRsa"/>, <see cref="TpmEcDsa"/>,
/// <see cref="TpmCaProfileFactory"/> or any DI registration code).
/// </summary>
public interface ITpmKeyProvider : IDisposable
{
    /// <summary>
    /// Ensures an RSA-2048 signing key exists at the given persistent handle.
    /// If the handle is already populated the call is a no-op.
    /// </summary>
    void EnsureRsaKey(uint persistentHandle);

    /// <summary>
    /// Ensures a P-256 ECDsa signing key exists at the given persistent handle.
    /// If the handle is already populated the call is a no-op.
    /// </summary>
    void EnsureEcDsaKey(uint persistentHandle);

    /// <summary>
    /// Signs a pre-computed <paramref name="hash"/> using the RSA key at
    /// <paramref name="persistentHandle"/> and returns the raw RSA signature bytes.
    /// </summary>
    byte[] SignRsa(uint persistentHandle, byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding);

    /// <summary>
    /// Signs a pre-computed <paramref name="hash"/> using the ECDsa key at
    /// <paramref name="persistentHandle"/> and returns the signature in IEEE P1363
    /// format (raw R‖S, each value zero-padded to 32 bytes for P-256).
    /// </summary>
    byte[] SignEcDsa(uint persistentHandle, byte[] hash, HashAlgorithmName hashAlgorithm);

    /// <summary>
    /// Reads the public portion of the RSA key at <paramref name="persistentHandle"/>
    /// and returns it as <see cref="RSAParameters"/> (no private fields populated).
    /// </summary>
    RSAParameters ExportRsaPublicParameters(uint persistentHandle);

    /// <summary>
    /// Reads the public portion of the ECDsa key at <paramref name="persistentHandle"/>
    /// and returns it as <see cref="ECParameters"/> (no private fields populated).
    /// </summary>
    ECParameters ExportEcDsaPublicParameters(uint persistentHandle);
}

