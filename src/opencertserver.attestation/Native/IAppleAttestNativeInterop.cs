namespace OpenCertServer.Attestation.Native;

/// <summary>
/// Abstraction over Apple Secure Enclave / App Attest native calls.
/// When running on an Apple device (macOS/iOS), the implementation delegates to
/// DCAppAttestService via the native DeviceCheck framework shim.
/// On non-Apple platforms, all methods throw <see cref="PlatformNotSupportedException"/>.
/// </summary>
public interface IAppleAttestNativeInterop
{
    /// <summary>
    /// Generates a hardware-backed key pair in the Secure Enclave and returns its key identifier.
    /// Requires macOS 11+ / iOS 14+ with the App Attest entitlement.
    /// </summary>
    Task<string> GenerateKeyAsync();

    /// <summary>
    /// Produces an App Attest attestation object for <paramref name="keyId"/> bound to
    /// <paramref name="clientDataHash"/> (SHA-256 of the challenge).
    /// </summary>
    Task<byte[]> AttestKeyAsync(string keyId, ReadOnlyMemory<byte> clientDataHash);
}
