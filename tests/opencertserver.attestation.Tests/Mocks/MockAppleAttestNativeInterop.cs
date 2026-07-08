using OpenCertServer.Attestation.Native;

namespace OpenCertServer.Attestation.Tests.Mocks;

/// <summary>
/// Configurable mock Apple native interop for unit tests.
/// </summary>
public sealed class MockAppleAttestNativeInterop : IAppleAttestNativeInterop
{
    public string KeyIdToReturn { get; set; } = "test-key-id-abc123";
    public byte[] AttestationObjectToReturn { get; set; } = new byte[512];
    public bool ShouldThrowOnGenerateKey { get; set; }
    public bool ShouldThrowOnAttestKey { get; set; }
    public Exception? ExceptionToThrow { get; set; }

    public Task<string> GenerateKeyAsync()
    {
        if (ShouldThrowOnGenerateKey)
            throw ExceptionToThrow ?? new AttestationException("Mock: key generation failed", -1);
        return Task.FromResult(KeyIdToReturn);
    }

    public Task<byte[]> AttestKeyAsync(string keyId, ReadOnlyMemory<byte> clientDataHash)
    {
        if (ShouldThrowOnAttestKey)
            throw ExceptionToThrow ?? new AttestationException("Mock: key attestation failed", -1);
        return Task.FromResult(AttestationObjectToReturn);
    }
}

/// <summary>
/// Mock that always throws <see cref="NativeLibraryException"/> (simulates missing shim library).
/// </summary>
public sealed class MissingAppleAttestNativeInterop : IAppleAttestNativeInterop
{
    public Task<string> GenerateKeyAsync()
        => throw new NativeLibraryException("opencertserver_apple_attest", new DllNotFoundException("opencertserver_apple_attest"));

    public Task<byte[]> AttestKeyAsync(string keyId, ReadOnlyMemory<byte> clientDataHash)
        => throw new NativeLibraryException("opencertserver_apple_attest", new DllNotFoundException("opencertserver_apple_attest"));
}
