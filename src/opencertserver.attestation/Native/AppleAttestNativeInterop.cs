using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace OpenCertServer.Attestation.Native;

/// <summary>
/// Native bindings for the Apple DeviceCheck/AppAttest framework shim.
/// The shim (<c>libopencertserver_apple_attest</c>) is a thin C wrapper around the async
/// Objective-C DCAppAttestService API, distributed via the
/// <c>OpenCertServer.Apple.Native</c> RID-based NuGet package per spec section 3.2.
/// </summary>
internal static partial class AppleAttestShim
{
    private const string ShimLibrary = "opencertserver_apple_attest";

    /// <summary>
    /// Generates a Secure Enclave-backed key via DCAppAttestService.generateKey.
    /// On success, <paramref name="keyIdBuffer"/> is filled with the UTF-8 key identifier.
    /// Returns 0 on success; negative errno on failure.
    /// </summary>
    [LibraryImport(ShimLibrary, EntryPoint = "oce_appattest_generate_key")]
    internal static partial int GenerateKey(
        Span<byte> keyIdBuffer,
        ref int keyIdLength);

    /// <summary>
    /// Attests a key via DCAppAttestService.attestKey(_:clientDataHash:completionHandler:).
    /// <paramref name="clientDataHash"/> must be exactly 32 bytes (SHA-256).
    /// On success, <paramref name="attestationBuffer"/> is filled with the CBOR attestation object.
    /// Returns 0 on success.
    /// </summary>
    [LibraryImport(ShimLibrary, EntryPoint = "oce_appattest_attest_key")]
    internal static partial int AttestKey(
        [MarshalAs(UnmanagedType.LPStr)] string keyId,
        ReadOnlySpan<byte> clientDataHash,
        Span<byte> attestationBuffer,
        ref int attestationLength);
}

/// <summary>
/// Production implementation of <see cref="IAppleAttestNativeInterop"/> that delegates to
/// the Apple DeviceCheck framework via a thin native shim.
/// Only functional on macOS 11+ / iOS 14+ with the App Attest entitlement.
/// </summary>
public sealed class AppleAttestNativeInterop : IAppleAttestNativeInterop
{
    private const string ShimLibrary = "opencertserver_apple_attest";
    private const int MaxKeyIdLength = 256;
    private const int MaxAttestationLength = 8192;

    public async Task<string> GenerateKeyAsync()
    {
        GuardPlatform();
        return await Task.Run(() =>
        {
            byte[] keyIdBuffer = new byte[MaxKeyIdLength];
            int keyIdLength = keyIdBuffer.Length;
            try
            {
                int result = AppleAttestShim.GenerateKey(keyIdBuffer.AsSpan(), ref keyIdLength);
                if (result != 0)
                {
                    throw new AttestationException(
                        $"App Attest key generation failed. Native error code: {result}",
                        errorCode: result,
                        vendorErrorName: "APPATTEST_KEY_GENERATION_ERROR");
                }
                return System.Text.Encoding.UTF8.GetString(keyIdBuffer, 0, keyIdLength);
            }
            catch (DllNotFoundException ex)
            {
                throw new NativeLibraryException(ShimLibrary, ex);
            }
        });
    }

    public async Task<byte[]> AttestKeyAsync(string keyId, ReadOnlyMemory<byte> clientDataHash)
    {
        GuardPlatform();
        if (clientDataHash.Length != SHA256.HashSizeInBytes)
        {
            throw new ArgumentException(
                $"clientDataHash must be exactly {SHA256.HashSizeInBytes} bytes (SHA-256).",
                nameof(clientDataHash));
        }

        return await Task.Run(() =>
        {
            byte[] attestBuffer = new byte[MaxAttestationLength];
            int attestLength = attestBuffer.Length;
            try
            {
                int result = AppleAttestShim.AttestKey(keyId, clientDataHash.Span, attestBuffer.AsSpan(), ref attestLength);
                if (result != 0)
                {
                    throw new AttestationException(
                        $"App Attest key attestation failed for keyId '{keyId}'. Native error code: {result}",
                        errorCode: result,
                        vendorErrorName: "APPATTEST_ATTEST_KEY_ERROR");
                }
                return attestBuffer[..attestLength];
            }
            catch (DllNotFoundException ex)
            {
                throw new NativeLibraryException(ShimLibrary, ex);
            }
        });
    }

    private static void GuardPlatform()
    {
        if (!OperatingSystem.IsMacOS() && !OperatingSystem.IsIOS())
        {
            throw new PlatformNotSupportedException(
                "Apple App Attest native key generation requires macOS 11+ or iOS 14+ with the " +
                "com.apple.developer.devicecheck.appattest-environment entitlement.");
        }
    }
}
