using System.Runtime.InteropServices;

namespace OpenCertServer.Attestation.Native;

/// <summary>
/// Production implementation of <see cref="ISgxNativeInterop"/> that calls into
/// <c>libsgx_dcap_ql</c>. Only functional on Linux x64 with SGX DCAP libraries installed.
/// </summary>
public sealed class SgxNativeInterop : ISgxNativeInterop
{
    private const string RequiredLibrary = "sgx_dcap_ql";

    public int GetPckId(out IntPtr pckIdPtr, ref uint size, ref uint tcbLevel)
    {
        GuardPlatform();
        try
        {
            return IntelSgxNative.sgx_get_pck_id(out pckIdPtr, ref size, ref tcbLevel);
        }
        catch (DllNotFoundException ex)
        {
            throw new NativeLibraryException(RequiredLibrary, ex);
        }
    }

    public int CreateQuote(IntPtr quoteBuffer, ref uint quoteSize, ReadOnlySpan<byte> nonce)
    {
        GuardPlatform();
        try
        {
            return IntelSgxNative.sgx_create_quote(quoteBuffer, ref quoteSize, nonce);
        }
        catch (DllNotFoundException ex)
        {
            throw new NativeLibraryException(RequiredLibrary, ex);
        }
    }

    private static void GuardPlatform()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            throw new PlatformNotSupportedException(
                "Intel SGX attestation requires Linux x64 with the SGX DCAP driver and libsgx_dcap_ql installed.");
        }
    }
}
