using OpenCertServer.Attestation.Native;

namespace OpenCertServer.Attestation.Tests.Mocks;

/// <summary>
/// Configurable mock SGX native interop for unit tests.
/// </summary>
public sealed class MockSgxNativeInterop : ISgxNativeInterop
{
    public int GetPckIdReturnCode { get; set; } = SgxErrorCodes.Success;
    public byte[] PckIdBytes { get; set; } = [0xA1, 0xB2, 0xC3, 0xD4];

    public int GetPckId(out IntPtr pckIdPtr, ref uint size, ref uint tcbLevel)
    {
        if (GetPckIdReturnCode != SgxErrorCodes.Success)
        {
            pckIdPtr = IntPtr.Zero;
            return GetPckIdReturnCode;
        }

        // Allocate unmanaged memory for the ID bytes so the caller can read them.
        pckIdPtr = System.Runtime.InteropServices.Marshal.AllocHGlobal(PckIdBytes.Length);
        System.Runtime.InteropServices.Marshal.Copy(PckIdBytes, 0, pckIdPtr, PckIdBytes.Length);
        size = (uint)PckIdBytes.Length;
        return SgxErrorCodes.Success;
    }

    public int CreateQuoteReturnCode { get; set; } = SgxErrorCodes.Success;
    public byte[] QuoteBytes { get; set; } = new byte[128];

    public int CreateQuote(IntPtr quoteBuffer, ref uint quoteSize, ReadOnlySpan<byte> nonce)
    {
        if (CreateQuoteReturnCode != SgxErrorCodes.Success)
            return CreateQuoteReturnCode;

        if (quoteBuffer == IntPtr.Zero)
        {
            quoteSize = (uint)QuoteBytes.Length;
            return SgxErrorCodes.Success;
        }

        System.Runtime.InteropServices.Marshal.Copy(QuoteBytes, 0, quoteBuffer, Math.Min(QuoteBytes.Length, (int)quoteSize));
        return SgxErrorCodes.Success;
    }
}

/// <summary>
/// Mock that always throws <see cref="NativeLibraryException"/> (simulates missing native library).
/// </summary>
public sealed class MissingSgxNativeInterop : ISgxNativeInterop
{
    public int GetPckId(out IntPtr pckIdPtr, ref uint size, ref uint tcbLevel)
    {
        pckIdPtr = IntPtr.Zero;
        throw new NativeLibraryException("sgx_dcap_ql", new DllNotFoundException("sgx_dcap_ql"));
    }

    public int CreateQuote(IntPtr quoteBuffer, ref uint quoteSize, ReadOnlySpan<byte> nonce)
        => throw new NativeLibraryException("sgx_dcap_ql", new DllNotFoundException("sgx_dcap_ql"));
}
