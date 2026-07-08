namespace OpenCertServer.Attestation.Native;

/// <summary>
/// Abstraction over Intel SGX DCAP native calls. Inject this interface to enable
/// unit testing without real SGX hardware or the native library present.
/// </summary>
public interface ISgxNativeInterop
{
    /// <summary>
    /// Retrieves the PCK ID from the SGX platform.
    /// Returns 0 on success; non-zero SGX error code on failure.
    /// </summary>
    int GetPckId(out IntPtr pckIdPtr, ref uint size, ref uint tcbLevel);

    /// <summary>
    /// Generates (or sizes then fills) an SGX DCAP quote.
    /// Pass <see cref="IntPtr.Zero"/> for <paramref name="quoteBuffer"/> to query the required size.
    /// Returns 0 on success.
    /// </summary>
    int CreateQuote(IntPtr quoteBuffer, ref uint quoteSize, ReadOnlySpan<byte> nonce);
}
