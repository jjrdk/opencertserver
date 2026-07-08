namespace OpenCertServer.Attestation.Native;

/// <summary>
/// Abstraction over AMD SEV-SNP native calls.
/// </summary>
public interface IAmdSnpNativeInterop
{
    /// <summary>
    /// Retrieves the VCEK Chip ID from the AMD SEV-SNP platform.
    /// Returns 0 on success.
    /// </summary>
    int GetVcekChipId(out IntPtr chipIdPtr, ref uint size);

    /// <summary>
    /// Generates an AMD SNP attestation report.
    /// Pass <see cref="IntPtr.Zero"/> for <paramref name="reportBuffer"/> to query the required size.
    /// Returns 0 on success.
    /// </summary>
    int GenerateReport(IntPtr reportBuffer, ref uint reportSize, ReadOnlySpan<byte> nonce);
}
