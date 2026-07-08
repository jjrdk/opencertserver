using System.Runtime.InteropServices;

namespace OpenCertServer.Attestation.Native;

/// <summary>
/// Production implementation of <see cref="IAmdSnpNativeInterop"/> that calls into
/// <c>amd_snp_driver</c>. Only functional on Linux x64 AMD SEV-SNP enabled VMs.
/// </summary>
public sealed class AmdSnpNativeInterop : IAmdSnpNativeInterop
{
    private const string RequiredLibrary = "amd_snp_driver";

    public int GetVcekChipId(out IntPtr chipIdPtr, ref uint size)
    {
        GuardPlatform();
        try
        {
            return AmdSnpNative.snp_get_vcek_chipid(out chipIdPtr, ref size);
        }
        catch (DllNotFoundException ex)
        {
            throw new NativeLibraryException(RequiredLibrary, ex);
        }
    }

    public int GenerateReport(IntPtr reportBuffer, ref uint reportSize, ReadOnlySpan<byte> nonce)
    {
        GuardPlatform();
        try
        {
            return AmdSnpNative.snp_generate_report(reportBuffer, ref reportSize, nonce);
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
                "AMD SEV-SNP attestation requires Linux x64 on an AMD SEV-SNP enabled instance.");
        }
    }
}
