using OpenCertServer.Attestation.Native;

namespace OpenCertServer.Attestation.Tests.Mocks;

/// <summary>
/// Configurable mock AMD SNP native interop for unit tests.
/// </summary>
public sealed class MockAmdSnpNativeInterop : IAmdSnpNativeInterop
{
    public int GetVcekChipIdReturnCode { get; set; } = AmdSnpErrorCodes.Success;
    public byte[] ChipIdBytes { get; set; } = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02];

    public int GetVcekChipId(out IntPtr chipIdPtr, ref uint size)
    {
        if (GetVcekChipIdReturnCode != AmdSnpErrorCodes.Success)
        {
            chipIdPtr = IntPtr.Zero;
            return GetVcekChipIdReturnCode;
        }

        chipIdPtr = System.Runtime.InteropServices.Marshal.AllocHGlobal(ChipIdBytes.Length);
        System.Runtime.InteropServices.Marshal.Copy(ChipIdBytes, 0, chipIdPtr, ChipIdBytes.Length);
        size = (uint)ChipIdBytes.Length;
        return AmdSnpErrorCodes.Success;
    }

    public int GenerateReportReturnCode { get; set; } = AmdSnpErrorCodes.Success;
    public byte[] ReportBytes { get; set; } = new byte[256];

    public int GenerateReport(IntPtr reportBuffer, ref uint reportSize, ReadOnlySpan<byte> nonce)
    {
        if (GenerateReportReturnCode != AmdSnpErrorCodes.Success)
            return GenerateReportReturnCode;

        if (reportBuffer == IntPtr.Zero)
        {
            reportSize = (uint)ReportBytes.Length;
            return AmdSnpErrorCodes.Success;
        }

        System.Runtime.InteropServices.Marshal.Copy(ReportBytes, 0, reportBuffer, Math.Min(ReportBytes.Length, (int)reportSize));
        return AmdSnpErrorCodes.Success;
    }
}

/// <summary>
/// Mock that always throws <see cref="NativeLibraryException"/> (simulates missing driver).
/// </summary>
public sealed class MissingAmdSnpNativeInterop : IAmdSnpNativeInterop
{
    public int GetVcekChipId(out IntPtr chipIdPtr, ref uint size)
    {
        chipIdPtr = IntPtr.Zero;
        throw new NativeLibraryException("amd_snp_driver", new DllNotFoundException("amd_snp_driver"));
    }

    public int GenerateReport(IntPtr reportBuffer, ref uint reportSize, ReadOnlySpan<byte> nonce)
        => throw new NativeLibraryException("amd_snp_driver", new DllNotFoundException("amd_snp_driver"));
}
