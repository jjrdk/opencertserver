using System;
using System.Runtime.InteropServices;

namespace OpenCertServer.Attestation.Native;

/// <summary>
/// Native bindings for AMD SEV-SNP (Secure Nested Paging).
/// Using [LibraryImport] for .NET 10 / Native AOT compatibility as per spec.md section 4.1.
/// </summary>
public static partial class AmdSnpNative
{
    private const string LibraryName = "amd_snp_driver";

    [LibraryImport(LibraryName)]
    public static partial int snp_get_vcek_chipid(out IntPtr chipId, ref uint chipIdSize);

    [LibraryImport(LibraryName)]
    public static partial int snp_generate_report(IntPtr p_report_buffer, ref uint report_size, ReadOnlySpan<byte> nonce);
}
