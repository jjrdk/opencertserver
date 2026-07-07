using System;
using System.Runtime.InteropServices;

namespace OpenCertServer.Attestation.Native;

/// <summary>
/// Native bindings for Intel SGX DCAP Quote Loader (libsgx_dcap_ql).
/// Using [LibraryImport] for .NET 10 / Native AOT compatibility as per spec.md section 4.1.
/// </summary>
public static partial class IntelSgxNative
{
    private const string LibraryName = "sgx_dcap_ql";

    [LibraryImport(LibraryName)]
    public static partial int sgx_get_pck_id(out IntPtr pck_id, ref uint pck_id_size, ref uint tcb_level);

    [LibraryImport(LibraryName)]
    public static partial int sgx_create_quote(IntPtr p_quote_buffer, ref uint quote_size, ReadOnlySpan<byte> nonce);
}
