namespace OpenCertServer.Attestation;

/// <summary>
/// Base exception for all attestation failures.
/// </summary>
public class AttestationException : Exception
{
    public int ErrorCode { get; }
    public string? VendorErrorName { get; }

    public AttestationException(string message, int errorCode = -1, string? vendorErrorName = null, Exception? inner = null)
        : base(message, inner)
    {
        ErrorCode = errorCode;
        VendorErrorName = vendorErrorName;
    }
}

/// <summary>
/// Thrown when a required native vendor library (e.g. libsgx_dcap_ql, amd_snp_driver) cannot be loaded.
/// This normally means the process is running on unsupported hardware or the RID-specific
/// NuGet native package has not been deployed.
/// </summary>
public sealed class NativeLibraryException : AttestationException
{
    public string LibraryName { get; }

    public NativeLibraryException(string libraryName, Exception? inner = null)
        : base($"Native attestation library '{libraryName}' could not be loaded. Ensure the platform-specific package is deployed and this process is running on compatible hardware.", inner: inner)
    {
        LibraryName = libraryName;
    }
}

/// <summary>
/// Thrown when a vendor API endpoint (PCCS, VPS, Apple AppAttest) returns an error response.
/// </summary>
public sealed class VendorApiException : AttestationException
{
    public int HttpStatusCode { get; }
    public string Vendor { get; }
    public Uri? Endpoint { get; }

    public VendorApiException(string vendor, Uri? endpoint, int httpStatusCode, string message, Exception? inner = null)
        : base(message, httpStatusCode, inner: inner)
    {
        HttpStatusCode = httpStatusCode;
        Vendor = vendor;
        Endpoint = endpoint;
    }
}

/// <summary>
/// Thrown when the certificate trust chain validation fails (e.g. untrusted root, revoked, expired).
/// </summary>
public sealed class CertificateValidationException : AttestationException
{
    public string Vendor { get; }

    public CertificateValidationException(string vendor, string reason, Exception? inner = null)
        : base(reason, inner: inner)
    {
        Vendor = vendor;
    }
}

/// <summary>
/// SGX-specific DCAP error codes mapped from libsgx_dcap_ql.
/// </summary>
public static class SgxErrorCodes
{
    public const int Success = 0x00000000;
    public const int Unexpected = 0x00000001;
    public const int OutOfMemory = 0x00000005;
    public const int InvalidParameter = 0x00000007;
    public const int DeviceBusy = 0x0000400C;
    public const int NetworkFailure = 0x0000E002;
    public const int NoPlatformCertData = 0x0000E009;

    public static string GetName(int code) => code switch
    {
        Success => "SGX_SUCCESS",
        Unexpected => "SGX_ERROR_UNEXPECTED",
        OutOfMemory => "SGX_ERROR_OUT_OF_MEMORY",
        InvalidParameter => "SGX_ERROR_INVALID_PARAMETER",
        DeviceBusy => "SGX_ERROR_DEVICE_BUSY",
        NetworkFailure => "SGX_QLOGE_NETWORK_FAILURE",
        NoPlatformCertData => "SGX_QLOGE_NO_PLATFORM_CERT_DATA",
        _ => $"UNKNOWN_SGX_ERROR_0x{code:X8}"
    };
}

/// <summary>
/// AMD SEV-SNP error codes.
/// </summary>
public static class AmdSnpErrorCodes
{
    public const int Success = 0;
    public const int InvalidParameter = 1;
    public const int NotSupported = 2;
    public const int HardwareBusy = 3;
    public const int PermissionDenied = 4;
    public const int OutOfMemory = 5;

    public static string GetName(int code) => code switch
    {
        Success => "SNP_SUCCESS",
        InvalidParameter => "SNP_ERROR_INVALID_PARAMETER",
        NotSupported => "SNP_ERROR_NOT_SUPPORTED",
        HardwareBusy => "SNP_ERROR_HARDWARE_BUSY",
        PermissionDenied => "SNP_ERROR_PERMISSION_DENIED",
        OutOfMemory => "SNP_ERROR_OUT_OF_MEMORY",
        _ => $"UNKNOWN_SNP_ERROR_{code}"
    };
}
