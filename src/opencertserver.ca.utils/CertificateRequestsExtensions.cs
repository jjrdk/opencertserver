using System.Security.Cryptography;

namespace OpenCertServer.Ca.Utils;

using System;
using System.Security.Cryptography.X509Certificates;
using System.Text;

/// <summary>
/// Defines extension methods for handling certificate requests.
/// </summary>
public static class CertificateRequestsExtensions
{
    private const string CertificateRequestHeader = "CERTIFICATE REQUEST";

    /// <summary>
    /// Converts the given <see cref="CertificateRequest"/> to a PKCS#10 formatted string.
    /// </summary>
    /// <param name="request">The CSR to convert.</param>
    /// <returns>A PKCS#10 formatted string.</returns>
    public static string ToPkcs10(this CertificateRequest request)
    {
        var bytes = request.CreateSigningRequest();
        return PemEncoding.WriteString(CertificateRequestHeader, bytes);
    }
}
