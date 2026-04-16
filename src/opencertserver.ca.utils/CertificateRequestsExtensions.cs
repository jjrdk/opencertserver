using System.Security.Cryptography;

namespace OpenCertServer.Ca.Utils;

using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Defines extension methods for handling certificate requests.
/// </summary>
public static class CertificateRequestsExtensions
{
    /// <param name="request">The CSR to convert.</param>
    extension(CertificateRequest request)
    {
        /// <summary>
        /// Converts the given <see cref="CertificateRequest"/> to a PKCS#10 formatted PEM string.
        /// </summary>
        /// <returns>A PKCS#10 formatted string.</returns>
        public string ToPkcs10Pem()
        {
            const string certificateRequestHeader = "CERTIFICATE REQUEST";
            var bytes = request.CreateSigningRequest();
            return PemEncoding.WriteString(certificateRequestHeader, bytes);
        }

        /// <summary>
        /// Converts the given <see cref="CertificateRequest"/> to a PKCS#10 formatted base64 encoded string.
        /// </summary>
        /// <returns>A PKCS#10 formatted string.</returns>
        public string ToPkcs10Base64()
        {
            return Convert.ToBase64String(request.CreateSigningRequest());
        }
    }
}
