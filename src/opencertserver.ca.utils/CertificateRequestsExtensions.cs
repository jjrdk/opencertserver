namespace OpenCertServer.Ca.Utils;

using System;
using System.Security.Cryptography.X509Certificates;
using System.Text;

/// <summary>
/// Defines extension methods for handling certificate requests.
/// </summary>
public static class CertificateRequestsExtensions
{
    private const string CertificateRequestHeader = "-----BEGIN CERTIFICATE REQUEST-----";
    private const string CertificateRequestFooter = "-----END CERTIFICATE REQUEST-----";
    private const string Pkcs12Header = "-----BEGIN PKCS12-----";
    private const string Pkcs12Footer = "-----END PKCS12-----";
    private const string Pkcs7Header = "-----BEGIN PKCS7-----";
    private const string Pkcs7Footer = "-----END PKCS7-----";

    /// <summary>
    /// Converts the given <see cref="CertificateRequest"/> to a PKCS#10 formatted string.
    /// </summary>
    /// <param name="request">The CSR to convert.</param>
    /// <returns>A PKCS#10 formatted string.</returns>
    public static string ToPkcs10(this CertificateRequest request)
    {
        var bytes = request.CreateSigningRequest();
        var builder = new StringBuilder();
        builder.Append(CertificateRequestHeader)
            .Append('\n')
            .Append(Convert.ToBase64String(bytes, Base64FormattingOptions.InsertLineBreaks))
            .Append('\n')
            .Append(CertificateRequestFooter);
        return builder.ToString();
    }

    extension(string pkcs12)
    {
        public byte[] FromPkcs12()
        {
            var value = pkcs12.Replace(Pkcs12Header, "")
                .Replace(Pkcs12Footer, "")
                .Replace("\r", "")
                .Replace("\n", "")
                .Trim();
            return Convert.FromBase64String(value);
        }

        public byte[] FromPkcs7()
        {
            var value = pkcs12.Replace(Pkcs7Header, "")
                .Replace(Pkcs7Footer, "")
                .Replace("\r", "")
                .Replace("\n", "")
                .Trim();
            return Convert.FromBase64String(value);
        }
    }
}
