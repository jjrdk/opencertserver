namespace OpenCertServer.Ca.Utils.X509Extensions;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

/// <summary>
/// Defines extension methods for <see cref="X509Certificate2"/>.
/// </summary>
public static partial class X509CertificatesExtensions
{
    private const string SubjectAlternateNameOid = "2.5.29.17";

    extension(X509Certificate2 cert)
    {
        /// <summary>
        /// Gets the subject alternative names from the certificate.
        /// </summary>
        /// <returns>A <see cref="HashSet{T}"/> of SANs.</returns>
        public HashSet<string> GetSubjectAlternativeNames()
        {
            ArgumentNullException.ThrowIfNull(cert);
            var subjectAlternativeName = cert.Extensions
                .Where(n => n.Oid?.Value == SubjectAlternateNameOid)
                .Select(n => new AsnEncodedData(n.Oid, n.RawData))
                .Select(n => n.Format(true));

            return subjectAlternativeName.SelectMany(x => string.IsNullOrWhiteSpace(x)
                    ? []
                    : x.Split(["\r\n", "\r", "\n"], StringSplitOptions.RemoveEmptyEntries)
                        .Select(n => DnsNameRegex().Match(n))
                        .Where(r => r.Success && !string.IsNullOrWhiteSpace(r.Groups[1].Value))
                        .Select(r => r.Groups[1].Value))
                .ToHashSet();
        }

        /// <summary>
        /// Converts the certificate and its issuers to a PEM chain.
        /// </summary>
        /// <param name="issuers">The certificate issuers.</param>
        /// <returns>A PEM encoded string of certificates.</returns>
        public string ToPemChain(X509Certificate2Collection issuers)
        {
            return $"{cert.ExportCertificatePem()}\n{string.Join('\n', issuers.Select(x => x.ExportCertificatePem()))}";
        }

        /// <summary>
        /// Writes the certificate as a PFX to the output stream.
        /// </summary>
        /// <param name="outputStream">The <see cref="Stream"/> to write to.</param>
        /// <param name="cancellation">The <see cref="CancellationToken"/> for the async operation.</param>
        public async Task WritePfx(Stream outputStream, CancellationToken cancellation = default)
        {
            var buffer = cert.Export(X509ContentType.Pfx);
            await outputStream.WriteAsync(buffer.AsMemory(), cancellation).ConfigureAwait(false);
        }
    }

    [GeneratedRegex(@"^DNS Name=(.+)", RegexOptions.Compiled | RegexOptions.CultureInvariant)]
    private static partial Regex DnsNameRegex();
}
