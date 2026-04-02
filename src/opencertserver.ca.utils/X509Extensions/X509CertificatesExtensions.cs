namespace OpenCertServer.Ca.Utils.X509Extensions;

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using OpenCertServer.Ca.Utils.X509;

/// <summary>
/// Defines extension methods for <see cref="X509Certificate2"/>.
/// </summary>
public static partial class X509CertificatesExtensions
{
    /// <summary>
    /// Represents the member.
    /// </summary>
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
        /// Gets the DNS subject alternative names from the certificate.
        /// </summary>
        /// <returns>The DNS SAN values.</returns>
        public IReadOnlyList<string> GetSubjectAlternativeDnsNames()
        {
            ArgumentNullException.ThrowIfNull(cert);
            return GetSubjectAlternativeGeneralNames(cert)
                .Where(name => name.Type == GeneralName.GeneralNameType.DnsName)
                .Select(name => name.Value)
                .OfType<AsnString>()
                .Select(name => name.Value)
                .Where(name => !string.IsNullOrWhiteSpace(name))
                .ToArray();
        }

        /// <summary>
        /// Gets the IP subject alternative names from the certificate.
        /// </summary>
        /// <returns>The IP SAN values.</returns>
        public IReadOnlyList<IPAddress> GetSubjectAlternativeIpAddresses()
        {
            ArgumentNullException.ThrowIfNull(cert);
            return GetSubjectAlternativeGeneralNames(cert)
                .Where(name => name.Type == GeneralName.GeneralNameType.IpAddress)
                .Select(name => name.Value)
                .OfType<AsnOctetString>()
                .Select(name => name.Value)
                .Where(value => value.Length is 4 or 16)
                .Select(value => new IPAddress(value))
                .ToArray();
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

    /// <summary>
    /// Executes the DnsNameRegex operation.
    /// </summary>
    [GeneratedRegex(@"^DNS Name=(.+)", RegexOptions.Compiled | RegexOptions.CultureInvariant)]
    private static partial Regex DnsNameRegex();

    private static IEnumerable<GeneralName> GetSubjectAlternativeGeneralNames(X509Certificate2 cert)
    {
        return cert.Extensions
            .Where(ext => ext.Oid?.Value == SubjectAlternateNameOid)
            .SelectMany(ext => new GeneralNames(ext.RawData).Names);
    }
}
