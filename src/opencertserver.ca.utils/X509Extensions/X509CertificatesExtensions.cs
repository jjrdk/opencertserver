using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace OpenCertServer.Ca.Utils.X509Extensions;

public static partial class X509CertificatesExtensions
{
    private const string SubjectAlternateNameOid = "2.5.29.17";

    extension(X509Certificate2 cert)
    {
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

        public string ToPemChain(X509Certificate2Collection issuers)
        {
            return $"{cert.ExportCertificatePem()}\n{string.Join('\n', issuers.Select(x => x.ExportCertificatePem()))}";
        }

        public async Task WritePfx(Stream outputStream, CancellationToken cancellation = default)
        {
            var buffer = cert.Export(X509ContentType.Pfx);
            await outputStream.WriteAsync(buffer.AsMemory(), cancellation).ConfigureAwait(false);
        }
    }

    [GeneratedRegex(@"^DNS Name=(.+)", RegexOptions.Compiled | RegexOptions.CultureInvariant)]
    private static partial Regex DnsNameRegex();
}
