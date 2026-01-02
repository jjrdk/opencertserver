namespace OpenCertServer.Ca.Utils;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

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
                .Select(n => n.Format(true))
                .FirstOrDefault();

            return string.IsNullOrWhiteSpace(subjectAlternativeName)
                ? []
                : subjectAlternativeName.Split(["\r\n", "\r", "\n"], StringSplitOptions.RemoveEmptyEntries)
                    .Select(n => DnsNameRegex().Match(n))
                    .Where(r => r.Success && !string.IsNullOrWhiteSpace(r.Groups[1].Value))
                    .Select(r => r.Groups[1].Value)
                    .ToHashSet();
        }

        public string ToPem()
        {
            return string.Concat("-----BEGIN CERTIFICATE-----\n",
                Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks),
                "\n-----END CERTIFICATE-----");
        }

        public string ToPemChain(X509Certificate2Collection issuers)
        {
            return $"{cert.ToPem()}\n{string.Join('\n', issuers.Select(x => x.ToPem()))}";
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
