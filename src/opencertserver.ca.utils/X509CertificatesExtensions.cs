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

public static class X509CertificatesExtensions
{
    private const string SubjectAlternateNameOID = "2.5.29.17";

    private static readonly Regex DnsNameRegex = new(
        @"^DNS Name=(.+)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static HashSet<string> GetSubjectAlternativeNames(this X509Certificate2 cert)
    {
        if (cert == null)
        {
            throw new ArgumentNullException(nameof(cert));
        }
        var subjectAlternativeName = cert.Extensions.OfType<X509Extension>()
            .Where(n => n.Oid?.Value == SubjectAlternateNameOID)
            .Select(n => new AsnEncodedData(n.Oid, n.RawData))
            .Select(n => n.Format(true))
            .FirstOrDefault();

        return string.IsNullOrWhiteSpace(subjectAlternativeName)
            ? new HashSet<string>()
            : subjectAlternativeName.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.RemoveEmptyEntries)
                .Select(n => DnsNameRegex.Match(n))
                .Where(r => r.Success && !string.IsNullOrWhiteSpace(r.Groups[1].Value))
                .Select(r => r.Groups[1].Value)
                .ToHashSet();
    }
    public static string ToPem(this X509Certificate2 cert)
    {
        return string.Concat("-----BEGIN CERTIFICATE-----\n",
            Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks),
            "\n-----END CERTIFICATE-----");
    }

    public static string ToPemChain(this X509Certificate2 cert, X509Certificate2Collection issuers)
    {
        return cert.ToPem() + string.Join('\n', issuers.OfType<X509Certificate2>().Select(x => x.ToPem()));
    }

    public static async Task WritePfx(this X509Certificate2 certificate, Stream outputStream, CancellationToken cancellation = default)
    {
        var buffer = certificate.Export(X509ContentType.Pfx);
        await outputStream.WriteAsync(buffer.AsMemory(), cancellation).ConfigureAwait(false);
    }
}