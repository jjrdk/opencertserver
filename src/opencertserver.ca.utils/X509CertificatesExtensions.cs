namespace OpenCertServer.Ca.Utils
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading;
    using System.Threading.Tasks;

    public static class X509CertificatesExtensions
    {
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
}