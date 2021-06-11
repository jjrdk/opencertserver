namespace OpenCertServer.Ca.Utils
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;

    public static class X509CertificatesExtensions
    {
        public static void WritePrivateKeyPem(this RSA certificate, Stream outputStream)
        {
            var writer = new PemUtils.PemWriter(outputStream, disposeStream: true, encoding: Encoding.UTF8);
            writer.WritePrivateKey(certificate);
        }

        public static void WritePublicKeyPem(this RSA certificate, Stream outputStream)
        {
            var publicWriter = new PemUtils.PemWriter(outputStream, disposeStream: true, encoding: Encoding.UTF8);
            publicWriter.WritePublicKey(certificate);
        }

        public static async Task WritePfx(this X509Certificate2 certificate, Stream outputStream, CancellationToken cancellation = default)
        {
            var buffer = certificate.Export(X509ContentType.Pfx);
            await outputStream.WriteAsync(buffer.AsMemory(), cancellation).ConfigureAwait(false);
        }
    }
}