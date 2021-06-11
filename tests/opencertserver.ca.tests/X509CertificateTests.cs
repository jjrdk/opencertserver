namespace OpenCertServer.Ca.Tests
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading.Tasks;
    using Microsoft.Extensions.Logging.Abstractions;
    using Utils;
    using Xunit;

    public class X509CertificateTests : IDisposable
    {
        private readonly CertificateAuthority _ca;
        private readonly RSA _rsa = RSA.Create();

        public X509CertificateTests()
        {
            _ca = new CertificateAuthority(
                new X500DistinguishedName("CN=Test"),
                TimeSpan.FromHours(1),
                _ => true,
                new NullLogger<CertificateAuthority>(),
                new DistinguishedNameValidation());
        }

        [Fact]
        public void CanWritePublicKey()
        {
            var cert = _ca.SignCertificateRequest(
                new CertificateRequest(
                        new X500DistinguishedName("CN=Someone"),
                        RSA.Create(),
                        HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pss)
                { CertificateExtensions = { new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false) } }) as SignCertificateResponse.Success;
            using var ms = new MemoryStream();
            cert.Certificate.GetRSAPublicKey().WritePublicKeyPem(ms);

            var key = Encoding.UTF8.GetString(ms.ToArray());

            Assert.NotNull(key);
        }

        [Fact]
        public async Task CanWritePfx()
        {
            var cert = _ca.SignCertificateRequest(
                new CertificateRequest(
                    new X500DistinguishedName("CN=Someone"),
                    _rsa,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pss)
                {
                    CertificateExtensions =
                    {
                        new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false),
                    }
                }) as SignCertificateResponse.Success;
            await using var ms = new MemoryStream();
            await cert.Certificate.WritePfx(ms).ConfigureAwait(false);

            var newCert = new X509Certificate2(ms.ToArray());

            Assert.NotNull(newCert.PublicKey);
        }

        [Fact]
        public async Task WhenCertificateRequestIncludesSanThenIncludesInCertificate()
        {
            var builder = new SubjectAlternativeNameBuilder();
            builder.AddDnsName("http://localhost");
            var cert = _ca.SignCertificateRequest(
                new CertificateRequest(
                    new X500DistinguishedName("CN=Someone"),
                    _rsa,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pss)
                {
                    CertificateExtensions =
                    {
                        new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false), builder.Build(true)
                    }
                }) as SignCertificateResponse.Success;

            await using var ms = new MemoryStream();
            var san = cert.Certificate.Extensions.OfType<X509Extension>()
                .FirstOrDefault(e => e.Oid.Value == "2.5.29.17");

            Assert.NotNull(san);
        }

        /// <inheritdoc />
        public void Dispose()
        {
            GC.SuppressFinalize(this);
            _ca?.Dispose();
            _rsa?.Dispose();
        }
    }
}