namespace OpenCertServer.Ca.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using Microsoft.Extensions.Logging.Abstractions;
    using Utils;
    using Xunit;

    public class CertificateAuthorityTests : IDisposable
    {
        private readonly CertificateAuthority _authority;

        public CertificateAuthorityTests()
        {
            using var ecdsa = ECDsa.Create();
            var ecdsaReq = new CertificateRequest("CN=Test Server", ecdsa, HashAlgorithmName.SHA256);
            ecdsaReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, false));
            var ecdsaCert = ecdsaReq.CreateSelfSigned(
                DateTimeOffset.UtcNow.Date,
                DateTimeOffset.UtcNow.Date.AddYears(1));
            using var rsa = RSA.Create(4096);
            var rsaReq = new CertificateRequest("CN=Test Server", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            rsaReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, false));
            var rsaCert = rsaReq.CreateSelfSigned(
                DateTimeOffset.UtcNow.Date,
                DateTimeOffset.UtcNow.Date.AddYears(1));
            _authority = new CertificateAuthority(
                rsaCert,
                ecdsaCert,
                TimeSpan.FromDays(90),
                _ => true,
                new NullLogger<CertificateAuthority>(),
                new DistinguishedNameValidation());
        }

        [Fact]
        public void CanSerializeCertificateRequest()
        {
            using var rsa = RSA.Create(2048);

            var req = CreateCertificateRequest(rsa);
            var bytes = req.CreateSigningRequest();

            var cert = _authority.SignCertificateRequest(bytes) as SignCertificateResponse.Success;

            static IEnumerable<string> GetParts(X500DistinguishedName name)
            {
                return name.Name!.Split(',').Select(x => x.Trim()).OrderBy(x => x);
            }

            Assert.Equal(GetParts(req.SubjectName), GetParts(cert.Certificate.SubjectName));
        }

        [Fact]
        public void CanCreateStringCertificateRequest()
        {
            using var rsa = RSA.Create(2048);

            var req = CreateCertificateRequest(rsa);
            var b64 = req.ToPkcs10();
            var cert = _authority.SignCertificateRequest(b64) as SignCertificateResponse.Success;

            Assert.Equal(
                string.Join(string.Empty, req.SubjectName.Format(true).Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries).OrderBy(x => x)),
                string.Join(string.Empty, cert.Certificate.SubjectName.Format(true).Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries).OrderBy(x => x)));
        }

        private static CertificateRequest CreateCertificateRequest(RSA rsa)
        {
            var req = new CertificateRequest("CN=Test, OU=Test Department", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            req.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(
                    false,
                    false,
                    0,
                    false));

            req.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation,
                    false));

            // Time stamping
            req.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.8") }, true));

            req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
            return req;
        }

        public void Dispose()
        {
            GC.SuppressFinalize(this);
            _authority?.Dispose();
        }
    }
}
