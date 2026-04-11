using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils;
using Xunit;

namespace OpenCertServer.Ca.Tests
{
    public class CertificateExtensionsTests
    {
        [Theory]
        [InlineData("RSA")]
        [InlineData("ECDsa")]
        public void PrintCertificate_IncludesExpectedSections(string algo)
        {
            var key = algo == "RSA" ? RSA.Create(2048) : (AsymmetricAlgorithm)ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var subject = "CN=example.test,O=TestOrg,OU=Unit,L=City,ST=State,C=US,E=admin@example.com";
            var req = algo == "RSA"
                ? new CertificateRequest(new X500DistinguishedName(subject), (RSA)key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
                : new CertificateRequest(new X500DistinguishedName(subject), (ECDsa)key, HashAlgorithmName.SHA256);

            // SAN
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName("example.test");
            san.AddIpAddress(IPAddress.Parse("127.0.0.1"));
            req.CertificateExtensions.Add(san.Build());

            // Key Usage
            req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));

            // EKU
            var oids = new OidCollection { new Oid("1.3.6.1.5.5.7.3.1"), new Oid("1.3.6.1.5.5.7.3.2") };
            req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(oids, false));

            // Create self-signed cert
            var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5).DateTime;
            var notAfter = DateTimeOffset.UtcNow.AddYears(1).DateTime;
            using var cert = req.CreateSelfSigned(notBefore, notAfter);

            // Act
            var text = cert.PrintCertificate();

            // Dispose key
            key.Dispose();

            // Assert some expected sections and values
            Assert.Contains("Certificate:", text);
            Assert.Contains("Version:", text);
            Assert.Contains("Serial Number:", text);
            Assert.Contains("Issuer:", text);
            Assert.Contains("Subject:", text);

            // Subject common name and organization present
            Assert.Contains("commonName", text);
            Assert.Contains("example.test", text);
            Assert.Contains("organizationName", text);
            Assert.Contains("TestOrg", text);

            // Public key info (RSA-specific checks only for RSA)
            if (algo == "RSA")
            {
                Assert.Contains("RSA Public-Key", text);
                Assert.Contains("Modulus:", text);
                Assert.Contains("Exponent:", text);
            }

            // Key usage and EKU
            Assert.Contains("X509v3 Key Usage", text);
            Assert.Contains("Digital Signature", text);
            Assert.Contains("Key Encipherment", text);
            Assert.Contains("X509v3 Extended Key Usage", text);
            // EKU mapped friendly name for serverAuth
            Assert.Contains("TLS Web Server Authentication", text);
        }

        [Fact]
        public void PrintCertificate_SerialNumberUsesColonSeparatedHex()
        {
            using var key = RSA.Create(2048);
            var name = new X500DistinguishedName("CN=serial.example.com,O=SerialTest");
            var request = new CertificateRequest(name, (RSA)key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5).DateTime;
            var notAfter = DateTimeOffset.UtcNow.AddYears(1).DateTime;
            using var cert = request.CreateSelfSigned(notBefore, notAfter);

            var text = cert.PrintCertificate();

            Assert.Contains("Serial Number:", text);
            var serial = cert.SerialNumber;
            if (serial.Length % 2 != 0)
            {
                serial = "0" + serial;
            }

            var colonSerial = string.Join(
                ":",
                Enumerable.Range(0, serial.Length / 2)
                    .Select(i => serial.Substring(i * 2, 2).ToLowerInvariant()));

            Assert.Contains(colonSerial, text);
        }
    }
}

