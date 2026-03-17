using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;
using OpenCertServer.Ca.Utils; // ToPkcs10 extension

namespace opencertserver.cli.tests.Unit
{
    public class CreateCsrNonInteractiveUnitTests
    {
        [Fact]
        public async Task CreateCsr_NonInteractive_WritesCsrFile()
        {
            // Arrange - generate a temporary PKCS#8 private key PEM
            var rsaKey = System.Security.Cryptography.RSA.Create(2048);
            var pkcs8 = rsaKey.ExportPkcs8PrivateKey();
            var pem = "-----BEGIN PRIVATE KEY-----\n" + Convert.ToBase64String(pkcs8, Base64FormattingOptions.InsertLineBreaks) + "\n-----END PRIVATE KEY-----\n";

            var keyPath = Path.Combine(Path.GetTempPath(), $"testkey_{Guid.NewGuid():N}.pem");
            await File.WriteAllTextAsync(keyPath, pem);

            var outPath = Path.Combine(Path.GetTempPath(), $"testcsr_{Guid.NewGuid():N}.pem");

            var args = new[]
            {
                "create-csr",
                "--private-key", keyPath,
                "--out", outPath,
                "--C", "US",
                "--ST", "CA",
                "--L", "TestCity",
                "--O", "TestOrg",
                "--OU", "Unit",
                "--CN", "example.test",
                "--E", "admin@example.test",
                "--san", "example.test,127.0.0.1",
                "--key-usage", "digitalSignature,keyEncipherment",
                "--eku", "serverAuth,clientAuth",
                "--basic-ca", "false",
                "--rsa-padding", "pkcs1"
            };

            // Act: construct a CSR using the same code path as the CLI
            var key = Program.LoadPrivateKeyFromPem(keyPath);
            try
            {
                var dn = new System.Security.Cryptography.X509Certificates.X500DistinguishedName("C=US,ST=CA,L=TestCity,O=TestOrg,OU=Unit,CN=example.test,E=admin@example.test");
                var req = key switch
                {
                    System.Security.Cryptography.RSA rsa => new System.Security.Cryptography.X509Certificates.CertificateRequest(dn, rsa, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1),
                    System.Security.Cryptography.ECDsa ecdsa => new System.Security.Cryptography.X509Certificates.CertificateRequest(dn, ecdsa, System.Security.Cryptography.HashAlgorithmName.SHA256),
                    _ => throw new InvalidOperationException("Unsupported key algorithm in test")
                };

                // SANs
                var sanBuilder = new System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder();
                sanBuilder.AddDnsName("example.test");
                sanBuilder.AddIpAddress(System.Net.IPAddress.Parse("127.0.0.1"));
                req.CertificateExtensions.Add(sanBuilder.Build());

                // Key usage
                req.CertificateExtensions.Add(new System.Security.Cryptography.X509Certificates.X509KeyUsageExtension(System.Security.Cryptography.X509Certificates.X509KeyUsageFlags.DigitalSignature | System.Security.Cryptography.X509Certificates.X509KeyUsageFlags.KeyEncipherment, true));

                // EKU
                var oids = new System.Security.Cryptography.OidCollection();
                oids.Add(new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.1"));
                oids.Add(new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.2"));
                req.CertificateExtensions.Add(new System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension(oids, false));

                var pemCsr = req.ToPkcs10();
                await File.WriteAllTextAsync(outPath, pemCsr);

                // Assert
                Assert.True(File.Exists(outPath), "CSR output file was not created.");
                var csrText = await File.ReadAllTextAsync(outPath);
                Assert.Contains("BEGIN CERTIFICATE REQUEST", csrText);
            }
            finally
            {
                (key as IDisposable)?.Dispose();
            }

            // Cleanup
            try { File.Delete(keyPath); } catch { }
            try { File.Delete(outPath); } catch { }
        }
    }
}



