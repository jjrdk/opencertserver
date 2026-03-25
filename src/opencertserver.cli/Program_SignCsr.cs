namespace opencertserver.cli;

using System;
using System.CommandLine;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

internal static partial class Program
{
    private static void CreateSignCsrCommand(RootCommand rootCommand)
    {
        // sign-csr command
        var csrOption = new Option<string>("--csr") { Description = "Path to the CSR file (PEM format)" };
        var caKeyOption = new Option<string>("--ca-key") { Description = "Path to the CA private key (PEM format)" };
        var caCertOption = new Option<string>("--ca-cert") { Description = "Path to the CA certificate (PEM or DER)" };
        var outOption = new Option<string>("--out")
            { Description = "Output path for the signed certificate (PEM format)" };
        var signCsrCommand = new Command("sign-csr")
        {
            Description = "Sign a certificate signing request (CSR)", Options =
            {
                csrOption,
                caKeyOption,
                caCertOption,
                outOption
            }
        };
        signCsrCommand.SetAction(SignCsr);
        rootCommand.Add(signCsrCommand);
        return;

        Task SignCsr(ParseResult parseResult)
        {
            var csrPath = parseResult.GetValue(csrOption);
            var caKeyPath = parseResult.GetValue(caKeyOption);
            var caCertPath = parseResult.GetValue(caCertOption);
            var outPath = parseResult.GetValue(outOption);

            if (string.IsNullOrWhiteSpace(csrPath) || !File.Exists(csrPath))
            {
                Console.WriteLine("CSR file path is required and must exist (--csr path).");
                return Task.CompletedTask;
            }

            if (string.IsNullOrWhiteSpace(caKeyPath) || !File.Exists(caKeyPath))
            {
                Console.WriteLine("CA private key path is required and must exist (--ca-key path).");
                return Task.CompletedTask;
            }

            if (string.IsNullOrWhiteSpace(caCertPath) || !File.Exists(caCertPath))
            {
                Console.WriteLine("CA certificate path is required and must exist (--ca-cert path).");
                return Task.CompletedTask;
            }

            if (string.IsNullOrWhiteSpace(outPath))
            {
                Console.WriteLine("Output path is required (--out path).");
                return Task.CompletedTask;
            }

            byte[] csrBytes;
            try
            {
                csrBytes = ReadPemOrDer(csrPath, "-----BEGIN CERTIFICATE REQUEST-----", "-----END CERTIFICATE REQUEST-----");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error reading CSR: {ex.Message}");
                return Task.CompletedTask;
            }

            CertificateRequest request;
            try
            {
                request = CertificateRequest.LoadSigningRequest(
                    csrBytes,
                    HashAlgorithmName.SHA256,
                    CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions,
                    RSASignaturePadding.Pss);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"CSR is invalid: {ex.Message}");
                return Task.CompletedTask;
            }

            if (string.IsNullOrWhiteSpace(request.SubjectName.Name))
            {
                Console.WriteLine("CSR does not contain a valid subject.");
                return Task.CompletedTask;
            }

            using var caKey = LoadPrivateKeyFromPem(caKeyPath);
            try
            {
                EnsureHasPrivateKey(caKey);
            }
            catch (Exception)
            {
                Console.WriteLine("CA private key must contain private key material.");
                return Task.CompletedTask;
            }
            using var caCert = LoadCertificate(caCertPath);
            using var issuer = AttachPrivateKeyToCertificate(caCert, caKey);

            var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
            var notAfter = notBefore.AddYears(1);
            var serial = new byte[16];
            RandomNumberGenerator.Fill(serial);

            X509Certificate2 signedCert;
            try
            {
                signedCert = request.Create(issuer, notBefore, notAfter, serial);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Could not sign CSR: {ex.Message}");
                return Task.CompletedTask;
            }

            try
            {
                var directory = Path.GetDirectoryName(outPath);
                if (!string.IsNullOrWhiteSpace(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                File.WriteAllText(outPath, signedCert.ExportCertificatePem());
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error writing certificate: {ex.Message}");
                signedCert.Dispose();
                return Task.CompletedTask;
            }

            Console.WriteLine($"Signing CSR: {csrPath} with CA key: {caKeyPath} and CA cert: {caCertPath}. Output: {outPath}");
            signedCert.Dispose();
            return Task.CompletedTask;
        }

        static byte[] ReadPemOrDer(string path, string begin, string end)
        {
            var text = File.ReadAllText(path);
            if (text.Contains(begin, StringComparison.Ordinal) && text.Contains(end, StringComparison.Ordinal))
            {
                var start = text.IndexOf(begin, StringComparison.Ordinal);
                var stop = text.IndexOf(end, start, StringComparison.Ordinal);
                if (start >= 0 && stop > start)
                {
                    var base64 = text[(start + begin.Length)..stop];
                    base64 = base64.Replace("\r", string.Empty).Replace("\n", string.Empty).Trim();
                    return Convert.FromBase64String(base64);
                }
            }

            return File.ReadAllBytes(path);
        }

        static X509Certificate2 LoadCertificate(string path)
        {
            var bytes = File.ReadAllBytes(path);
            return X509CertificateLoader.LoadCertificate(bytes);
        }

        static X509Certificate2 AttachPrivateKeyToCertificate(X509Certificate2 certificate, AsymmetricAlgorithm privateKey)
        {
            return privateKey switch
            {
                RSA rsa => certificate.CopyWithPrivateKey(rsa),
                ECDsa ecdsa => certificate.CopyWithPrivateKey(ecdsa),
                _ => throw new InvalidOperationException("Unsupported CA key algorithm")
            };
        }
    }
}
