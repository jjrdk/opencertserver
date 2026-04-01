using System;
using System.CommandLine;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using OpenCertServer.Est.Client;

namespace opencertserver.cli;

internal static partial class Program
{
    private static void CreateEstReEnrollCommand(RootCommand rootCommand)
    {
        var urlOption = new Option<string>("--url")
        {
            Description = "HTTPS base URL for the EST server"
        };
        var privateKeyOption = new Option<string>("--private-key")
        {
            Description = "Path to the private key used to sign the re-enrollment request (PEM)"
        };
        var profileOption = new Option<string>("--profile")
        {
            Description = "Profile name to use for the EST request"
        };
        var certificateOption = new Option<string>("--cert")
        {
            Description = "Existing certificate to re-enroll (PEM or DER)"
        };
        var outOption = new Option<string>("--out")
        {
            DefaultValueFactory = _ => "reenrolled.pem",
            Description = "Output path for the re-issued certificate (PEM)"
        };

        var cmd = new Command("est-reenroll", "Re-enroll an existing certificate via EST")
        {
            urlOption,
            privateKeyOption,
            profileOption,
            certificateOption,
            outOption
        };
        cmd.SetAction(ReEnroll);

        rootCommand.Add(cmd);

        async Task ReEnroll(ParseResult parse)
        {
            var url = parse.GetValue(urlOption);
            if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out var baseUri) ||
                baseUri.Scheme != Uri.UriSchemeHttps)
            {
                Console.WriteLine("EST server URL is required and must be HTTPS (--url https://...)");
                return;
            }

            var privateKeyPath = parse.GetValue(privateKeyOption);
            if (string.IsNullOrWhiteSpace(privateKeyPath) || !File.Exists(privateKeyPath))
            {
                Console.WriteLine("Private key file is required and must exist (--private-key path).");
                return;
            }

            var profile = parse.GetValue(profileOption);

            var certificatePath = parse.GetValue(certificateOption);
            if (string.IsNullOrWhiteSpace(certificatePath) || !File.Exists(certificatePath))
            {
                Console.WriteLine("Certificate path is required and must exist (--cert path).");
                return;
            }

            var outPath = parse.GetValue(outOption);
            if (string.IsNullOrWhiteSpace(outPath))
            {
                Console.WriteLine("Output path is required (--out path).");
                return;
            }

            try
            {
                using var key = LoadPrivateKeyFromPem(privateKeyPath);
                EnsureHasPrivateKey(key);

                var certBytes = await File.ReadAllBytesAsync(certificatePath).ConfigureAwait(false);
                using var currentCert = X509CertificateLoader.LoadCertificate(certBytes);
                using var publicKey = currentCert.GetRSAPublicKey() ??
                    (AsymmetricAlgorithm?)currentCert.GetECDsaPublicKey();
                if (publicKey == null)
                {
                    Console.WriteLine("Certificate does not contain a supported public key.");
                    return;
                }

                using (publicKey)
                {
                    if (!KeysMatch(key, publicKey))
                    {
                        Console.WriteLine("Provided private key does not match the certificate's public key.");
                        return;
                    }
                }

                using var estClient =
                    new EstClient(baseUri, messageHandler: MessageHandlerFactory(), profileName: profile);
                var (errors, collection) = await estClient.ReEnroll(key, currentCert).ConfigureAwait(false);

                if (errors != null)
                {
                    Console.WriteLine("EST re-enrollment did not return a certificate.");
                    foreach (var error in errors.Split('\n',
                        StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    {
                        Console.WriteLine($"EST error: {error}");
                    }

                    return;
                }

                var builder = new StringBuilder();
                foreach (var cert in collection!)
                {
                    builder.AppendLine(cert.ExportCertificatePem());
                }

                var directoryName = string.IsNullOrWhiteSpace(outPath) ? null : Path.GetDirectoryName(outPath);
                if (!string.IsNullOrWhiteSpace(directoryName))
                {
                    Directory.CreateDirectory(directoryName);
                }

                await File.WriteAllTextAsync(outPath, builder.ToString()).ConfigureAwait(false);
                Console.WriteLine($"EST re-enrollment succeeded, output saved to {outPath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error re-enrolling certificate: {ex.Message}");
            }
        }
    }
}
