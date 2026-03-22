using System;
using System.CommandLine;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using OpenCertServer.Est.Client;

namespace opencertserver.cli;

internal static partial class Program
{
    private static void CreateEstEnrollCommand(RootCommand rootCommand)
    {
        var urlOption = new Option<string>("--url")
        {
            Description = "HTTPS base URL for the EST server"
        };
        var privateKeyOption = new Option<string>("--private-key")
        {
            Description = "Path to the private key file to sign the CSR (PEM)"
        };
        var outOption = new Option<string>("--out")
        {
            DefaultValueFactory = _ => "est-cert.pem",
            Description = "Output path for the enrolled certificate (PEM)"
        };
        var clientCertOption = new Option<string>("--client-cert")
        {
            Description = "Client certificate for mTLS authentication (PEM)"
        };
        var authOption = new Option<string>("--auth")
        {
            Description = "Authentication header value (e.g. 'Bearer <token>')"
        };

        var csrOptions = CreateCsrOptions();
        var cmd = new Command("est-enroll", "Generate a CSR and enroll via EST")
        {
            urlOption,
            privateKeyOption,
            outOption,
            clientCertOption,
            authOption,
            csrOptions.Country,
            csrOptions.State,
            csrOptions.Locality,
            csrOptions.Organization,
            csrOptions.OrganizationalUnit,
            csrOptions.CommonName,
            csrOptions.Email,
            csrOptions.San,
            csrOptions.KeyUsage,
            csrOptions.EnhancedKeyUsage,
            csrOptions.BasicCa,
            csrOptions.BasicPathLen,
            csrOptions.Subject,
            csrOptions.RsaPadding
        };
        cmd.SetAction(Enroll);

        rootCommand.Add(cmd);

        async Task Enroll(ParseResult parse)
        {
            var url = parse.GetValue(urlOption);
            if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out var baseUri) ||
                baseUri.Scheme != Uri.UriSchemeHttps)
            {
                Console.WriteLine("EST server URL is required and must be HTTPS (--url https://...)");
                return;
            }

            var privateKey = parse.GetValue(privateKeyOption);
            if (string.IsNullOrWhiteSpace(privateKey) || !File.Exists(privateKey))
            {
                Console.WriteLine("Private key file is required and must exist (--private-key path).");
                return;
            }

            var outPath = parse.GetValue(outOption);
            if (string.IsNullOrWhiteSpace(outPath))
            {
                Console.WriteLine("Output path is required (--out path).");
                return;
            }

            var resolvedOutPath = outPath!;
            var clientCertPath = parse.GetValue(clientCertOption);
            var authHeader = ParseAuthenticationHeader(parse.GetValue(authOption));
            X509Certificate2? clientCert = null;

            try
            {
                if (!string.IsNullOrWhiteSpace(clientCertPath))
                {
                    if (!File.Exists(clientCertPath))
                    {
                        Console.WriteLine("Client certificate path must exist (--client-cert path).");
                        return;
                    }

                    var extension = Path.GetExtension(clientCertPath);
                    if (extension.Equals(".pfx", StringComparison.OrdinalIgnoreCase) ||
                        extension.Equals(".p12", StringComparison.OrdinalIgnoreCase))
                    {
                        // Load PKCS#12/PFX file including private key for mTLS authentication.
                        clientCert = X509CertificateLoader.LoadCertificateFromFile(clientCertPath);
                    }
                    else
                    {
                        var clientBytes = File.ReadAllBytes(clientCertPath);
                        clientCert = X509CertificateLoader.LoadCertificate(clientBytes);
                    }

                    if (!clientCert.HasPrivateKey)
                    {
                        Console.WriteLine(
                            "Client certificate does not contain a private key. Provide a client certificate (e.g., PFX/PKCS#12) that includes the private key for mTLS authentication (--client-cert path).");
                        return;
                    }
                }

                using var key = LoadPrivateKeyFromPem(privateKey);
                EnsureHasPrivateKey(key);
                var csrInput = CollectCsrInput(parse, csrOptions, Console.Out, Console.In);
                var request = BuildCertificateRequest(key, csrInput, Console.Out);

                using var estClient = new EstClient(baseUri, MessageHandlerFactory());
                var (error, certCollection) = await estClient.Enroll(
                    request.SubjectName,
                    key,
                    csrInput.KeyUsageFlags,
                    authHeader,
                    clientCert).ConfigureAwait(false);

                if (error != null)
                {
                    Console.WriteLine($"EST enrollment failed: {error}");
                    return;
                }

                if (certCollection == null || certCollection.Count == 0)
                {
                    Console.WriteLine("EST enrollment did not return a certificate.");
                    return;
                }

                var builder = new StringBuilder();
                foreach (X509Certificate2 cert in certCollection)
                {
                    builder.AppendLine(cert.ExportCertificatePem());
                }

                var directoryName = string.IsNullOrWhiteSpace(resolvedOutPath)
                    ? null
                    : Path.GetDirectoryName(resolvedOutPath);
                if (!string.IsNullOrWhiteSpace(directoryName))
                {
                    Directory.CreateDirectory(directoryName!);
                }

                await File.WriteAllTextAsync(resolvedOutPath, builder.ToString());
                Console.WriteLine($"EST enrollment succeeded, output saved to {outPath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error enrolling certificate: {ex.Message}");
            }
            finally
            {
                clientCert?.Dispose();
            }
        }
    }
}
