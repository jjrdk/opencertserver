using System;
using System.CommandLine;
using System.IO;
using System.Threading.Tasks;
using OpenCertServer.Ca.Utils;

namespace opencertserver.cli;

internal static partial class Program
{
    private static void CreateCsrFromKeysCommand(RootCommand rootCommand)
    {
        var privateKeyOption = new Option<string>("--private-key")
        {
            Description = "Path to the private key file (PEM)"
        };
        var publicKeyOption = new Option<string>("--public-key")
        {
            Description = "Path to the public key or certificate file (PEM or DER)"
        };
        var outOption = new Option<string>("--out")
        {
            DefaultValueFactory = _ => "csr-from-keys.pem",
            Description = "Output path for the CSR (PEM)"
        };

        var csrOptions = CreateCsrOptions();
        var cmd = new Command("create-csr-from-keys", "Create a CSR from a public/private key pair")
        {
            privateKeyOption,
            publicKeyOption,
            outOption,
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
        cmd.SetAction(CreateCsrFromKeys);

        rootCommand.Add(cmd);

        async Task CreateCsrFromKeys(ParseResult parse)
        {
            var privateKey = parse.GetValue(privateKeyOption);
            var publicKey = parse.GetValue(publicKeyOption);
            var outPath = parse.GetValue(outOption);

            if (string.IsNullOrWhiteSpace(privateKey) || !File.Exists(privateKey))
            {
                Console.WriteLine("Private key file is required and must exist (--private-key path).");
                return;
            }

            if (string.IsNullOrWhiteSpace(publicKey) || !File.Exists(publicKey))
            {
                Console.WriteLine("Public key file is required and must exist (--public-key path).");
                return;
            }

            if (string.IsNullOrWhiteSpace(outPath))
            {
                Console.WriteLine("Output path is required (--out path).");
                return;
            }

            try
            {
                using var privateKeyAlg = LoadPrivateKeyFromPem(privateKey);
                EnsureHasPrivateKey(privateKeyAlg);
                using var publicKeyAlg = LoadPublicKey(publicKey);
                if (!KeysMatch(privateKeyAlg, publicKeyAlg))
                {
                    Console.WriteLine("Private key does not match the provided public key.");
                    return;
                }

                var csrInput = CollectCsrInput(parse, csrOptions, Console.Out, Console.In);
                var request = BuildCertificateRequest(privateKeyAlg, csrInput, Console.Out);
                var pem = request.ToPkcs10Pem();

                var directoryName = string.IsNullOrWhiteSpace(outPath) ? null : Path.GetDirectoryName(outPath);
                if (!string.IsNullOrWhiteSpace(directoryName))
                {
                    Directory.CreateDirectory(directoryName!);
                }

                await File.WriteAllTextAsync(outPath!, pem).ConfigureAwait(false);
                Console.WriteLine($"CSR written to {outPath} using public key from {publicKey}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error creating CSR: {ex.Message}");
            }
        }
    }
}





