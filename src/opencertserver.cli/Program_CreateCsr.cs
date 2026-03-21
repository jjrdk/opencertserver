using System;
using System.CommandLine;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using OpenCertServer.Ca.Utils;

namespace opencertserver.cli;

internal static partial class Program
{
    private static void CreateCreateCsrCommand(RootCommand rootCommand)
    {
        var privateKeyOption = new Option<string>("--private-key")
        {
            Description = "Path to the private key file (PEM)"
        };
        var outOption = new Option<string>("--out")
        {
            DefaultValueFactory = _ => "csr.pem",
            Description = "Output path for the CSR (PEM)"
        };

        var csrOptions = CreateCsrOptions();
        var cmd = new Command("create-csr", "Create a CSR from a private key (interactive)")
        {
            privateKeyOption,
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
        cmd.SetAction(CreateCsr);

        rootCommand.Add(cmd);

        async Task CreateCsr(ParseResult parse)
        {
            var privateKey = parse.GetValue(privateKeyOption);
            var outPath = parse.GetValue(outOption);

            if (string.IsNullOrWhiteSpace(privateKey) || !File.Exists(privateKey))
            {
                Console.WriteLine("Private key file is required and must exist (--private-key path).");
                return;
            }

            if (string.IsNullOrWhiteSpace(outPath))
            {
                Console.WriteLine("Output path is required (--out path).");
                return;
            }

            try
            {
                using var key = LoadPrivateKeyFromPem(privateKey);
                EnsureHasPrivateKey(key);
                var csrInput = CollectCsrInput(parse, csrOptions, Console.Out, Console.In);
                var request = BuildCertificateRequest(key, csrInput, Console.Out);
                var pem = request.ToPkcs10();

                var directoryName = string.IsNullOrWhiteSpace(outPath) ? null : Path.GetDirectoryName(outPath);
                if (!string.IsNullOrWhiteSpace(directoryName))
                {
                    Directory.CreateDirectory(directoryName!);
                }

                await File.WriteAllTextAsync(outPath!, pem);
                Console.WriteLine($"CSR written to {outPath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error creating CSR: {ex.Message}");
            }
        }
    }

    internal static AsymmetricAlgorithm LoadPrivateKeyFromPem(string privateKeyPath)
    {
        var pem = File.ReadAllText(privateKeyPath);
        // Prefer RSA, then EC
        if (pem.Contains("RSA PRIVATE KEY", StringComparison.Ordinal) ||
            pem.Contains("BEGIN PRIVATE KEY", StringComparison.Ordinal) ||
            pem.Contains("BEGIN ENCRYPTED PRIVATE KEY", StringComparison.Ordinal))
        {
            var rsa = RSA.Create();
            try
            {
                rsa.ImportFromPem(pem);
                return rsa;
            }
            catch
            {
                rsa.Dispose();
                throw;
            }
        }

        if (pem.Contains("EC PRIVATE KEY", StringComparison.Ordinal) ||
            pem.Contains("BEGIN EC PRIVATE KEY", StringComparison.Ordinal))
        {
            var ecdsa = ECDsa.Create();
            try
            {
                ecdsa.ImportFromPem(pem);
                return ecdsa;
            }
            catch
            {
                ecdsa.Dispose();
                throw;
            }
        }

        // Fall back: try to parse as RSA/PKCS#8
        try
        {
            var rsa2 = RSA.Create();
            rsa2.ImportFromPem(pem);
            return rsa2;
        }
        catch
        {
            var ecdsa2 = ECDsa.Create();
            ecdsa2.ImportFromPem(pem);
            return ecdsa2;
        }
    }
}
