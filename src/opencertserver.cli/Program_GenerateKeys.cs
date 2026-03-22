using System;
using System.CommandLine;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace opencertserver.cli;

internal static partial class Program
{
    private const int DefaultRsaKeySize = 3072;
    private const string DefaultEcdsaCurve = "nistP256";

    private sealed record GeneratedKeyPair(string Description, string PrivateKeyPem, string PublicKeyPem);
    private sealed record OutputPaths(string PrivateKeyPath, string PublicKeyPath);

    private static void CreateGenerateKeysCommand(RootCommand rootCommand)
    {
        var algorithmOption = new Option<string>("--algorithm")
        {
            Description = "Key algorithm to generate: rsa, ecdsa, or mldsa (default: rsa)",
            DefaultValueFactory = _ => "rsa"
        };
        var privateKeyOutOption = new Option<string>("--private-key-out")
        {
            Description = "Output path for the private key PEM file"
        };
        var publicKeyOutOption = new Option<string>("--public-key-out")
        {
            Description = "Output path for the public key PEM file"
        };
        var outOption = new Option<string>("--out")
        {
            Description = "Base output path or directory used to derive the private/public PEM file paths"
        };
        var rsaKeySizeOption = new Option<int>("--rsa-key-size")
        {
            Description = "RSA key size in bits (default: 3072)",
            DefaultValueFactory = _ => DefaultRsaKeySize
        };
        var ecdsaCurveOption = new Option<string>("--ecdsa-curve")
        {
            Description = "ECDSA curve to use: nistP256, nistP384, or nistP521 (default: nistP256)",
            DefaultValueFactory = _ => DefaultEcdsaCurve
        };

        var cmd = new Command("generate-keys", "Generate a public/private key pair as PEM files")
        {
            algorithmOption,
            outOption,
            privateKeyOutOption,
            publicKeyOutOption,
            rsaKeySizeOption,
            ecdsaCurveOption,
        };
        cmd.SetAction(GenerateKeys);

        rootCommand.Add(cmd);

        async Task GenerateKeys(ParseResult parse)
        {
            var algorithm = parse.GetValue(algorithmOption);
            var outPath = parse.GetValue(outOption);
            var privateKeyOut = parse.GetValue(privateKeyOutOption);
            var publicKeyOut = parse.GetValue(publicKeyOutOption);
            var rsaKeySize = parse.GetValue(rsaKeySizeOption);
            var ecdsaCurve = parse.GetValue(ecdsaCurveOption);

            OutputPaths outputPaths;

            try
            {
                outputPaths = ResolveOutputPaths(outPath, privateKeyOut, publicKeyOut);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error generating keys: {ex.Message}");
                return;
            }

            try
            {
                var keyPair = GenerateKeyPair(algorithm, rsaKeySize, ecdsaCurve);
                await WritePemAsync(outputPaths.PrivateKeyPath, keyPair.PrivateKeyPem);
                await WritePemAsync(outputPaths.PublicKeyPath, keyPair.PublicKeyPem);

                Console.WriteLine($"Generated {keyPair.Description} key pair.");
                Console.WriteLine($"Private key written to {outputPaths.PrivateKeyPath}");
                Console.WriteLine($"Public key written to {outputPaths.PublicKeyPath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error generating keys: {ex.Message}");
            }
        }
    }

    private static GeneratedKeyPair GenerateKeyPair(
        string? algorithm,
        int rsaKeySize,
        string? ecdsaCurve)
    {
        var normalizedAlgorithm = NormalizeAlgorithm(algorithm);
        return normalizedAlgorithm switch
        {
            "rsa" => GenerateRsaKeyPair(rsaKeySize),
            "ecdsa" => GenerateEcdsaKeyPair(ecdsaCurve),
            _ => throw new InvalidOperationException(
                "Unsupported algorithm. Supported values are rsa, ecdsa, and mldsa.")
        };
    }

    private static GeneratedKeyPair GenerateRsaKeyPair(int keySize)
    {
        if (keySize < 2048 || keySize % 8 != 0)
        {
            throw new InvalidOperationException("RSA key size must be a multiple of 8 and at least 2048 bits.");
        }

        using var rsa = RSA.Create(keySize);
        return new GeneratedKeyPair(
            $"RSA-{keySize}",
            rsa.ExportPkcs8PrivateKeyPem(),
            rsa.ExportSubjectPublicKeyInfoPem());
    }

    private static GeneratedKeyPair GenerateEcdsaKeyPair(string? curveName)
    {
        var normalizedCurveName = NormalizeAlgorithm(curveName);
        var curve = ResolveEcdsaCurve(normalizedCurveName);
        using var ecdsa = ECDsa.Create(curve);
        return new GeneratedKeyPair(
            $"ECDSA-{ToEcdsaDisplayName(normalizedCurveName)}",
            ecdsa.ExportPkcs8PrivateKeyPem(),
            ecdsa.ExportSubjectPublicKeyInfoPem());
    }

    private static string NormalizeAlgorithm(string? algorithm)
    {
        return string.IsNullOrWhiteSpace(algorithm)
            ? "rsa"
            : algorithm.Trim().Replace("-", string.Empty, StringComparison.Ordinal)
                .Replace("_", string.Empty, StringComparison.Ordinal)
                .ToLowerInvariant();
    }

    private static ECCurve ResolveEcdsaCurve(string? curveName)
    {
        return curveName switch
        {
            "nistp256" or "p256" or "secp256r1" => ECCurve.NamedCurves.nistP256,
            "nistp384" or "p384" or "secp384r1" => ECCurve.NamedCurves.nistP384,
            "nistp521" or "p521" or "secp521r1" => ECCurve.NamedCurves.nistP521,
            _ => throw new InvalidOperationException(
                "Unsupported ECDSA curve. Supported values are nistP256, nistP384, and nistP521.")
        };
    }

    private static string ToEcdsaDisplayName(string? curveName)
    {
        return curveName switch
        {
            "nistp384" or "p384" or "secp384r1" => "nistP384",
            "nistp521" or "p521" or "secp521r1" => "nistP521",
            _ => "nistP256"
        };
    }

    private static OutputPaths ResolveOutputPaths(string? outPath, string? privateKeyOut, string? publicKeyOut)
    {
        if (string.IsNullOrWhiteSpace(outPath) &&
            string.IsNullOrWhiteSpace(privateKeyOut) &&
            string.IsNullOrWhiteSpace(publicKeyOut))
        {
            throw new InvalidOperationException(
                "An output location is required. Use --out or provide both --private-key-out and --public-key-out.");
        }

        if (!string.IsNullOrWhiteSpace(outPath))
        {
            var derivedPaths = DeriveOutputPaths(outPath);
            privateKeyOut ??= derivedPaths.PrivateKeyPath;
            publicKeyOut ??= derivedPaths.PublicKeyPath;
        }

        if (string.IsNullOrWhiteSpace(privateKeyOut))
        {
            throw new InvalidOperationException("Private key output path is required (--private-key-out path or --out path).");
        }

        if (string.IsNullOrWhiteSpace(publicKeyOut))
        {
            throw new InvalidOperationException("Public key output path is required (--public-key-out path or --out path).");
        }

        if (string.Equals(Path.GetFullPath(privateKeyOut), Path.GetFullPath(publicKeyOut), StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Private and public key output paths must be different.");
        }

        return new OutputPaths(privateKeyOut, publicKeyOut);
    }

    private static OutputPaths DeriveOutputPaths(string outPath)
    {
        var normalizedPath = outPath.Trim();
        var looksLikeDirectory = normalizedPath.EndsWith(Path.DirectorySeparatorChar) ||
            normalizedPath.EndsWith(Path.AltDirectorySeparatorChar) ||
            Directory.Exists(normalizedPath);

        if (looksLikeDirectory)
        {
            return new OutputPaths(
                Path.Combine(normalizedPath, "private-key.pem"),
                Path.Combine(normalizedPath, "public-key.pem"));
        }

        var basePath = normalizedPath.EndsWith(".pem", StringComparison.OrdinalIgnoreCase)
            ? normalizedPath[..^4]
            : normalizedPath;

        return new OutputPaths(
            $"{basePath}-private.pem",
            $"{basePath}-public.pem");
    }

    private static async Task WritePemAsync(string path, string pem)
    {
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        await File.WriteAllTextAsync(path, pem);
    }
}





