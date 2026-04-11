using System;
using System.CommandLine;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils;

namespace opencertserver.cli;

internal static partial class Program
{
    private sealed record CsrOptionSet(
        Option<string?> Country,
        Option<string?> State,
        Option<string?> Locality,
        Option<string?> Organization,
        Option<string?> OrganizationalUnit,
        Option<string?> CommonName,
        Option<string?> Email,
        Option<string?> San,
        Option<string?> KeyUsage,
        Option<string?> EnhancedKeyUsage,
        Option<bool?> BasicCa,
        Option<int?> BasicPathLen,
        Option<string?> Subject,
        Option<string?> RsaPadding);

    private sealed record CsrInput(
        string? Country,
        string? State,
        string? Locality,
        string? Organization,
        string? OrganizationalUnit,
        string? CommonName,
        string? Email,
        string? SubjectOverride,
        string? SubjectAlternativeNames,
        bool HasKeyUsage,
        X509KeyUsageFlags KeyUsageFlags,
        bool HasEnhancedKeyUsage,
        OidCollection EnhancedKeyUsageOids,
        bool? BasicCa,
        int? BasicPathLen,
        string RsaPadding);

    private static CsrOptionSet CreateCsrOptions()
    {
        var cOption = new Option<string?>("--C") { Description = "Country (C)" };
        var stOption = new Option<string?>("--ST") { Description = "State or Province (ST)" };
        var lOption = new Option<string?>("--L") { Description = "Locality (L)" };
        var oOption = new Option<string?>("--O") { Description = "Organization (O)" };
        var ouOption = new Option<string?>("--OU") { Description = "Organizational Unit (OU)" };
        var cnOption = new Option<string?>("--CN") { Description = "Common Name (CN)" };
        var eOption = new Option<string?>("--E") { Description = "Email (E)" };
        var sanOption = new Option<string?>("--san") { Description = "Subject Alternative Names (comma separated)" };
        var keyUsageOption = new Option<string?>("--key-usage") { Description = "Key Usage (comma separated)" };
        var ekuOption = new Option<string?>("--eku")
        {
            Description = "Enhanced Key Usages (comma separated)"
        };
        var basicCaOption = new Option<bool?>("--basic-ca")
        {
            Description = "Set basic constraints CA flag (true/false)"
        };
        var basicPathLenOption = new Option<int?>("--basic-path-len")
        {
            Description = "Path length constraint for basic constraints (integer)"
        };
        var subjectOption = new Option<string?>("--subject")
        {
            Description = "RFC2253 subject string (e.g. CN=example.com,O=Org)"
        };
        var rsaPaddingOption = new Option<string?>("--rsa-padding")
        {
            Description = "RSA signature padding to use when creating CSR: pss or pkcs1 (default: pss)",
            DefaultValueFactory = _ => "pss"
        };

        return new CsrOptionSet(
            cOption,
            stOption,
            lOption,
            oOption,
            ouOption,
            cnOption,
            eOption,
            sanOption,
            keyUsageOption,
            ekuOption,
            basicCaOption,
            basicPathLenOption,
            subjectOption,
            rsaPaddingOption);
    }

    private static CsrInput CollectCsrInput(
        ParseResult parse,
        CsrOptionSet options,
        TextWriter writer,
        TextReader reader)
    {
        var cVal = NormalizeInput(parse.GetValue(options.Country));
        var stVal = NormalizeInput(parse.GetValue(options.State));
        var lVal = NormalizeInput(parse.GetValue(options.Locality));
        var oVal = NormalizeInput(parse.GetValue(options.Organization));
        var ouVal = NormalizeInput(parse.GetValue(options.OrganizationalUnit));
        var cnVal = NormalizeInput(parse.GetValue(options.CommonName));
        var eVal = NormalizeInput(parse.GetValue(options.Email));
        var sansVal = NormalizeInput(parse.GetValue(options.San));
        var keyUsageVal = NormalizeInput(parse.GetValue(options.KeyUsage));
        var ekuVal = NormalizeInput(parse.GetValue(options.EnhancedKeyUsage));
        var basicCaVal = parse.GetValue(options.BasicCa);
        var basicPathLenVal = parse.GetValue(options.BasicPathLen);
        var subjectVal = NormalizeInput(parse.GetValue(options.Subject));
        var rsaPaddingVal = NormalizeInput(parse.GetValue(options.RsaPadding)) ?? "pss";

        var providedAny = new object?[]
        {
            cVal, stVal, lVal, oVal, ouVal, cnVal, eVal, sansVal, keyUsageVal, ekuVal, basicCaVal, basicPathLenVal,
            subjectVal
        }.Any(x => x != null);

        if (!providedAny)
        {
            cVal = PromptForInput(writer, reader, "Country (C): ");
            stVal = PromptForInput(writer, reader, "State or Province (ST): ");
            lVal = PromptForInput(writer, reader, "Locality (L): ");
            oVal = PromptForInput(writer, reader, "Organization (O): ");
            ouVal = PromptForInput(writer, reader, "Organizational Unit (OU): ");
            cnVal = PromptForInput(writer, reader, "Common Name (CN): ");
            eVal = PromptForInput(writer, reader, "Email (E): ");
            sansVal = PromptForInput(writer, reader,
                "Subject Alternative Names (comma separated, leave empty to skip): ");
            keyUsageVal = PromptForInput(
                writer,
                reader,
                "Key Usage (comma separated - e.g. digitalSignature,keyEncipherment; leave empty to skip): ");
            ekuVal = PromptForInput(
                writer,
                reader,
                "Enhanced Key Usages (comma separated - serverAuth,clientAuth,emailProtection,codeSigning; leave empty to skip): ");

            var bcInput = PromptForInput(writer, reader, "Basic Constraints - CA? (y/N, leave empty to skip): ");
            if (!string.IsNullOrWhiteSpace(bcInput) &&
                bcInput.Trim().Equals("y", StringComparison.OrdinalIgnoreCase))
            {
                basicCaVal = true;
                var pathLen = PromptForInput(writer, reader, "Path length constraint (empty for none): ");
                if (int.TryParse(pathLen, out var pathLenVal))
                {
                    basicPathLenVal = pathLenVal;
                }
            }
        }

        var hasKeyUsage = keyUsageVal != null;
        var keyUsageFlags = hasKeyUsage ? ParseKeyUsageFlags(keyUsageVal!, writer) : X509KeyUsageFlags.None;
        var ekuOids = new OidCollection();
        var hasEnhancedKeyUsage = false;
        if (ekuVal != null)
        {
            (ekuOids, hasEnhancedKeyUsage) = ParseEnhancedKeyUsage(ekuVal, writer);
        }

        return new CsrInput(
            cVal,
            stVal,
            lVal,
            oVal,
            ouVal,
            cnVal,
            eVal,
            subjectVal,
            sansVal,
            hasKeyUsage,
            keyUsageFlags,
            hasEnhancedKeyUsage,
            ekuOids,
            basicCaVal,
            basicPathLenVal,
            rsaPaddingVal);
    }

    private static CertificateRequest BuildCertificateRequest(
        AsymmetricAlgorithm key,
        CsrInput input,
        TextWriter writer)
    {
        var name = BuildDistinguishedName(input);
        var padding = GetPadding(input.RsaPadding);
        var request = key switch
        {
            RSA rsa => new CertificateRequest(name, rsa, HashAlgorithmName.SHA256, padding),
            ECDsa ecdsa => new CertificateRequest(name, ecdsa, HashAlgorithmName.SHA256),
            _ => throw new InvalidOperationException("Unsupported key algorithm for CSR generation")
        };

        if (!string.IsNullOrWhiteSpace(input.SubjectAlternativeNames))
        {
            AddSubjectAlternativeNames(request, input.SubjectAlternativeNames!);
        }

        if (input.HasKeyUsage && input.KeyUsageFlags != X509KeyUsageFlags.None)
        {
            request.CertificateExtensions.Add(new X509KeyUsageExtension(input.KeyUsageFlags, true));
        }
        else if (input.HasKeyUsage)
        {
            writer.WriteLine("Key usage was requested but no valid flags were parsed, skipping extension.");
        }

        if (input is { HasEnhancedKeyUsage: true, EnhancedKeyUsageOids.Count: > 0 })
        {
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(input.EnhancedKeyUsageOids, false));
        }

        if (input.BasicCa == true)
        {
            var hasPath = input.BasicPathLen.HasValue;
            var pathLen = input.BasicPathLen.GetValueOrDefault();
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, hasPath, pathLen, true));
        }

        return request;
    }

    private static X509KeyUsageFlags ParseKeyUsageFlags(string value, TextWriter writer)
    {
        var flags = X509KeyUsageFlags.None;
        var parts = value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var part in parts)
        {
            switch (part.Trim().ToLowerInvariant())
            {
                case "digitalsignature":
                case "digital_signature":
                case "digital-signature":
                case "digital-sign":
                case "ds":
                    flags |= X509KeyUsageFlags.DigitalSignature;
                    break;
                case "nonrepudiation":
                case "non-repudiation":
                    flags |= X509KeyUsageFlags.NonRepudiation;
                    break;
                case "keyencipherment":
                case "key-encipherment":
                    flags |= X509KeyUsageFlags.KeyEncipherment;
                    break;
                case "dataencipherment":
                case "data-encipherment":
                    flags |= X509KeyUsageFlags.DataEncipherment;
                    break;
                case "keyagreement":
                case "key-agreement":
                    flags |= X509KeyUsageFlags.KeyAgreement;
                    break;
                case "keycertsign":
                case "key-cert-sign":
                    flags |= X509KeyUsageFlags.KeyCertSign;
                    break;
                case "crlsign":
                case "crl-sign":
                    flags |= X509KeyUsageFlags.CrlSign;
                    break;
                case "encipheronly":
                case "encipher-only":
                    flags |= X509KeyUsageFlags.EncipherOnly;
                    break;
                case "decipheronly":
                case "decipher-only":
                    flags |= X509KeyUsageFlags.DecipherOnly;
                    break;
                default:
                    writer.WriteLine($"Unknown key usage: {part}, ignoring.");
                    break;
            }
        }

        return flags;
    }

    private static (OidCollection, bool) ParseEnhancedKeyUsage(string value, TextWriter writer)
    {
        var oids = new OidCollection();
        var parts = value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var part in parts)
        {
            switch (part.Trim().ToLowerInvariant())
            {
                case "serverauth":
                case "server-auth":
                case "tlsserver":
                case "tls-server":
                    oids.Add(Oids.ServerAuthenticationPurpose.InitializeOid(Oids.ServerAuthenticationPurposeFriendlyName));
                    break;
                case "clientauth":
                case "client-auth":
                case "tlsclient":
                case "tls-client":
                    oids.Add(Oids.ClientAuthenticationPurpose.InitializeOid(Oids.ClientAuthenticationPurposeFriendlyName));
                    break;
                case "emailprotection":
                case "email-protection":
                case "email":
                case "smime":
                case "s/mime":
                    oids.Add(Oids.EmailProtectionPurpose.InitializeOid(Oids.EmailProtectionPurposeFriendlyName));
                    break;
                case "codesigning":
                case "code-signing":
                case "code_signing":
                    oids.Add(Oids.CodeSigningPurpose.InitializeOid(Oids.CodeSigningPurposeFriendlyName));
                    break;
                case "time-stamping":
                case "timestamping":
                case "timestamp":
                    oids.Add(Oids.TimeStampingPurpose.InitializeOid(Oids.TimeStampingPurposeFriendlyName));
                    break;
                default:
                    writer.WriteLine($"Unknown EKU: {part}, ignoring.");
                    break;
            }
        }

        return (oids, oids.Count > 0);
    }

    private static string? PromptForInput(TextWriter writer, TextReader reader, string prompt)
    {
        writer.Write(prompt);
        return NormalizeInput(reader.ReadLine());
    }

    private static string? NormalizeInput(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }

    private static X500DistinguishedName BuildDistinguishedName(CsrInput input)
    {
        if (!string.IsNullOrWhiteSpace(input.SubjectOverride))
        {
            return new X500DistinguishedName(input.SubjectOverride);
        }

        var parts = new[]
        {
            FormatDnComponent("C", input.Country),
            FormatDnComponent("ST", input.State),
            FormatDnComponent("L", input.Locality),
            FormatDnComponent("O", input.Organization),
            FormatDnComponent("OU", input.OrganizationalUnit),
            FormatDnComponent("CN", input.CommonName),
            FormatDnComponent("E", input.Email)
        }.Where(part => part != null).ToArray();

        var subject = parts.Length == 0 ? string.Empty : string.Join(", ", parts);
        return new X500DistinguishedName(subject);

        static string? FormatDnComponent(string key, string? value)
        {
            return string.IsNullOrWhiteSpace(value) ? null : $"{key}={value}";
        }
    }

    private static void AddSubjectAlternativeNames(CertificateRequest request, string sansInput)
    {
        var sanBuilder = new SubjectAlternativeNameBuilder();
        var parts = sansInput.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var part in parts)
        {
            if (IPAddress.TryParse(part, out var ip))
            {
                sanBuilder.AddIpAddress(ip);
            }
            else
            {
                sanBuilder.AddDnsName(part);
            }
        }

        request.CertificateExtensions.Add(sanBuilder.Build());
    }

    private static RSASignaturePadding GetPadding(string value)
    {
        return value.Trim().Equals("pkcs1", StringComparison.OrdinalIgnoreCase)
            ? RSASignaturePadding.Pkcs1
            : RSASignaturePadding.Pss;
    }

    internal static AuthenticationHeaderValue? ParseAuthenticationHeader(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        var trimmed = raw.Trim();
        var spaceIndex = trimmed.IndexOf(' ');
        if (spaceIndex <= 0)
        {
            return new AuthenticationHeaderValue(trimmed);
        }

        var scheme = trimmed[..spaceIndex];
        var parameter = trimmed[(spaceIndex + 1)..];
        return new AuthenticationHeaderValue(scheme, parameter);
    }

    internal static AsymmetricAlgorithm LoadPublicKey(string path)
    {
        try
        {
            using var certificate = X509CertificateLoader.LoadCertificateFromFile(path);
            var rsa = certificate.GetRSAPublicKey();
            if (rsa != null)
            {
                return rsa;
            }

            var ecdsa = certificate.GetECDsaPublicKey();
            if (ecdsa != null)
            {
                return ecdsa;
            }
        }
        catch
        {
        }

        try
        {
            var rsaKey = RSA.Create();
            rsaKey.ImportFromPem(File.ReadAllText(path));
            return rsaKey;
        }
        catch
        {
        }

        try
        {
            var ecdsaKey = ECDsa.Create();
            ecdsaKey.ImportFromPem(File.ReadAllText(path));
            return ecdsaKey;
        }
        catch
        {
            throw new InvalidOperationException("Unsupported public key format.");
        }
    }

    internal static bool KeysMatch(AsymmetricAlgorithm privateKey, AsymmetricAlgorithm publicKey)
    {
        return (privateKey, publicKey) switch
        {
            (RSA privateRsa, RSA publicRsa) => RSAKeysMatch(privateRsa, publicRsa),
            (ECDsa privateEcdsa, ECDsa publicEcdsa) => EcdsaKeysMatch(privateEcdsa, publicEcdsa),
            _ => false
        };

        static bool RSAKeysMatch(RSA priv, RSA pub)
        {
            var privParams = priv.ExportParameters(false);
            var pubParams = pub.ExportParameters(false);
            return privParams.Modulus.SequenceEqual(pubParams.Modulus) &&
                privParams.Exponent.SequenceEqual(pubParams.Exponent);
        }

        static bool EcdsaKeysMatch(ECDsa priv, ECDsa pub)
        {
            var privParams = priv.ExportParameters(false);
            var pubParams = pub.ExportParameters(false);
            return privParams.Q.X.SequenceEqual(pubParams.Q.X) &&
                privParams.Q.Y.SequenceEqual(pubParams.Q.Y) &&
                string.Equals(privParams.Curve.Oid.Value, pubParams.Curve.Oid.Value,
                    StringComparison.OrdinalIgnoreCase);
        }
    }

    internal static void EnsureHasPrivateKey(AsymmetricAlgorithm key)
    {
        try
        {
            switch (key)
            {
                case RSA rsa:
                    _ = rsa.ExportParameters(true);
                    break;
                case ECDsa ecdsa:
                    _ = ecdsa.ExportParameters(true);
                    break;
                default:
                    throw new InvalidOperationException("Unsupported key algorithm.");
            }
        }
        catch (CryptographicException ex)
        {
            throw new InvalidOperationException("The provided key does not contain private key material.", ex);
        }
    }
}
