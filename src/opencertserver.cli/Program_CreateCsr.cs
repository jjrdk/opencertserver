using System;
using System.CommandLine;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using OpenCertServer.Ca.Utils;

namespace opencertserver.cli;

internal static partial class Program
{
    private static void CreateCreateCsrCommand(RootCommand rootCommand)
    {
        var privateKeyOption = new Option<string>("--private-key")
            { Description = "Path to the private key file (PEM)" };
        var outOption = new Option<string>("--out")
            { DefaultValueFactory = _ => "csr.pem", Description = "Output path for the CSR (PEM)" };

        // Non-interactive options (optional) - if provided, the command will not prompt for those fields
        var cOption = new Option<string?>("--C") { Description = "Country (C)" };
        var stOption = new Option<string?>("--ST") { Description = "State or Province (ST)" };
        var lOption = new Option<string?>("--L") { Description = "Locality (L)" };
        var oOption = new Option<string?>("--O") { Description = "Organization (O)" };
        var ouOption = new Option<string?>("--OU") { Description = "Organizational Unit (OU)" };
        var cnOption = new Option<string?>("--CN") { Description = "Common Name (CN)" };
        var eOption = new Option<string?>("--E") { Description = "Email (E)" };
        var sansOption = new Option<string?>("--san") { Description = "Subject Alternative Names (comma separated)" };
        var keyUsageOption = new Option<string?>("--key-usage") { Description = "Key Usage (comma separated)" };
        var ekuOption = new Option<string?>("--eku") { Description = "Enhanced Key Usages (comma separated)" };
        var basicCaOption = new Option<bool?>("--basic-ca")
            { Description = "Set basic constraints CA flag (true/false)" };
        var basicPathLenOption = new Option<int?>("--basic-path-len")
            { Description = "Path length constraint for basic constraints (integer)" };
        var subjectOption = new Option<string?>("--subject")
            { Description = "RFC2253 subject string (e.g. CN=example.com,O=Org)" };
        var rsaPaddingOption = new Option<string?>("--rsa-padding")
        {
            DefaultValueFactory = _ => "pss", Description =
                "RSA signature padding to use when creating CSR: pss or pkcs1 (default: pss)"
        };

        var cmd = new Command("create-csr", "Create a CSR from a private key (interactive)")
        {
            privateKeyOption,
            outOption,
            cOption,
            stOption,
            lOption,
            oOption,
            ouOption,
            cnOption,
            eOption,
            sansOption,
            keyUsageOption,
            ekuOption,
            basicCaOption,
            basicPathLenOption, subjectOption, rsaPaddingOption
        };

        cmd.SetAction(CreateCsr);

        rootCommand.Add(cmd);
        return;

        async Task CreateCsr(ParseResult parse)
        {
            await Task.Yield();
            try
            {
                var privateKey = parse.GetValue(privateKeyOption);
                var outPath = parse.GetValue(outOption);
                var cVal = parse.GetValue(cOption);
                var stVal = parse.GetValue(stOption);
                var lVal = parse.GetValue(lOption);
                var oVal = parse.GetValue(oOption);
                var ouVal = parse.GetValue(ouOption);
                var cnVal = parse.GetValue(cnOption);
                var eVal = parse.GetValue(eOption);
                var sansVal = parse.GetValue(sansOption);
                var keyUsageVal = parse.GetValue(keyUsageOption);
                var ekuVal = parse.GetValue(ekuOption);
                var basicCaVal = parse.GetValue(basicCaOption);
                var basicPathLenVal = parse.GetValue(basicPathLenOption);

                if (string.IsNullOrWhiteSpace(privateKey) || !File.Exists(privateKey))
                {
                    Console.WriteLine("Private key file is required and must exist (--private-key path).");
                    return;
                }

                using var key = LoadPrivateKeyFromPem(privateKey);
                var providedAny = cVal != null || stVal != null || lVal != null || oVal != null || ouVal != null ||
                    cnVal != null || eVal != null || sansVal != null || keyUsageVal != null || ekuVal != null ||
                    basicCaVal != null || basicPathLenVal != null;

                string? c = cVal, st = stVal, l = lVal, o = oVal, ou = ouVal, cn = cnVal, e = eVal;
                string? sansInput = sansVal, ku = keyUsageVal, eku = ekuVal;
                var bc = basicCaVal;
                var plcVal = basicPathLenVal;
                var subjectVal = parse.GetValue(subjectOption);
                var rsaPaddingVal = parse.GetValue(rsaPaddingOption);

                if (!providedAny)
                {
                    // Prompt for DN components
                    Console.Write("Country (C): ");
                    c = Console.ReadLine();
                    Console.Write("State or Province (ST): ");
                    st = Console.ReadLine();
                    Console.Write("Locality (L): ");
                    l = Console.ReadLine();
                    Console.Write("Organization (O): ");
                    o = Console.ReadLine();
                    Console.Write("Organizational Unit (OU): ");
                    ou = Console.ReadLine();
                    Console.Write("Common Name (CN): ");
                    cn = Console.ReadLine();
                    Console.Write("Email (E): ");
                    e = Console.ReadLine();

                    // Prompt for SANs
                    Console.Write("Subject Alternative Names (comma separated, leave empty to skip): ");
                    sansInput = Console.ReadLine();

                    // Key Usage
                    Console.Write(
                        "Key Usage (comma separated - e.g. digitalSignature,keyEncipherment; leave empty to skip): ");
                    ku = Console.ReadLine();

                    // EKU
                    Console.Write(
                        "Enhanced Key Usages (comma separated - serverAuth,clientAuth,emailProtection,codeSigning; leave empty to skip): ");
                    eku = Console.ReadLine();

                    // Basic constraints
                    Console.Write("Basic Constraints - CA? (y/N, leave empty to skip): ");
                    var bcInput = Console.ReadLine();
                    if (!string.IsNullOrWhiteSpace(bcInput) &&
                        bcInput.Trim().Equals("y", StringComparison.OrdinalIgnoreCase))
                    {
                        bc = true;
                        Console.Write("Path length constraint (empty for none): ");
                        var plc = Console.ReadLine();
                        if (int.TryParse(plc, out var pathLenVal)) plcVal = pathLenVal;
                    }
                }

                var dnParts = new[]
                {
                    string.IsNullOrWhiteSpace(c) ? null : $"C={c}",
                    string.IsNullOrWhiteSpace(st) ? null : $"ST={st}",
                    string.IsNullOrWhiteSpace(l) ? null : $"L={l}", string.IsNullOrWhiteSpace(o) ? null : $"O={o}",
                    string.IsNullOrWhiteSpace(ou) ? null : $"OU={ou}",
                    string.IsNullOrWhiteSpace(cn) ? null : $"CN={cn}",
                    string.IsNullOrWhiteSpace(e) ? null : $"E={e}"
                }.Where(x => x != null).ToArray();

                var subject = dnParts.Length == 0 ? string.Empty : string.Join(", ", dnParts);
                // If the subject option is provided, prefer it (RFC2253 style). Otherwise use assembled DN.
                var name = !string.IsNullOrWhiteSpace(subjectVal)
                    ? new X500DistinguishedName(subjectVal)
                    : new X500DistinguishedName(subject);

                // Determine RSA padding
                var padding = RSASignaturePadding.Pss;
                if (!string.IsNullOrWhiteSpace(rsaPaddingVal) &&
                    rsaPaddingVal.Trim().Equals("pkcs1", StringComparison.OrdinalIgnoreCase))
                {
                    padding = RSASignaturePadding.Pkcs1;
                }

                var req = key switch
                {
                    RSA rsa => new CertificateRequest(name, rsa, HashAlgorithmName.SHA256, padding),
                    ECDsa ecdsa => new CertificateRequest(name, ecdsa, HashAlgorithmName.SHA256),
                    _ => throw new InvalidOperationException("Unsupported key algorithm")
                };

                if (!string.IsNullOrWhiteSpace(sansInput))
                {
                    var sanBuilder = new SubjectAlternativeNameBuilder();
                    var parts = sansInput.Split(',',
                        StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
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

                    req.CertificateExtensions.Add(sanBuilder.Build());
                }

                if (!string.IsNullOrWhiteSpace(ku))
                {
                    var flags = X509KeyUsageFlags.None;
                    foreach (var part in ku.Split(',',
                        StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    {
                        switch (part.Trim())
                        {
                            case "digitalsignature":
                            case "digitalSignature":
                            case "digital_signature":
                            case "ds":
                            case "digital-signature":
                            case "digital-sign":
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
                                Console.WriteLine($"Unknown key usage: {part}, ignoring.");
                                break;
                        }
                    }

                    req.CertificateExtensions.Add(new X509KeyUsageExtension(flags, true));
                }

                if (!string.IsNullOrWhiteSpace(eku))
                {
                    var oids = new OidCollection();
                    foreach (var part in eku.Split(',',
                        StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    {
                        switch (part.Trim().ToLowerInvariant())
                        {
                            case "serverauth":
                            case "serverAuth":
                            case "server-auth":
                            case "tlsserver":
                            case "tls-server":
                                oids.Add(Oids.ServerAuthenticationPurpose.InitializeOid());
                                break;
                            case "clientauth":
                            case "client-auth":
                            case "tlsclient":
                            case "tls-client":
                            case "clientAuth":
                                oids.Add(Oids.ClientAuthenticationPurpose.InitializeOid());
                                break;
                            case "emailprotection":
                            case "email-protection":
                            case "email":
                            case "smime":
                            case "s/mime":
                                oids.Add(Oids.EmailProtectionPurpose.InitializeOid());
                                break;
                            case "codesigning":
                            case "code-signing":
                            case "code_signing":
                                oids.Add(Oids.CodeSigningPurpose.InitializeOid());
                                break;
                            case "time-stamping":
                            case "timestamping":
                            case "timestamp":
                                oids.Add(Oids.TimeStampingPurpose.InitializeOid());
                                break;
                            default:
                                Console.WriteLine($"Unknown EKU: {part}, ignoring.");
                                break;
                        }
                    }

                    req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(oids, false));
                }

                if (bc == true)
                {
                    var hasPath = plcVal.HasValue;
                    var pathLen = plcVal.GetValueOrDefault();
                    req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, hasPath, pathLen, true));
                }

                var pem = req.ToPkcs10();

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
        if (pem.Contains("RSA PRIVATE KEY") || pem.Contains("BEGIN PRIVATE KEY") ||
            pem.Contains("BEGIN ENCRYPTED PRIVATE KEY"))
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

        if (pem.Contains("EC PRIVATE KEY") || pem.Contains("BEGIN EC PRIVATE KEY"))
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
            // try ECDsa
            var ecdsa2 = ECDsa.Create();
            ecdsa2.ImportFromPem(pem);
            return ecdsa2;
        }
    }
}
