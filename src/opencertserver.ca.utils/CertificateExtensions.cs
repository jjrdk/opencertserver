namespace OpenCertServer.Ca.Utils;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

/// <summary>
/// Provides extension helpers for working with <see cref="X509Certificate2"/> instances.
/// </summary>
public static class CertificateExtensions
{
    extension(X509Certificate2 cert)
    {
        /// <summary>
        /// Produce a detailed, human-readable text representation of an X509Certificate2 similar to openssl x509 -text.
        /// </summary>
        public string PrintCertificate()
        {
            var sb = new StringBuilder();

            sb.AppendLine("Certificate:");
            sb.AppendLine("\tData:");

            // Version
            var version = cert.Version;
            sb.AppendLine($"\t\tVersion: {version} (0x{(version - 1):x})");

            // Serial Number
            sb.AppendLine("\t\tSerial Number:");
            var serial = cert.SerialNumber;
            var serialBytes = Convert.FromHexString(serial);
            sb.Append(FormatHexLines(serialBytes, 12, "\t\t\t", ":"));

            // Signature algorithm
            var sigAlg = cert.SignatureAlgorithm.FriendlyName ?? cert.SignatureAlgorithm.Value ?? "unknown";
            sb.AppendLine($"\t\tSignature Algorithm: {sigAlg}");

            // Issuer
            sb.AppendLine("\t\tIssuer:");
            sb.Append(FormatName(cert.IssuerName, "\t\t\t"));

            // Validity
            var nowUtc = DateTime.UtcNow;
            var notBefore = cert.NotBefore.ToUniversalTime();
            var notAfter = cert.NotAfter.ToUniversalTime();
            var expired = nowUtc > notAfter;
            sb.AppendLine($"\t\tValidity {(expired ? "(Expired)" : string.Empty)}");
            sb.AppendLine($"\t\t\tNot Before: {notBefore.ToString("MMM dd HH:mm:ss yyyy 'GMT'")}");
            sb.AppendLine($"\t\t\tNot After : {notAfter.ToString("MMM dd HH:mm:ss yyyy 'GMT'")}");

            // Subject
            sb.AppendLine("\t\tSubject:");
            sb.Append(FormatName(cert.SubjectName, "\t\t\t"));

            // Subject Public Key Info
            sb.AppendLine("\t\tSubject Public Key Info:");
            var pubOid = cert.PublicKey.Oid.FriendlyName ?? cert.PublicKey.Oid.Value ?? "unknown";
            sb.AppendLine($"\t\t\tPublic Key Algorithm: {pubOid}");

            try
            {
                using var rsa = cert.GetRSAPublicKey();
                if (rsa != null)
                {
                    var rsaParams = rsa.ExportParameters(false);
                    var modulus = rsaParams.Modulus;
                    var exponent = rsaParams.Exponent;
                    if (modulus != null && modulus.Length > 0)
                    {
                        var bits = (modulus.Length - LeadingZeroCount(modulus)) * 8;
                        sb.AppendLine($"\t\t\t\tRSA Public-Key: ({bits} bit)");
                        sb.AppendLine("\t\t\t\tModulus:");
                        sb.Append(FormatHexLines(modulus, 16, "\t\t\t\t\t", ":"));
                    }

                    if (exponent != null && exponent.Length > 0)
                    {
                        var expHex = "0x" + BitConverter.ToString(exponent).Replace("-", "");
                        string expStr;
                        if (exponent.Length <= 8)
                        {
                            var dec = exponent.Aggregate<byte, long>(0, (current, t) => (current << 8) + t);

                            expStr = $"{dec} ({expHex})";
                        }
                        else
                        {
                            expStr = expHex;
                        }

                        sb.AppendLine($"\t\t\t\tExponent: {expStr}");
                    }
                }
            }
            catch
            {
                // ignore
            }

            // Extensions
            sb.AppendLine("\t\tX509v3 extensions:");
            foreach (var ext in cert.Extensions)
            {
                try
                {
                    var oid = ext.Oid?.Value ?? string.Empty;
                    switch (oid)
                    {
                        case "2.5.29.15": // Key Usage
                        {
                            var ku = new X509KeyUsageExtension(ext, ext.Critical);
                            sb.AppendLine($"\t\t\tX509v3 Key Usage: ");
                            var names = KeyUsageNames(ku.KeyUsages);
                            sb.AppendLine($"\t\t\t\t{string.Join(", ", names)}");
                            break;
                        }
                        case "2.5.29.37": // EKU
                        {
                            var eku = new X509EnhancedKeyUsageExtension(ext, ext.Critical);
                            sb.AppendLine($"\t\t\tX509v3 Extended Key Usage: ");
                            var list = eku.EnhancedKeyUsages.Cast<Oid>().Select(o => OidFriendlyName(o));
                            sb.AppendLine($"\t\t\t\t{string.Join(", ", list)}");
                            break;
                        }
                        case "2.5.29.14": // Subject Key Identifier
                        {
                            var skid = new X509SubjectKeyIdentifierExtension(ext, ext.Critical);
                            sb.AppendLine($"\t\t\tX509v3 Subject Key Identifier:");
                            sb.AppendLine($"\t\t\t\t{skid.SubjectKeyIdentifier}");
                            break;
                        }
                        case "2.5.29.35": // Authority Key Identifier
                        {
                            sb.AppendLine($"\t\t\tX509v3 Authority Key Identifier:");
                            var formatted = ext.Format(true).Trim();
                            sb.Append(FormatMultiline(formatted, "\t\t\t\t"));
                            break;
                        }
                        default:
                        {
                            var name = ext.Oid?.FriendlyName ?? ext.Oid?.Value ?? "<unknown>";
                            sb.AppendLine($"\t\t\t{name}: ");
                            var raw = ext.RawData;
                            sb.Append(FormatHexDumpWithOffsets(raw, "\t\t\t\t"));
                            break;
                        }
                    }
                }
                catch (Exception ex)
                {
                    var oidVal = ext.Oid?.Value ?? "<unknown>";
                    sb.AppendLine($"\t\t\t{oidVal}: (error formatting extension: {ex.Message})");
                }
            }

            // Signature
            var sigAlgText = cert.SignatureAlgorithm.FriendlyName ?? cert.SignatureAlgorithm.Value ?? "unknown";
            sb.AppendLine();
            sb.AppendLine($"\tSignature Algorithm: {sigAlgText}");
            var sigRaw = GetSignature(cert);
            sb.Append(FormatHexLines(sigRaw, 16, "\t\t ", ":"));

            return sb.ToString();
        }
    }

    /// <summary>
    /// Executes the FormatName operation.
    /// </summary>
    private static string FormatName(X500DistinguishedName name, string indent)
    {
        var raw = name.Name;
        var parts = raw.Split([','], StringSplitOptions.RemoveEmptyEntries).Select(p => p.Trim()).ToArray();
        if (parts.Length == 0) return indent + "<empty>\n";

        var sb = new StringBuilder();
        foreach (var part in parts)
        {
            var idx = part.IndexOf('=');
            if (idx <= 0)
            {
                sb.AppendLine(indent + part);
                continue;
            }

            var k = part[..idx].Trim();
            var v = part[(idx + 1)..].Trim();
            var key = k switch
            {
                "CN" => "commonName",
                "OU" => "organizationalUnitName",
                "O" => "organizationName",
                "L" => "localityName",
                "ST" => "stateOrProvinceName",
                "C" => "countryName",
                "DC" => "domainComponent",
                _ => k
            };

            sb.AppendLine($"{indent}{key.PadRight(25)} = {v}");
        }

        return sb.ToString();
    }

    /// <summary>
    /// Executes the FormatHexLines operation.
    /// </summary>
    private static string FormatHexLines(byte[] data, int bytesPerLine, string indent, string sep)
    {
        if (data.Length == 0) return indent + "<none>\n";
        var hexPairs = data.Select(b => b.ToString("x2")).ToArray();
        var sb = new StringBuilder();
        for (var i = 0; i < hexPairs.Length; i += bytesPerLine)
        {
            var slice = hexPairs.Skip(i).Take(bytesPerLine);
            sb.AppendLine($"{indent}{string.Join(sep, slice)}");
        }

        return sb.ToString();
    }

    /// <summary>
    /// Executes the LeadingZeroCount operation.
    /// </summary>
    private static int LeadingZeroCount(byte[] data)
    {
        var i = 0;
        while (i < data.Length && data[i] == 0) i++;
        return i;
    }

    /// <summary>
    /// Executes the KeyUsageNames operation.
    /// </summary>
    private static ReadOnlySpan<string> KeyUsageNames(X509KeyUsageFlags flags)
    {
        var list = new List<string>();
        if (flags.HasFlag(X509KeyUsageFlags.DigitalSignature)) list.Add("Digital Signature");
        if (flags.HasFlag(X509KeyUsageFlags.NonRepudiation)) list.Add("Non Repudiation");
        if (flags.HasFlag(X509KeyUsageFlags.KeyEncipherment)) list.Add("Key Encipherment");
        if (flags.HasFlag(X509KeyUsageFlags.DataEncipherment)) list.Add("Data Encipherment");
        if (flags.HasFlag(X509KeyUsageFlags.KeyAgreement)) list.Add("Key Agreement");
        if (flags.HasFlag(X509KeyUsageFlags.KeyCertSign)) list.Add("Key Cert Sign");
        if (flags.HasFlag(X509KeyUsageFlags.CrlSign)) list.Add("CRL Sign");
        if (flags.HasFlag(X509KeyUsageFlags.EncipherOnly)) list.Add("Encipher Only");
        if (flags.HasFlag(X509KeyUsageFlags.DecipherOnly)) list.Add("Decipher Only");
        if (list.Count == 0) list.Add("<none>");
        return CollectionsMarshal.AsSpan(list);
    }

    /// <summary>
    /// Executes the OidFriendlyName operation.
    /// </summary>
    private static string OidFriendlyName(Oid? o)
    {
        if (o == null) return "<unknown>";
        if (!string.IsNullOrEmpty(o.FriendlyName)) return o.FriendlyName;
        if (!string.IsNullOrEmpty(o.Value))
        {
            return o.Value switch
            {
                Oids.ServerAuthenticationPurpose => "TLS Web Server Authentication",
                Oids.ClientAuthenticationPurpose => "TLS Web Client Authentication",
                Oids.CodeSigningPurpose => "Code Signing",
                Oids.EmailProtectionPurpose => "Email Protection",
                _ => o.Value
            };
        }

        return "<unknown>";
    }

    /// <summary>
    /// Executes the FormatMultiline operation.
    /// </summary>
    private static string FormatMultiline(string s, string indent)
    {
        var lines = s.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
        var sb = new StringBuilder();
        foreach (var line in lines) sb.AppendLine(indent + line.Trim());
        return sb.ToString();
    }

    /// <summary>
    /// Executes the FormatHexDumpWithOffsets operation.
    /// </summary>
    private static string FormatHexDumpWithOffsets(byte[] data, string indent)
    {
        if (data.Length == 0) return $"{indent}<none>\n";

        var sb = new StringBuilder();
        var offset = 0;
        while (offset < data.Length)
        {
            var line = data.Skip(offset).Take(16).ToArray();
            var hex = string.Join(" ", line.Select(b => b.ToString("x2")));
            if (line.Length > 8)
            {
                var first = string.Join(" ", line.Take(8).Select(b => b.ToString("x2")));
                var second = string.Join(" ", line.Skip(8).Select(b => b.ToString("x2")));
                hex = first + " " + second;
            }

            var ascii = string.Concat(line.Select(b => b >= 32 && b <= 126 ? (char)b : '.'));
            sb.AppendLine($"{indent}{offset.ToString("X4")} - {hex.PadRight(47)}   {ascii}");
            offset += line.Length;
        }

        return sb.ToString();
    }

    /// <summary>
    /// Executes the GetSignature operation.
    /// </summary>
    private static byte[] GetSignature(X509Certificate2 cert)
    {
        try
        {
            return cert.GetCertHash();
        }
        catch
        {
            return [];
        }
    }
}
