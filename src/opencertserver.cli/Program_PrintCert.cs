using System;
using System.CommandLine;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using OpenCertServer.Ca.Utils;

namespace opencertserver.cli;

internal static partial class Program
{
    private static void CreatePrintCertificateCommand(RootCommand rootCommand)
    {
        // print-cert command
        var certOption = new Option<string>("--cert") { Description = "Path to the certificate file (PEM format)" };
        var printCertCommand = new Command("print-cert", "Print certificate details") { certOption };
        printCertCommand.SetAction(cert => PrintCert(cert.GetValue(certOption)));

        rootCommand.Add(printCertCommand);
    }

    private static Task PrintCert(string? certPath)
    {
        if (certPath == null)
        {
            Console.WriteLine("No certificate specified.");
            return Task.CompletedTask;
        }
        try
        {
            if (string.IsNullOrWhiteSpace(certPath) || !File.Exists(certPath))
            {
                Console.WriteLine("Certificate file is required and must exist (--cert path).\n");
                return Task.CompletedTask;
            }

            var pem = File.ReadAllText(certPath);
            byte[]? certBytes = null;
            // Try to find PEM block
            const string begin = "-----BEGIN CERTIFICATE-----";
            const string end = "-----END CERTIFICATE-----";
            if (pem.Contains(begin) && pem.Contains(end))
            {
                var start = pem.IndexOf(begin, StringComparison.Ordinal);
                var stop = pem.IndexOf(end, start, StringComparison.Ordinal);
                if (start >= 0 && stop > start)
                {
                    var base64 = pem.Substring(start + begin.Length, stop - (start + begin.Length));
                    base64 = base64.Replace("\r", string.Empty).Replace("\n", string.Empty).Trim();
                    certBytes = Convert.FromBase64String(base64);
                }
            }

            certBytes ??= File.ReadAllBytes(certPath);

            if (certBytes.Length == 0)
            {
                Console.WriteLine("Certificate file did not contain valid PEM or DER data.");
                return Task.CompletedTask;
            }

            X509Certificate2 cert;
            // If original file contains PEM, prefer CreateFromPem which is the recommended API
            if (pem.Contains(begin) && pem.Contains(end))
            {
                cert = X509Certificate2.CreateFromPem(pem);
            }
            else
            {
                cert = X509CertificateLoader.LoadCertificate(certBytes);
            }

            using (cert)
            {
                var text = cert.PrintCertificate();
                Console.WriteLine(text);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error printing certificate: {ex.Message}");
        }

        return Task.CompletedTask;
    }
}
