namespace OpenCertServer.Est.Cli;

using System.Security.Cryptography.X509Certificates;
using CommandLine;

[Verb(
    "reenroll",
    true,
    new[] { "re" },
    HelpText = "Requests a certificate renewal based on the passed certificate.",
    Hidden = false)]
public class ReEnrollArgs
{
    [Option('c', "certificate-file", Required = true, HelpText = "The certificate to renew.")]
    public string CertificateFile { get; set; } = null!;
}
