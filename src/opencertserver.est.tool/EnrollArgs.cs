namespace OpenCertServer.Est.Cli;

using System.Security.Cryptography.X509Certificates;
using CommandLine;

[Verb(
    "enroll",
    true,
    new[] { "e" },
    HelpText = "Requests a certificate based on the passed certificate request",
    Hidden = false)]
public class EnrollArgs
{
    [Option(
        'a',
        "access-token",
        Required = true,
        HelpText =
            "The access token for the enroll request. May be a base64 encoded credential for a basic authentication flow.")]
    public string AccessToken { get; set; } = null!;

    [Option(
        't',
        "type",
        Required = true,
        HelpText = "The type of authentication to perform. Allowed values are: 'Bearer' or 'Basic'")]
    public string AuthenticationType { get; set; } = null!;

    [Option('i', "id-token", Required = false, HelpText = "An optional id token for additional certificate details.")]
    public string? IdToken { get; set; }

    [Option('d', "dn", Required = true, HelpText = "The distinguished name to issue the certificate to.")]
    public string DistinguishedName { get; set; } = null!;

    [Option('k', "key-file", Required = true, HelpText = "The path to the private key file")]
    public string KeyFilePath { get; set; } = null!;

    [Option('u', "usage", Required = true, HelpText = "The usage flags to set in the certificate.")]
    public X509KeyUsageFlags UsageFlags { get; set; } = X509KeyUsageFlags.None;

    [Option('o', "output", Required = false, HelpText = "Optional output file to write the received certificates to.")]
    public string? Output { get; set; }
}
