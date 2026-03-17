namespace opencertserver.cli;

using System;
using System.CommandLine;
using System.Threading.Tasks;

internal static partial class Program
{
    private static void CreateSignCsrCommand(RootCommand rootCommand)
    {
        // sign-csr command
        var csrOption = new Option<string>("--csr") { Description = "Path to the CSR file (PEM format)" };
        var caKeyOption = new Option<string>("--ca-key") { Description = "Path to the CA private key (PEM format)" };
        var caCertOption = new Option<string>("--ca-cert") { Description = "Path to the CA certificate (PEM format)" };
        var outOption = new Option<string>("--out")
            { Description = "Output path for the signed certificate (PEM format)" };
        var signCsrCommand = new Command("sign-csr")
        {
            Description = "Sign a certificate signing request (CSR)", Options =
            {
                csrOption,
                caKeyOption,
                caCertOption,
                outOption
            }
        };
        signCsrCommand.SetAction(SignCsr);
        rootCommand.Add(signCsrCommand);
        return;

        // Handler for sign-csr
        Task SignCsr(ParseResult parseResult)
        {
            var csr = parseResult.GetValue(csrOption);
            var caKey = parseResult.GetValue(caKeyOption);
            var caCert = parseResult.GetValue(caCertOption);
            var outPath = parseResult.GetValue(outOption);

            //string csr, string caKey, string caCert, string outPath
            // TODO: Implement using opencertserver.ca logic
            Console.WriteLine($"Signing CSR: {csr} with CA key: {caKey} and CA cert: {caCert}. Output: {outPath}");
            return Task.CompletedTask;
        }
    }
}
