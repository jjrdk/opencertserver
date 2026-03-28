using System;
using System.CommandLine;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using OpenCertServer.Est.Client;

namespace opencertserver.cli;

internal static partial class Program
{
    private static void CreateEstServerCertificatesCommand(RootCommand rootCommand)
    {
        var urlOption = new Option<string>("--url")
        {
            Description = "HTTPS base URL for the EST server"
        };

        var profileOption = new Option<string>("--profile")
        {
            Description = "The name of the est-server profile"
        };

        var cmd = new Command("est-server-certificates", "Fetch the EST server's CA certificates")
        {
            urlOption
        };
        cmd.SetAction(FetchServerCertificates);
        rootCommand.Add(cmd);

        async Task FetchServerCertificates(ParseResult parse)
        {
            var url = parse.GetValue(urlOption);
            if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out var baseUri) ||
                baseUri.Scheme != Uri.UriSchemeHttps)
            {
                Console.WriteLine("EST server URL is required and must be HTTPS (--url https://...)");
                return;
            }

            var profile = parse.GetValue(profileOption);

            try
            {
                using var estClient =
                    new EstClient(baseUri, messageHandler: MessageHandlerFactory(), profileName: profile);
                var collection = await estClient.ServerCertificates().ConfigureAwait(false);
                if (collection.Count == 0)
                {
                    Console.WriteLine("EST server did not return any certificates.");
                    return;
                }

                var builder = new StringBuilder();
                foreach (var cert in collection)
                {
                    builder.AppendLine(cert.ExportCertificatePem());
                }

                Console.Write(builder.ToString());
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error reading EST server certificates: {ex.Message}");
            }
        }
    }
}
