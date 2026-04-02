using System;
using System.Collections.Generic;
using System.CommandLine;
using System.CommandLine.Parsing;
using System.Linq;
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

        var estCaOptions = new Option<IList<string>>("--est-ca")
        {
            Description =
                "Path to an EST CA certificate to trust explicitly (can specify multiple times for multiple CAs)",
            AllowMultipleArgumentsPerToken = true
        };
        var taModeOption = new Option<EstTrustAnchorMode>("--ta-mode")
        {
            Description = "Trust anchor mode: implicit, explicit, or explicit-then-implicit (default: implicit)",
            CustomParser = r =>
            {
                if (r.Tokens.Where(token => token.Type == TokenType.Argument).Select(token => token.Value)
                        .FirstOrDefault() is { } value)
                {
                    return value.ToLower() switch
                    {
                        "implicit" => EstTrustAnchorMode.ImplicitOnly,
                        "explicit" => EstTrustAnchorMode.ExplicitOnly,
                        "explicit-then-implicit" => EstTrustAnchorMode.ExplicitThenImplicit,
                        _ => throw new ArgumentException(
                            "Invalid trust anchor mode. Valid values are: implicit, explicit, explicit-then-implicit.")
                    };
                }

                return EstTrustAnchorMode.ImplicitOnly;
            }
        };

        var cmd = new Command("est-server-certificates", "Fetch the EST server's CA certificates")
        {
            urlOption,
            profileOption,
            taModeOption,
            estCaOptions
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

            var taMode = parse.GetValue(taModeOption);
            var estCaPaths = parse.GetValue(estCaOptions) ?? [];
            try
            {
                var options = new EstClientOptions
                {
                    AuthorizedUri = baseUri,
                    TrustAnchorMode = taMode
                };

                foreach (var path in estCaPaths)
                {
                    options.ExplicitTrustAnchors.Add(X509CertificateLoader.LoadCertificateFromFile(path));
                }

                using var estClient =
                    new EstClient(baseUri, options, messageHandler: MessageHandlerFactory(), profileName: profile);
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
