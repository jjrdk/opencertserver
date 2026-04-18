namespace OpenCertServer.Acme.Server.Endpoints;

using System.Diagnostics;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using OpenCertServer.Acme.Server.Configuration;

public static class DirectoryEndpoints
{
    public static IEndpointRouteBuilder MapDirectoryEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/directory", GetDirectoryHandler).WithName("Directory");
        return endpoints;
    }

    private static IResult GetDirectoryHandler(HttpContext context, IOptions<AcmeServerOptions> optionsAccessor, LinkGenerator links)
    {
        AcmeInstruments.DirectoryRequests.Add(1);
        var sw = Stopwatch.GetTimestamp();
        using var activity = AcmeInstruments.ActivitySource.StartActivity(ActivityNames.Directory);
        try
        {
            var options = optionsAccessor.Value;
            var directory = new OpenCertServer.Acme.Abstractions.HttpModel.Directory
            {
                NewNonce    = GetUrl("NewNonce"),
                NewAccount  = GetUrl("NewAccount"),
                NewOrder    = GetUrl("NewOrder"),
                NewAuthz    = null,
                RevokeCert  = GetUrl("RevokeCert"),
                KeyChange   = GetUrl("KeyChange"),
                Meta = new OpenCertServer.Acme.Abstractions.HttpModel.DirectoryMetadata
                {
                    ExternalAccountRequired = options.ExternalAccountRequired,
                    CAAIdentities           = null,
                    TermsOfService          = options.TOS.RequireAgreement ? options.TOS.Url : null,
                    Website                 = options.WebsiteUrl
                }
            };
            AcmeInstruments.DirectorySuccesses.Add(1);
            activity?.SetStatus(ActivityStatusCode.Ok);
            return Results.Ok(directory);

            string? GetUrl(string routeName) => links.GetUriByName(context, routeName, values: null, scheme: Uri.UriSchemeHttps);
        }
        catch (Exception ex)
        {
            AcmeInstruments.DirectoryFailures.Add(1);
            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
            throw;
        }
        finally
        {
            AcmeInstruments.DirectoryDuration.Record(Stopwatch.GetElapsedTime(sw).TotalSeconds);
        }
    }
}
