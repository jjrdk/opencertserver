using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using OpenCertServer.Acme.Server.Configuration;

namespace OpenCertServer.Acme.Server.Endpoints;

public static class DirectoryEndpoints
{
    public static IEndpointRouteBuilder MapDirectoryEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/directory", (HttpContext context, IOptions<AcmeServerOptions> optionsAccessor, LinkGenerator links) =>
        {
            var options = optionsAccessor.Value;
            var req = context.Request;

            var directory = new OpenCertServer.Acme.Abstractions.HttpModel.Directory
            {
                NewNonce = GetUrl("NewNonce"),
                NewAccount = GetUrl("NewAccount"),
                NewOrder = GetUrl("NewOrder"),
                NewAuthz = null,
                RevokeCert = null,
                KeyChange = GetUrl("KeyChange"),
                Meta = new OpenCertServer.Acme.Abstractions.HttpModel.DirectoryMetadata
                {
                    ExternalAccountRequired = false,
                    CAAIdentities = null,
                    TermsOfService = options.TOS.RequireAgreement ? options.TOS.Url : null,
                    Website = options.WebsiteUrl
                }
            };
            return Results.Ok(directory);

            // Use LinkGenerator to generate absolute URLs for endpoints
            string? GetUrl(string routeName) => links.GetUriByName(context, routeName, values: null, scheme: req.Scheme, host: req.Host);
        }).WithName("Directory");
        return endpoints;
    }
}
