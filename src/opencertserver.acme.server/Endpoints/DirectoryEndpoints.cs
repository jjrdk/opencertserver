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

            var directory = new OpenCertServer.Acme.Abstractions.HttpModel.Directory
            {
                NewNonce = GetUrl("NewNonce"),
                NewAccount = GetUrl("NewAccount"),
                NewOrder = GetUrl("NewOrder"),
                NewAuthz = null,
                RevokeCert = GetUrl("RevokeCert"),
                KeyChange = GetUrl("KeyChange"),
                Meta = new OpenCertServer.Acme.Abstractions.HttpModel.DirectoryMetadata
                {
                    ExternalAccountRequired = options.ExternalAccountRequired,
                    CAAIdentities = null,
                    TermsOfService = options.TOS.RequireAgreement ? options.TOS.Url : null,
                    Website = options.WebsiteUrl
                }
            };
            return Results.Ok(directory);

            string? GetUrl(string routeName) => links.GetUriByName(context, routeName, values: null, scheme: Uri.UriSchemeHttps);
        }).WithName("Directory");
        return endpoints;
    }
}
