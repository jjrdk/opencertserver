namespace OpenCertServer.Acme.Server.Filters;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

public sealed class AcmeIndexLinkFilter : IEndpointFilter
{
    private readonly LinkGenerator _linkGenerator;

    public AcmeIndexLinkFilter(LinkGenerator linkGenerator)
    {
        _linkGenerator = linkGenerator;
    }

    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var linkHeaderUrl =
            _linkGenerator.GetPathByRouteValues(
                routeName: "Directory",
                httpContext: context.HttpContext,
                options: new LinkOptions { LowercaseUrls = true }); //, null, "https");
        var linkHeader = $"<{linkHeaderUrl}>;rel=\"index\"";

        context.HttpContext.Response.GetTypedHeaders().Set("Link", linkHeader);
        return await next(context);
    }
}
