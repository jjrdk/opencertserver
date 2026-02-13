namespace OpenCertServer.Acme.Server.Filters;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Net.Http.Headers;
using Microsoft.AspNetCore.Mvc.Filters;

[AttributeUsage(AttributeTargets.Method)]
public sealed class AcmeLocationAttribute : Attribute, IFilterMetadata
{
    public AcmeLocationAttribute(string routeName)
    {
        RouteName = routeName;
    }

    public string RouteName { get; }
}

public sealed class AcmeLocationFilter : IEndpointFilter
{
    private readonly LinkGenerator _linkGenerator;

    public AcmeLocationFilter(LinkGenerator linkGenerator)
    {
        _linkGenerator = linkGenerator;
    }

    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var locationAttribute =context.HttpContext.GetEndpoint()?.Metadata.GetMetadata<AcmeLocationAttribute>();
        if (locationAttribute == null)
        {
            return await next(context);
        }
        var locationHeaderUrl = _linkGenerator.GetUriByRouteValues(context.HttpContext,
            locationAttribute.RouteName,
            context.HttpContext.Request.RouteValues, Uri.UriSchemeHttps);
        var locationHeader = $"{locationHeaderUrl}";

        context.HttpContext.Response.GetTypedHeaders().Set(HeaderNames.Location, locationHeader);
        return await next(context);
    }
}
