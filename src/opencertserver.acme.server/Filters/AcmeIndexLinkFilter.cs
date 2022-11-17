namespace OpenCertServer.Acme.Server.Filters;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.Routing;

public sealed class AcmeIndexLinkFilter : IActionFilter
{
    private readonly IUrlHelperFactory _urlHelperFactory;

    public AcmeIndexLinkFilter(IUrlHelperFactory urlHelperFactory)
    {
        _urlHelperFactory = urlHelperFactory;
    }

    public void OnActionExecuted(ActionExecutedContext context) { }

    public void OnActionExecuting(ActionExecutingContext context)
    {
        var urlHelper = _urlHelperFactory.GetUrlHelper(context);

        var linkHeaderUrl = urlHelper.RouteUrl("Directory", null, "https");
        var linkHeader = $"<{linkHeaderUrl}>;rel=\"index\"";

        context.HttpContext.Response.Headers.Add("Link", linkHeader);
    }
}