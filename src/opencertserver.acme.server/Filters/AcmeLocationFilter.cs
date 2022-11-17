﻿namespace OpenCertServer.Acme.Server.Filters;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.Routing;

[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
public sealed class AcmeLocationAttribute : Attribute, IFilterMetadata
{
    public AcmeLocationAttribute(string routeName)
    {
        RouteName = routeName;
    }

    public string RouteName { get; }
}

public sealed class AcmeLocationFilter : IActionFilter
{
    private readonly IUrlHelperFactory _urlHelperFactory;

    public AcmeLocationFilter(IUrlHelperFactory urlHelperFactory)
    {
        _urlHelperFactory = urlHelperFactory;
    }

    public void OnActionExecuted(ActionExecutedContext context) 
    {
        var locationAttribute = context.ActionDescriptor.FilterDescriptors
            .Select(x => x.Filter)
            .OfType<AcmeLocationAttribute>()
            .FirstOrDefault();

        if (locationAttribute == null)
        {
            return;
        }

        var urlHelper = _urlHelperFactory.GetUrlHelper(context);

        var locationHeaderUrl = urlHelper.RouteUrl(locationAttribute.RouteName, context.RouteData.Values, "https");
        var locationHeader = $"{locationHeaderUrl}";

        context.HttpContext.Response.Headers.Add("Location", locationHeader);
    }

    public void OnActionExecuting(ActionExecutingContext context)
    { }
}