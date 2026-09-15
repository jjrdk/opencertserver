namespace OpenCertServer.Acme.Yarp;

using System.Collections.Generic;
using System.Text.Json;

/// <summary>
/// Well-known route metadata keys used to mark a YARP route as ACME-enabled and carry a
/// <see cref="RouteAcmeOptions"/> bag.
/// </summary>
public static class AcmeRouteMetadataKeys
{
    /// <summary>
    /// The metadata key under which a <see cref="RouteAcmeOptions"/> is attached to a route.
    /// </summary>
    public const string Options = "acme";
}

/// <summary>
/// Helpers to attach and read a <see cref="RouteAcmeOptions"/> from a YARP route metadata bag.
/// </summary>
public static class RouteAcmeMetadataExtensions
{
    /// <summary>
    /// Builds a YARP <c>RouteConfig</c> with the ACME metadata bag attached. The route metadata
    /// is init-only, so the metadata must be supplied at construction time.
    /// </summary>
    public static global::Yarp.ReverseProxy.Configuration.RouteConfig WithAcmeRoute(
       global::Yarp.ReverseProxy.Configuration.RouteConfig route,
       RouteAcmeOptions options)
    {
        var metadata = route.Metadata is null
            ? new Dictionary<string, string>()
            : new Dictionary<string, string>(route.Metadata);

        metadata[AcmeRouteMetadataKeys.Options] = JsonSerializer.Serialize(
            options,
            RouteAcmeOptionsSerializerContext.Default.RouteAcmeOptions);

        return route with { Metadata = metadata };
    }

    /// <summary>
    /// Reads the <see cref="RouteAcmeOptions"/> attached to a route, if any. Returns null
    /// when the route carries no <c>acme</c> metadata, so the config filter can skip routes
    /// that have not opted into ACME.
    /// </summary>
    public static RouteAcmeOptions? TryReadOptions(global::Yarp.ReverseProxy.Configuration.RouteConfig route)
    {
        if (route.Metadata is null)
        {
            return null;
        }

        if (!route.Metadata.TryGetValue(AcmeRouteMetadataKeys.Options, out var json))
        {
            return null;
        }

        return JsonSerializer.Deserialize<RouteAcmeOptions>(json, RouteAcmeOptionsSerializerContext.Default.RouteAcmeOptions);
    }

    /// <summary>
    /// Reads the <see cref="RouteAcmeOptions"/> attached to a route, defaulting to a disabled
    /// <see cref="RouteAcmeOptions"/> (<see cref="RouteAcmeOptions.Enabled"/> false) when the
    /// metadata bag is absent so an unannotated route is not silently enrolled in issuance.
    /// Prefer <see cref="TryReadOptions"/> when <see langword="null"/> is the correct "no
    /// options" signal.
    /// </summary>
    public static RouteAcmeOptions ReadOptionsOrDefault(global::Yarp.ReverseProxy.Configuration.RouteConfig route)
    {
        var options = TryReadOptions(route);
        if (options != null)
        {
            return options;
        }

        return new RouteAcmeOptions { Enabled = false };
    }
}
