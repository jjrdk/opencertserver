namespace OpenCertServer.Acme.Abstractions.AcmeRoute;

/// <summary>
/// Well-known route identifiers used by the per-route ACME model.
/// </summary>
public static class AcmeRouteConstants
{
    /// <summary>
    /// The route id used when no YARP route is ACME-tagged. This preserves the legacy
    /// single-listener behaviour: a certificate persisted under this id is served for any
    /// SNI host that does not match a registered ACME route.
    /// </summary>
    public const string DefaultRouteId = "__default__";
}
