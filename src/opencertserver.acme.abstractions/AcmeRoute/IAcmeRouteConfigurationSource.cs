namespace OpenCertServer.Acme.Abstractions.AcmeRoute;

/// <summary>
/// Provides the set of ACME route configurations that the renewal service iterates.
/// </summary>
public interface IAcmeRouteConfigurationSource
{
    /// <summary>
    /// Gets all registered ACME route configurations. An empty sequence means that no
    /// route is ACME-tagged and the renewal service falls back to the default route scope.
    /// </summary>
    IEnumerable<IAcmeRouteConfiguration> GetRouteConfigurations();
}
