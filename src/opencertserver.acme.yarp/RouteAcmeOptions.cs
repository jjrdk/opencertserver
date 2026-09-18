namespace OpenCertServer.Acme.Yarp;

using System.Collections.Generic;

/// <summary>
/// Strongly typed ACME options attached to a YARP route. This is the "metadata bag" that the
/// <see cref="AddAcmeRoutesConfigFilter"/> reads for each <c>RouteConfig</c>. It is kept a flat
/// POCO (string/bool fields only) so that it can be serialized to the route metadata bag and is
/// AOT/trimming-safe via <see cref="RouteAcmeOptionsSerializerContext"/>.
/// </summary>
public sealed class RouteAcmeOptions
{
    /// <summary>
    /// When true the route participates in ACME. Defaults to true when present.
    /// </summary>
    public bool Enabled { get; init; } = true;

    /// <summary>
    /// The hostnames this route's certificate is requested for (SANs). When null or empty the
    /// route's <c>Match.Hosts</c> are used as the SANs.
    /// </summary>
    public List<string> Hosts { get; init; } = [];

    /// <summary>
    /// Optional common name. When null the first host is used.
    /// </summary>
    public string? CommonName { get; init; }

    /// <summary>
    /// Optional country code (X.509 <c>C</c>) override for this route.
    /// </summary>
    public string? CountryName { get; init; }

    /// <summary>
    /// Optional organization (X.509 <c>O</c>) override for this route.
    /// </summary>
    public string? Organization { get; init; }
}
