namespace OpenCertServer.Acme.Abstractions.Acme;

using CertesSlim.Extensions;

/// <summary>
/// Describes a single ACME certificate request that is scoped to a YARP route.
/// </summary>
/// <remarks>
/// Each <see cref="IAcmeRouteConfiguration"/> is an independent ACME order: the
/// <see cref="Hosts"/> become the certificate's subject alternative names (SANs),
/// and the resulting leaf is stored in a route-scoped location so that multiple
/// simultaneous TLS certificates can be selected by SNI.
/// </remarks>
public interface IAcmeRouteConfiguration
{
     /// <summary>
     /// The route identifier. For a YARP route this is the <c>RouteConfig.RouteId</c>;
     /// it is also used as the persistence storage key for the route's leaf/chain/key.
     /// </summary>
    string RouteId { get; }

     /// <summary>
     /// The hostnames this route serves. These become the certificate SANs. For a YARP
     /// route this mirrors <c>RouteConfig.Match.Hosts</c>.
     /// </summary>
    IReadOnlyList<string> Hosts { get; }

     /// <summary>
     /// Optional common name for the certificate. When null the first host is used.
     /// </summary>
    string? CommonName { get; }

     /// <summary>
     /// Optional CSR override for this route. When null the global CSR is used.
     /// </summary>
    CsrInfo? CertificateSigningRequest { get; }
}
