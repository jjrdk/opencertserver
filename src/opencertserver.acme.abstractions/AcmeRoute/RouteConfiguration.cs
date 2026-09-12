namespace OpenCertServer.Acme.Abstractions.Acme;

using CertesSlim.Extensions;

/// <summary>
/// A concrete, immutable <see cref="IAcmeRouteConfiguration"/>.
/// </summary>
public sealed record RouteConfiguration(
    string RouteId,
    IReadOnlyList<string> Hosts,
    string? CommonName = null,
    CsrInfo? CertificateSigningRequest = null) : IAcmeRouteConfiguration
{
}
