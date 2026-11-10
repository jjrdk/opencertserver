namespace OpenCertServer.Acme.Server.Services;

/// <summary>
/// Names a single DNS resolver that acts as a Network Perspective for
/// Multi-Perspective Issuance Corroboration (CA/Browser Forum TLS Baseline
/// Requirements §3.2.2.9).
/// </summary>
/// <param name="Name">
/// A stable, operator-facing name for the perspective (normally the configured
/// DoH URL or <c>DnsEndpoint</c> value).
/// </param>
/// <param name="Resolver">The resolver that queries this perspective.</param>
public sealed record DnsPerspective(string Name, IDnsResolver Resolver);
