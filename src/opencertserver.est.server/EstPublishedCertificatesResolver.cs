namespace OpenCertServer.Est.Server;

using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Resolves the EST CA certificates that should be published from the <c>/cacerts</c> endpoint.
/// </summary>
/// <param name="profileName">The optional EST profile name.</param>
/// <param name="cancellationToken">The cancellation token.</param>
/// <returns>The CA certificates to publish for the requested profile.</returns>
public delegate Task<X509Certificate2Collection> EstPublishedCertificatesResolver(
    string? profileName,
    CancellationToken cancellationToken = default);

