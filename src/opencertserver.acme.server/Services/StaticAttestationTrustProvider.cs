namespace OpenCertServer.Acme.Server.Services;

using System.Security.Cryptography.X509Certificates;
using Abstractions.Services;

/// <summary>
/// An <see cref="IAttestationTrustProvider"/> backed by a fixed certificate collection.
/// Used in tests and production registrations where roots are loaded at startup.
/// </summary>
public sealed class StaticAttestationTrustProvider : IAttestationTrustProvider
{
    private readonly X509Certificate2Collection _roots;

    public StaticAttestationTrustProvider(X509Certificate2Collection roots)
    {
        _roots = roots;
    }

    public X509Certificate2Collection GetTrustedRoots() => _roots;
}
