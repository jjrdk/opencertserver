namespace OpenCertServer.Acme.Yarp.Tests;

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Acme.AspNetClient.Certes;
using Acme.AspNetClient.Persistence;
using CertesSlim.Acme;
using NSubstitute;

/// <summary>
/// A fake <see cref="IAcmeClient"/> that provisions certificates in-process, without contacting a
/// real ACME server. Each call to <see cref="PlaceOrder"/> records the domains (route SANs) it was
/// asked for, and <see cref="FinalizeOrder"/> mints a fresh self-signed certificate whose subject
/// reflects the first requested domain. The SNI selection under test is host-based (via the route
/// scope), so the certificate need not itself carry the SANs.
/// </summary>
public sealed class InMemoryAcmeClient : IAcmeClient
{
    public InMemoryAcmeClient()
    {
        ThrownDuringPlaceOrder = null;
    }

    /// <summary>When non-null, <see cref="PlaceOrder"/> throws with this exception (for failure-isolation tests).</summary>
    public Exception? ThrownDuringPlaceOrder { get; set; }

    /// <summary>The last set of domains (route SANs) the client was asked to order a certificate for.</summary>
    public string[]? LastOrderDomains { get; private set; }

    public Task<PlacedOrder> PlaceOrder(string[] domains)
    {
        if (ThrownDuringPlaceOrder != null)
        {
            return Task.FromException<PlacedOrder>(ThrownDuringPlaceOrder);
        }

        LastOrderDomains = [.. domains];

        var challengeDtos = domains
              .Select(d => new ChallengeDto(Guid.NewGuid().ToString(), d, [d]))
              .ToArray();

        var order = Substitute.For<IOrderContext>();
        var challengeContexts = Array.Empty<IChallengeContext>();

        return Task.FromResult(new PlacedOrder(challengeDtos, order, challengeContexts));
    }

    public Task<(X509Certificate2 Certificate, string KeyPem, X509Certificate2Collection Collection)> FinalizeOrder(
        PlacedOrder placedOrder,
        string password,
        string? existingKeyPem = null)
    {
        var domains = placedOrder.Challenges
               .Where(c => c.Domains is not null)
               .SelectMany(c => c.Domains!)
               .Where(d => !string.IsNullOrWhiteSpace(d))
               .Distinct()
               .OrderBy(d => d, StringComparer.Ordinal)
               .ToArray();

        var commonName = domains.Length > 0 ? domains[0] : "self-signed.example.com";

        var cert = Mint(commonName);
        var keyPem = ExportKeyPem(cert);

        var collection = new X509Certificate2Collection { cert };

        return Task.FromResult<(X509Certificate2, string, X509Certificate2Collection)>((cert, keyPem, collection));
    }

    private static string ExportKeyPem(X509Certificate2 cert)
    {
        var rsa = cert.GetRSAPrivateKey();
        if (rsa != null)
        {
            return rsa.ExportRSAPrivateKeyPem();
        }

        var ecdsa = cert.GetECDsaPrivateKey();
        if (ecdsa != null)
        {
            return ecdsa.ExportECPrivateKeyPem();
        }

        return string.Empty;
    }

    private static X509Certificate2 Mint(string commonName)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={commonName}", ecdsa, HashAlgorithmName.SHA256);

        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
         DateTimeOffset.UtcNow.AddDays(90));

        var pfx = certificate.Export(X509ContentType.Pkcs12, string.Empty);
        return X509CertificateLoader.LoadPkcs12(pfx, string.Empty);
    }
}
