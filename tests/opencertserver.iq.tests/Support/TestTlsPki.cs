namespace OpenCertServer.Iq.Tests.Support;

using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Test-only TLS PKI for the server's Kestrel endpoint: a throw-away root that the client container
/// installs as a system trust anchor, and a leaf naming every server network alias. It is separate
/// from the CA under test, whose issuing certificates the scenarios fetch from the server itself.
/// </summary>
internal sealed class TestTlsPki : IDisposable
{
    private TestTlsPki(X509Certificate2 root, string leafPem, string leafKeyPem)
    {
        Root = root;
        LeafPem = leafPem;
        LeafKeyPem = leafKeyPem;
    }

    public X509Certificate2 Root { get; }

    public string RootPem => Root.ExportCertificatePem();

    public string LeafPem { get; }

    public string LeafKeyPem { get; }

    public static TestTlsPki Create(params string[] dnsNames)
    {
        var now = DateTimeOffset.UtcNow;
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rootRequest = new CertificateRequest("CN=OpenCertServer IQ TLS Root", rootKey, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        rootRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));
        var root = rootRequest.CreateSelfSigned(now.AddMinutes(-5), now.AddDays(2));

        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafRequest = new CertificateRequest($"CN={dnsNames[0]}", leafKey, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        foreach (var name in dnsNames)
        {
            san.AddDnsName(name);
        }

        leafRequest.CertificateExtensions.Add(san.Build());
        leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        leafRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        leafRequest.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        leafRequest.CertificateExtensions.Add(
            X509AuthorityKeyIdentifierExtension.CreateFromCertificate(root, true, false));
        using var leaf = leafRequest.Create(
            root,
            now.AddMinutes(-5),
            now.AddDays(1),
            RandomNumberGenerator.GetBytes(16));
        return new TestTlsPki(root, leaf.ExportCertificatePem(), leafKey.ExportPkcs8PrivateKeyPem());
    }

    /// <summary>
    /// Validates the server chain against <see cref="Root"/> only. The host reaches the server through a
    /// mapped localhost port, so the host-name mismatch is the one error tolerated here.
    /// </summary>
    public HttpMessageHandler CreateTrustingHandler() =>
        new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, certificate, _, errors) =>
            {
                if (certificate == null || errors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable))
                {
                    return false;
                }

                using var chain = new X509Chain();
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(Root);
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                return chain.Build(certificate);
            }
        };

    public void Dispose() => Root.Dispose();
}
