namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using OpenCertServer.Ca.Client;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Ca.Utils.X509Extensions;
using OpenCertServer.Acme.Remote;
using Reqnroll;
using Xunit;

public partial class CertificateServerFeatures
{
    private CaClient? _caClient;
    private X509Certificate2? _caClientIdentity;
    private string? _caClientCsr;
    private string? _caClientChainPem;
    private SignCertificateResponse? _caClientResult;
    private bool _caClientRevoked;
    private Exception? _caClientConfigError;
    private RemoteIssuer? _remoteIssuer;
    private byte[]? _remoteIssuerCert;
    private string? _remoteIssuerError;

    // F4: the CA client's "trusted connection" pins the trust anchor. A presented server certificate
    // that does not terminate at a pinned anchor is rejected even if the system store would trust it.
    private X509Certificate2? _pinnedRoot;
    private X509Certificate2? _unrelatedRoot;
    private bool _anchorChainResult;

    /// <summary>
    /// Builds a backing-CA client authenticated with a bearer token (the RA identity). This is the
    /// "ACME server or RA process issues through a trusted HTTPS connection" wiring.
    /// </summary>
    [Given(@"a backing CA client for ""(.*)""")]
    public void GivenABackingCaClientFor(string dnsName)
    {
        CreateCaClient(dnsName, withClientCertificate: false);
    }

    /// <summary>
    /// Builds a backing-CA client that also presents a client certificate. In-process tests cannot run
    /// a real TLS handshake, so the certificate is forwarded to the server the same way the RA peer test
    /// does, via the <c>X-Client-Cert</c> header.
    /// </summary>
    [Given(@"a backing CA client for ""(.*)"" using its client certificate")]
    public void GivenABackingCaClientUsingClientCertificateFor(string dnsName)
    {
        CreateCaClient(dnsName, withClientCertificate: true);
    }

    private void CreateCaClient(string dnsName, bool withClientCertificate)
    {
        var client = _server.CreateClient();

        X509Certificate2? revokeIdentity = null;
        if (withClientCertificate)
        {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest(
                "CN=ra-tenant-a",
                key,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            var extendedKeyUsage = new OidCollection { new("1.3.6.1.5.5.7.3.2") };
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(extendedKeyUsage, critical: false));
            var ca = _server.Services.GetRequiredService<ICertificateAuthority>();
            var response = ca.SignCertificateRequest(request, "default").GetAwaiter().GetResult();
            revokeIdentity = Assert.IsType<SignCertificateResponse.Success>(response).Certificate.CopyWithPrivateKey(key);
            client.DefaultRequestHeaders.Add(
                "X-Client-Cert",
                Convert.ToBase64String(revokeIdentity.RawData));
        }

        var options = new CaClientOptions
        {
            BaseUrl = new Uri("https://localhost/"),
            Profile = "default",
            DelegatedScope = "tenant-a.example.com",
            BearerToken = "ra-token",
        };

        _caClientIdentity = revokeIdentity;
        _caClient = new CaClient(client, options, NullLogger<CaClient>.Instance);

        using var csrKey = RSA.Create(2048);
        var csr = new CertificateRequest(
            $"CN={dnsName}",
            csrKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        var subjectAlternativeName = new SubjectAlternativeNameBuilder();
        subjectAlternativeName.AddDnsName(dnsName);
        csr.CertificateExtensions.Add(subjectAlternativeName.Build());
        _caClientCsr = PemEncoding.WriteString("CERTIFICATE REQUEST", csr.CreateSigningRequest());
    }

    [When("the client signs a certificate request")]
    public async Task WhenTheClientSignsACertificateRequest()
    {
        Assert.NotNull(_caClient);
        Assert.NotNull(_caClientCsr);
        _caClientResult = await _caClient.SignCsr(_caClientCsr).ConfigureAwait(false);
        if (_caClientResult is SignCertificateResponse.Success success)
        {
            _caClientChainPem = success.Certificate.ToPemChain(success.Issuers);
        }
    }

    [Then("the client receives a CA-issued certificate")]
    public void ThenTheClientReceivesACaIssuedCertificate()
    {
        Assert.True(_caClientResult is SignCertificateResponse.Success);
        Assert.NotNull(_caClientChainPem);
        var certificates = new X509Certificate2Collection();
        certificates.ImportFromPem(_caClientChainPem!);
        Assert.NotEmpty(certificates);
        Assert.Equal("CN=host.tenant-a.example.com", certificates[0].Subject);
    }

    [Then("the client uses HTTPS")]
    public void ThenTheClientUsesHttps()
    {
        Assert.NotNull(_caClient);
        Assert.Equal(Uri.UriSchemeHttps, _caClient.BaseUrl.Scheme);
    }

    [Then("the backing CA reports a signing error")]
    public void ThenTheBackingCaReportsASigningError()
    {
        Assert.NotNull(_caClientResult);
        Assert.False(_caClientResult is SignCertificateResponse.Success);
        Assert.Null(_caClientChainPem);
    }

    [Given("a non-HTTPS backing CA configuration")]
    public void GivenANonHttpsBackingCaConfiguration()
    {
        _caClientConfig = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Ca:RemoteUrl"] = "http://localhost:5001/"
            })
            .Build();
    }

    [When("the backing CA client is built from configuration")]
    public void WhenTheBackingCaClientIsBuiltFromConfiguration()
    {
        Assert.NotNull(_caClientConfig);
        try
        {
            var options = CaClientOptions.FromConfiguration(_caClientConfig!);
            _ = new CaClient(_server.CreateClient(), options, NullLogger<CaClient>.Instance);
        }
        catch (Exception exception)
        {
            _caClientConfigError = exception;
        }
    }

    [Then("the configuration is rejected")]
    public void ThenTheConfigurationIsRejected()
    {
        Assert.NotNull(_caClientConfigError);
    }

    [When("the client revokes the certificate")]
    public async Task WhenTheClientRevokesTheCertificate()
    {
        Assert.NotNull(_caClient);
        Assert.NotNull(_caClientIdentity);
        Assert.NotNull(_caClientChainPem);
        var certificates = new X509Certificate2Collection();
        certificates.ImportFromPem(_caClientChainPem!);
        using var issued = certificates[0];
        _caClientRevoked = await _caClient.Revoke(
            _caClientIdentity!,
            issued.GetSerialNumberString(),
            X509RevocationReason.CessationOfOperation).ConfigureAwait(false);
    }

    [Then("the client revocation succeeds")]
    public void ThenTheClientRevocationSucceeds()
    {
        Assert.True(_caClientRevoked);
    }

    /// <summary>
    /// Builds the ACME-side <see cref="RemoteIssuer"/> on top of the backing-CA client already created.
    /// This is the wiring an ACME host uses to issue through a backing CA over the trusted connection.
    /// </summary>
    [Given("a remote ACME issuer using the client")]
    public void GivenARemoteAcmeIssuerUsingTheClient()
    {
        Assert.NotNull(_caClient);
        _remoteIssuer = new RemoteIssuer(_caClient);
    }

    [When("the remote issuer issues a certificate")]
    public async Task WhenTheRemoteIssuerIssuesACertificate()
    {
        Assert.NotNull(_remoteIssuer);
        Assert.NotNull(_caClientCsr);
        var (certificate, error) = await _remoteIssuer.IssueCertificate(
            "default",
            _caClientCsr,
            [],
            null,
            null,
            CancellationToken.None).ConfigureAwait(false);
        _remoteIssuerCert = certificate;
        _remoteIssuerError = error?.Detail;
    }

    [Then("the remote issuer returns a signed certificate")]
    public void ThenTheRemoteIssuerReturnsASignedCertificate()
    {
        Assert.Null(_remoteIssuerError);
        Assert.NotNull(_remoteIssuerCert);
        var chainPem = System.Text.Encoding.UTF8.GetString(_remoteIssuerCert!);
        var certificates = new X509Certificate2Collection();
        certificates.ImportFromPem(chainPem);
        Assert.NotEmpty(certificates);
        using var leaf = certificates[0];
        Assert.Equal("CN=host.tenant-a.example.com", leaf.Subject);
    }

    /// <summary>
    /// Builds a self-signed root and, for the pinning check, a leaf that either chains to that root
    /// (accepted) or to a different root (rejected).
    /// </summary>
    private X509Certificate2 CreateRoot(string cn)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            cn,
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(10));
    }

    private X509Certificate2 CreateLeafSignedBy(string leafCn, X509Certificate2 issuer)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            leafCn,
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new("1.3.6.1.5.5.7.3.1") }, false));
        return request.Create(
            issuer,
            DateTimeOffset.UtcNow.AddHours(-1),
            DateTimeOffset.UtcNow.AddDays(1),
            RandomNumberGenerator.GetBytes(16));
    }

    [Given("a pinned CA trust anchor")]
    public void GivenAPinnedCaTrustAnchor()
    {
        _pinnedRoot = CreateRoot("CN=Pinned test CA");
        _unrelatedRoot = CreateRoot("CN=Unrelated test CA");
    }

    [When("the CA client is presented with a certificate that does not chain to the pinned anchor")]
    public void WhenTheCaClientIsPresentedWithACertificateThatDoesNotChain()
    {
        Assert.NotNull(_pinnedRoot);
        Assert.NotNull(_unrelatedRoot);
        var pinned = new X509Certificate2Collection { _pinnedRoot! };
        using var leaf = CreateLeafSignedBy("CN=server.example.com", _unrelatedRoot!);
        _anchorChainResult =
            OpenCertServer.Ca.Client.CaClientOptions.ServerCertificateChainsToAnchor(pinned, leaf);
    }

    [When("the CA client is presented with a certificate that chains to the pinned anchor")]
    public void WhenTheCaClientIsPresentedWithACertificateThatChains()
    {
        Assert.NotNull(_pinnedRoot);
        // A leaf that chains to the very root the client pinned must be accepted.
        var pinned = new X509Certificate2Collection { _pinnedRoot! };
        using var leaf = CreateLeafSignedBy("CN=server.example.com", _pinnedRoot!);
        _anchorChainResult =
            OpenCertServer.Ca.Client.CaClientOptions.ServerCertificateChainsToAnchor(pinned, leaf);
    }

    [Then("the certificate is rejected")]
    public void ThenTheCertificateIsRejected()
    {
        Assert.False(_anchorChainResult);
    }

    [Then("the certificate is accepted")]
    public void ThenTheCertificateIsAccepted()
    {
        Assert.True(_anchorChainResult);
    }

    private IConfiguration? _caClientConfig;

    [AfterScenario]
    public void DisposeCaClient()
    {
        _caClientIdentity?.Dispose();
        _pinnedRoot?.Dispose();
        _unrelatedRoot?.Dispose();
    }
}
