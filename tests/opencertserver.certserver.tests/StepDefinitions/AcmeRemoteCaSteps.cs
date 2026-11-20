namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertesSlim.Acme;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using OpenCertServer.Acme.Remote;
using OpenCertServer.Ca.Client;
using OpenCertServer.Ca.Utils.Ca;
using Reqnroll;
using Xunit;

public partial class CertificateServerFeatures
{
    private CaClient? _acmeRemoteCaClient;
    private RemoteIssuer? _acmeRemoteIssuer;
    private InMemoryCertificateStore? _acmeRemoteCertificateStore;
    private X509Certificate2? _acmeRemoteRevokeIdentity;
    private string? _acmeRemoteCsr;
    private byte[]? _acmeRemoteCert;
    private AcmeError? _acmeRemoteError;
    private IConfiguration? _acmeRemoteConfig;
    private Exception? _acmeRemoteStartupError;
    private bool _acmeRemoteRevoked;

    private void BuildAcmeRemoteIssuer(bool withClientCertificate)
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
            revokeIdentity = Assert.IsType<SignCertificateResponse.Success>(response).Certificate
                .CopyWithPrivateKey(key);
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

        _acmeRemoteRevokeIdentity = revokeIdentity;
        _acmeRemoteCaClient = new CaClient(client, options, NullLogger<CaClient>.Instance);
        _acmeRemoteCertificateStore = new InMemoryCertificateStore();
        _acmeRemoteIssuer = new RemoteIssuer(_acmeRemoteCaClient, _acmeRemoteCertificateStore);
        _acmeRemoteCsr = BuildCsr("host.tenant-a.example.com");
    }

    private static string BuildCsr(string dnsName)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={dnsName}",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        var subjectAlternativeName = new SubjectAlternativeNameBuilder();
        subjectAlternativeName.AddDnsName(dnsName);
        request.CertificateExtensions.Add(subjectAlternativeName.Build());
        return PemEncoding.WriteString("CERTIFICATE REQUEST", request.CreateSigningRequest());
    }

    [Given(@"a remote ACME issuer pointed at the backing CA")]
    public void GivenARemoteAcmeIssuerPointedAtTheBackingCa()
    {
        BuildAcmeRemoteIssuer(withClientCertificate: false);
    }

    [Given(@"a remote ACME issuer pointed at the backing CA using its client certificate")]
    public void GivenARemoteAcmeIssuerPointedAtTheBackingCaUsingClientCertificate()
    {
        BuildAcmeRemoteIssuer(withClientCertificate: true);
    }

    [When(@"an ACME order finalizes for ""(.*)""")]
    public async Task WhenAnAcmeOrderFinalizesFor(string dnsName)
    {
        Assert.NotNull(_acmeRemoteIssuer);
        var csr = dnsName == "host.tenant-a.example.com" ? _acmeRemoteCsr : BuildCsr(dnsName);
        var (certificate, error) = await _acmeRemoteIssuer!.IssueCertificate(
            "default",
            csr!,
            [],
            null,
            null,
            CancellationToken.None).ConfigureAwait(false);
        _acmeRemoteCert = certificate;
        _acmeRemoteError = error;
    }

    [When(@"an ACME order finalizes for the out-of-scope identifier ""(.*)""")]
    public async Task WhenAnAcmeOrderFinalizesForOutOfScopeIdentifier(string dnsName)
    {
        Assert.NotNull(_acmeRemoteIssuer);
        var csr = BuildCsr(dnsName);
        var (certificate, error) = await _acmeRemoteIssuer!.IssueCertificate(
            "default",
            csr,
            [],
            null,
            null,
            CancellationToken.None).ConfigureAwait(false);
        _acmeRemoteCert = certificate;
        _acmeRemoteError = error;
    }

    [Then(@"the backing CA returns a signed certificate chain")]
    public async Task ThenTheBackingCaReturnsASignedCertificateChain()
    {
        Assert.Null(_acmeRemoteError);
        Assert.NotNull(_acmeRemoteCert);
        var chainPem = System.Text.Encoding.UTF8.GetString(_acmeRemoteCert!);
        var certificates = new X509Certificate2Collection();
        certificates.ImportFromPem(chainPem);
        Assert.NotEmpty(certificates);
        using var leaf = certificates[0];
        Assert.Equal("CN=host.tenant-a.example.com", leaf.Subject);
        Assert.Equal("default", await _acmeRemoteCertificateStore!.GetIssuingProfile(
            leaf.Thumbprint, CancellationToken.None));
    }

    [Then(@"the order fails with a rejected identifier")]
    public void ThenTheOrderFailsWithARejectedIdentifier()
    {
        Assert.Null(_acmeRemoteCert);
        Assert.NotNull(_acmeRemoteError);
    }

    [When(@"the certificate is revoked over the wire")]
    public async Task WhenTheCertificateIsRevokedOverTheWire()
    {
        Assert.NotNull(_acmeRemoteCaClient);
        Assert.NotNull(_acmeRemoteRevokeIdentity);
        Assert.NotNull(_acmeRemoteCert);
        var certificates = new X509Certificate2Collection();
        certificates.ImportFromPem(System.Text.Encoding.UTF8.GetString(_acmeRemoteCert!));
        Assert.NotEmpty(certificates);
        using var issued = certificates[0];
        _acmeRemoteRevoked = await _acmeRemoteCaClient!.Revoke(
            _acmeRemoteRevokeIdentity!,
            issued.GetSerialNumberString(),
            "default",
            X509RevocationReason.CessationOfOperation).ConfigureAwait(false);
    }

    [Then(@"the revocation succeeds")]
    public void ThenTheRevocationSucceeds()
    {
        Assert.True(_acmeRemoteRevoked);
    }

    [Given(@"a non-HTTPS remote ACME configuration")]
    public void GivenANonHttpsRemoteAcmeConfiguration()
    {
        _acmeRemoteConfig = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Ca:RemoteUrl"] = "http://localhost:5001/"
            })
            .Build();
    }

    [When(@"the remote ACME host is configured")]
    public void WhenTheRemoteAcmeHostIsConfigured()
    {
        Assert.NotNull(_acmeRemoteConfig);
        try
        {
            var options = CaClientOptions.FromConfiguration(_acmeRemoteConfig!);
            _ = new CaClient(_server.CreateClient(), options, NullLogger<CaClient>.Instance);
        }
        catch (Exception exception)
        {
            _acmeRemoteStartupError = exception;
        }
    }

    [Then(@"startup is rejected")]
    public void ThenStartupIsRejected()
    {
        Assert.NotNull(_acmeRemoteStartupError);
    }

    [AfterScenario]
    public void DisposeAcmeRemote()
    {
        _acmeRemoteRevokeIdentity?.Dispose();
    }
}
