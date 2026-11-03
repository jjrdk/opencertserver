namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertesSlim.Extensions;
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
            Array.Empty<CertesSlim.Acme.Resource.Identifier>(),
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

    private IConfiguration? _caClientConfig;

    [AfterScenario]
    public void DisposeCaClient()
    {
        _caClientIdentity?.Dispose();
    }
}
