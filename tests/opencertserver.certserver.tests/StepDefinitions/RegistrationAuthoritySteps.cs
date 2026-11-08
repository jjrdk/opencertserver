using OpenCertServer.Ra;

namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CertesSlim;
using CertesSlim.Extensions;
using Acme.AspNetClient.Certes;
using Acme.AspNetClient.Persistence;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.CertServer.Tests;
using Reqnroll;
using Xunit;

public partial class CertificateServerFeatures
{
    private HttpClient? _raHttpClient;
    private RaPeerClient? _raPeerClient;
    private X509Certificate2? _raIdentityCertificate;
    private string? _raCsr;
    private string? _raCertificatePem;
    private HttpStatusCode? _raResponseStatus;
    private bool _raRevocationSucceeded;
    private Exception? _accountCreationError;
    private HttpStatusCode? _firstDirectoryStatus;
    private HttpStatusCode? _secondDirectoryStatus;
    private IReadOnlyList<string>? _supportedProfiles;

    [Given(@"an outbound RA peer for ""(.*)""")]
    public void GivenAnOutboundRaPeerFor(string dnsName)
    {
        CreateRaPeer(dnsName, bearerToken: "ra-token");
    }

    [Given(@"an outbound RA peer for ""(.*)"" using its client certificate")]
    public async Task GivenAnOutboundRaPeerUsingClientCertificateFor(string dnsName)
    {
        CreateRaPeer(dnsName, bearerToken: null);
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=ra-tenant-a",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        var extendedKeyUsage = new OidCollection { new("1.3.6.1.5.5.7.3.2") };
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(extendedKeyUsage, critical: false));
        var ca = _server.Services.GetRequiredService<ICertificateAuthority>();
        var response = await ca.SignCertificateRequest(request, "default").ConfigureAwait(false);
        var issuedCertificate = Assert.IsType<SignCertificateResponse.Success>(response).Certificate;
        _raIdentityCertificate = issuedCertificate.CopyWithPrivateKey(key);
        _raHttpClient!.DefaultRequestHeaders.Add(
            "X-Client-Cert",
            Convert.ToBase64String(_raIdentityCertificate.RawData));
    }

    private void CreateRaPeer(string dnsName, string? bearerToken)
    {
        _raHttpClient = _server.CreateClient();
        _raPeerClient = new RaPeerClient(
            _raHttpClient,
            new RaPeerOptions
            {
                PeerUrl = new Uri("https://localhost/"),
                Scope = "tenant-a.example.com",
                Profile = "default",
                BearerToken = bearerToken
            });

        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={dnsName}",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        var subjectAlternativeName = new SubjectAlternativeNameBuilder();
        subjectAlternativeName.AddDnsName(dnsName);
        request.CertificateExtensions.Add(subjectAlternativeName.Build());
        _raCsr = PemEncoding.WriteString("CERTIFICATE REQUEST", request.CreateSigningRequest());
    }

    [When("the RA enrolls a certificate")]
    public async Task WhenTheRaEnrollsACertificate()
    {
        Assert.NotNull(_raPeerClient);
        Assert.NotNull(_raCsr);
        try
        {
            _raCertificatePem = await _raPeerClient.EnrollAsync(_raCsr).ConfigureAwait(false);
            _raResponseStatus = HttpStatusCode.OK;
        }
        catch (HttpRequestException exception)
        {
            _raResponseStatus = exception.StatusCode;
        }
    }

    [When("the RA renews the certificate")]
    public async Task WhenTheRaRenewsTheCertificate()
    {
        Assert.NotNull(_raPeerClient);
        Assert.NotNull(_raCsr);
        _raCertificatePem = await _raPeerClient.RenewAsync(_raCsr).ConfigureAwait(false);
        _raResponseStatus = HttpStatusCode.OK;
    }

    [When("the RA revokes the certificate")]
    public async Task WhenTheRaRevokesTheCertificate()
    {
        Assert.NotNull(_raPeerClient);
        Assert.NotNull(_raIdentityCertificate);
        Assert.Equal(HttpStatusCode.OK, _raResponseStatus);
        Assert.NotNull(_raCertificatePem);
        var issuedCertificates = new X509Certificate2Collection();
        issuedCertificates.ImportFromPem(_raCertificatePem);
        Assert.NotEmpty(issuedCertificates);
        using var issuedCertificate = issuedCertificates[0];
        _raRevocationSucceeded = await _raPeerClient.RevokeAsync(
            _raIdentityCertificate,
            issuedCertificate.GetSerialNumberString(),
            X509RevocationReason.CessationOfOperation).ConfigureAwait(false);
    }

    [Then("the RA revocation succeeds")]
    public void ThenTheRaRevocationSucceeds()
    {
        Assert.True(_raRevocationSucceeded);
    }

    [Then("the RA receives a CA-issued certificate")]
    public void ThenTheRaReceivesACaIssuedCertificate()
    {
        Assert.Equal(HttpStatusCode.OK, _raResponseStatus);
        Assert.False(string.IsNullOrWhiteSpace(_raCertificatePem));

        var certificates = new X509Certificate2Collection();
        certificates.ImportFromPem(_raCertificatePem);
        Assert.NotEmpty(certificates);
        Assert.Equal("CN=host.tenant-a.example.com", certificates[0].Subject);
    }

    [Then("the central CA rejects the RA request")]
    public void ThenTheCentralCaRejectsTheRaRequest()
    {
        Assert.Equal(HttpStatusCode.BadRequest, _raResponseStatus);
        Assert.Null(_raCertificatePem);
    }

    [When("the RA requests the supported profiles")]
    public async Task WhenTheRaRequestsTheSupportedProfiles()
    {
        Assert.NotNull(_raPeerClient);
        _supportedProfiles = await _raPeerClient.GetSupportedProfiles().ConfigureAwait(false);
    }

    [Then(@"the supported profiles include ""(.+)"" and ""(.+)""")]
    public void ThenTheSupportedProfilesInclude(string first, string second)
    {
        Assert.NotNull(_supportedProfiles);
        Assert.Contains(first, _supportedProfiles);
        Assert.Contains(second, _supportedProfiles);
    }

    [When(@"the RA enrolls a certificate against the ""(.+)"" profile")]
    public async Task WhenTheRaEnrollsACertificateAgainstTheNamedProfile(string profile)
    {
        Assert.NotNull(_raPeerClient);
        Assert.NotNull(_raCsr);
        try
        {
            _raCertificatePem = await _raPeerClient.EnrollAsync(_raCsr, profile).ConfigureAwait(false);
            _raResponseStatus = HttpStatusCode.OK;
        }
        catch (HttpRequestException exception)
        {
            _raResponseStatus = exception.StatusCode;
        }
    }

    [Then("the peer request uses HTTPS")]
    public void ThenThePeerRequestUsesHttps()
    {
        Assert.NotNull(_raPeerClient);
        Assert.Equal(Uri.UriSchemeHttps, _raPeerClient.PeerUrl.Scheme);
    }

    [When("an anonymous client submits a certificate request to the CA")]
    public async Task WhenAnAnonymousClientSubmitsACertificateRequestToTheCa()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=host.tenant-a.example.com",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        var pem = PemEncoding.WriteString("CERTIFICATE REQUEST", request.CreateSigningRequest());
        using var client = _server.CreateClient();
        using var response = await client.PostAsync(
            "ca/csr",
            new StringContent(pem, Encoding.UTF8, "application/pkcs10")).ConfigureAwait(false);
        _scenarioContext["anonymousCaStatus"] = response.StatusCode;
    }

    [Then("the CA rejects the anonymous request")]
    public void ThenTheCaRejectsTheAnonymousRequest()
    {
        Assert.Equal(HttpStatusCode.Unauthorized, _scenarioContext["anonymousCaStatus"]);
    }

    [When("an ACME client creates an account without EAB")]
    public async Task WhenAnAcmeClientCreatesAnAccountWithoutEab()
    {
        var factory = new AcmeClientFactory(
            new PersistenceService(
                [new InMemoryCertificatePersistenceStrategy()],
                [new InMemoryChallengePersistenceStrategy()],
                NullLogger<PersistenceService>.Instance),
            new TestAcmeOptions
            {
                Profile = "rsa",
                Email = "test@test.com",
                Domains = ["localhost"],
                KeyAlgorithm = "RS256",
                CertificateSigningRequest = new CsrInfo { CommonName = "test", CountryName = "DK" },
                AccountPassword = "test"
            },
            _server.CreateClient(),
            NullLoggerFactory.Instance);

        try
        {
            _ = await factory.GetClient().ConfigureAwait(false);
        }
        catch (AcmeException exception)
        {
            _accountCreationError = exception;
        }
    }

    [Then("ACME account creation is rejected")]
    public void ThenAcmeAccountCreationIsRejected()
    {
        Assert.NotNull(_accountCreationError);
    }

    [When("the client requests the ACME directory twice")]
    public async Task WhenTheClientRequestsTheAcmeDirectoryTwice()
    {
        using var client = _server.CreateClient();
        using var first = await client.GetAsync("directory").ConfigureAwait(false);
        using var second = await client.GetAsync("directory").ConfigureAwait(false);
        _firstDirectoryStatus = first.StatusCode;
        _secondDirectoryStatus = second.StatusCode;
    }

    [Then("the first directory response is successful and the second is rate limited")]
    public void ThenTheFirstDirectoryResponseIsSuccessfulAndTheSecondIsRateLimited()
    {
        Assert.Equal(HttpStatusCode.OK, _firstDirectoryStatus);
        Assert.Equal(HttpStatusCode.TooManyRequests, _secondDirectoryStatus);
    }

    [AfterScenario]
    public void DisposeRaPeerHttpClient()
    {
        _raHttpClient?.Dispose();
        _raIdentityCertificate?.Dispose();
    }
}
