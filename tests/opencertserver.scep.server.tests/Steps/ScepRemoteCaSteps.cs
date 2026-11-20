namespace OpenCertServer.Scep.Tests.Steps;

using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using OpenCertServer.Ca;
using OpenCertServer.Ca.Client;
using OpenCertServer.Ca.Server;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Scep.Server;
using Reqnroll;
using Xunit;

/// <summary>
/// The SCEP-over-a-backing-CA scenarios: a SCEP server that holds no CA key and issues through a
/// backing certificate authority over a trusted HTTPS connection, the way opencertserver.scep does.
/// The SCEP process keeps only its RA certificate and the replay store; the CA stays authoritative
/// for scope and identity.
/// </summary>
[Binding]
public sealed class ScepRemoteCaSteps : IDisposable
{
    private const string Challenge = "geheim";
    private const string Subject = "CN=device.tenant-a.example.com, O=entra-vpn";

    private IHost? _caHost;
    private TestServer? _caServer;
    private IHost? _scepHost;
    private ScepTestClient? _scepClient;
    private X509Certificate2? _ca;
    private X509Certificate2? _ra;
    private X509Certificate2? _held;
    private X509Certificate2? _renewed;
    private X509Certificate2Collection _caCerts = [];
    private ScepTestResponse? _certRep;
    private Exception? _startupError;
    private readonly string _transactionId = Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
    private readonly byte[] _senderNonce = RandomNumberGenerator.GetBytes(16);

    // --- Backing CA over a trusted HTTPS connection ------------------------------------------

    [Given("a SCEP server backed by a separate certificate authority")]
    public Task GivenAScepServerBackedByASeparateCa() => StartScepOverCa();

    [Given("a client holding a certificate renewed through a backing CA")]
    public async Task GivenAClientHoldingACertificateRenewedThroughABackingCa()
    {
        await StartScepOverCa().ConfigureAwait(false);
        var key = RSA.Create(2048);
        var signer = ScepTestClient.CreateTransientSigner(key);
        var response = await _scepClient!.Enroll(
            ScepTestClient.CreateCsr(key, Subject, Challenge),
            signer, _ra!, _transactionId, _senderNonce).ConfigureAwait(false);
        _certRep = ScepTestResponse.Read(
            await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false), signer);
        Assert.Equal("0", _certRep!.PkiStatus);
        _held = _certRep!.Issued!.CopyWithPrivateKey(key);
    }

    private async Task StartScepOverCa()
    {
        // 1. A backing CA, hosted in its own process, over HTTPS.
        var rsaKey = RSA.Create(2048);
        var rsaReq = new CertificateRequest("CN=tenant-a CA", rsaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rsaReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rsaReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rsaReq.PublicKey, false));
        rsaReq.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        _ca = rsaReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var profile = new CaProfile
        {
            CertificateChain = [X509Certificate2.CreateFromPem(_ca.ExportCertificatePem())],
            Name = "rsa",
            CertificateValidity = TimeSpan.FromDays(90),
            CrlNumber = new System.Numerics.BigInteger(0),
            PrivateKey = _ca.GetRSAPrivateKey()!
        };
        _caHost = new HostBuilder().ConfigureWebHost(web =>
        {
            web.UseTestServer().UseUrls("http://localhost")
                .ConfigureServices(services =>
                {
                    services
                        .AddInMemoryCertificateStore()
                        .AddCertificateAuthority(new CaConfiguration(
                            new CaProfileSet("rsa", profile),
                            ["http://localhost/crl"], [], []))
                        .AddRouting()
                        .AddAuthorization()
                        .AddCertificateAuthorityAuthorization()
                        .AddAuthentication(options =>
                        {
                            options.DefaultScheme = "CaAuthentication";
                            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                        })
                        .AddPolicyScheme("CaAuthentication", null, options =>
                        {
                            options.ForwardDefaultSelector = context =>
                                context.Request.Headers.Authorization.ToString()
                                    .StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
                                    ? JwtBearerDefaults.AuthenticationScheme
                                    : CertificateAuthenticationDefaults.AuthenticationScheme;
                        })
                        .AddJwtBearer(o =>
                        {
                            o.Events = new JwtBearerEvents
                            {
                                OnAuthenticationFailed = c =>
                                {
                                    c.NoResult();
                                    c.Principal = new ClaimsPrincipal(new ClaimsIdentity(
                                        [new Claim("ra", "ra-tenant-a"), new Claim("role", "user")],
                                        JwtBearerDefaults.AuthenticationScheme));
                                    c.Success();
                                    return Task.CompletedTask;
                                }
                            };
                        })
                        .AddCertificate();
                })
                .Configure(app =>
                    app.UseRouting().UseAuthentication().UseAuthorization()
                        .UseEndpoints(e => e.MapCertificateAuthorityServer()));
        }).Build();
        await _caHost.StartAsync(CancellationToken.None).ConfigureAwait(false);
        _caServer = _caHost.GetTestServer();

        // 2. A SCEP host whose ICertificateAuthority is a remote CA client over that CA, and whose
        // RA certificate is its own local identity. The SCEP process holds no CA key.
        var caClient = new CaClient(_caServer.CreateClient(), new CaClientOptions
        {
            BaseUrl = new Uri("https://localhost/"),
            Profile = "rsa",
            DelegatedScope = "tenant-a.example.com",
            BearerToken = "ra-token",
        }, NullLogger<CaClient>.Instance);
        var remoteCa = new RemoteCertificateAuthority(caClient);

        var raKey = RSA.Create(2048);
        var raReq = new CertificateRequest("CN=SCEP RA", raKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        raReq.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        _ra = raReq.Create(_ca, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddMonths(6),
                RandomNumberGenerator.GetBytes(16))
            .CopyWithPrivateKey(raKey);

        _scepHost = new HostBuilder().ConfigureWebHost(web =>
        {
            web.UseTestServer().UseUrls("http://localhost")
                .ConfigureServices(services =>
                {
                    services
                        .AddRouting()
                        .AddAuthorization()
                        .AddSingleton<ICertificateAuthority>(remoteCa)
                        .AddSingleton(_ra)
                        .AddScepServer(new ScepServerOptions
                        {
                            RaCertificate = _ra,
                            DefaultProfile = "rsa"
                        }, new SharedSecretChallengeValidator(Challenge));
                })
                .Configure(app =>
                    app.UseRouting().UseAuthorization().UseEndpoints(e => e.MapScepServer()));
        }).Build();
        await _scepHost.StartAsync(CancellationToken.None).ConfigureAwait(false);
        _scepClient = new ScepTestClient(_scepHost.GetTestClient());
    }

    // --- Enroll -----------------------------------------------------------------------------

    [When("a client enrolls with the challenge password {string}")]
    public async Task WhenAClientEnrolls(string password)
    {
        var key = RSA.Create(2048);
        var signer = ScepTestClient.CreateTransientSigner(key);
        var response = await _scepClient!.Enroll(
            ScepTestClient.CreateCsr(key, Subject, password),
            signer, _ra!, _transactionId, _senderNonce).ConfigureAwait(false);
        _certRep = ScepTestResponse.Read(
            await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false), signer);
    }

    [Then("the certificate is issued by the backing CA")]
    public void ThenTheCertificateIsIssuedByTheBackingCa()
    {
        Assert.Equal("0", _certRep!.PkiStatus);
        Assert.NotNull(_certRep!.Issued);
        // The leaf was signed by the backing CA, not by anything the SCEP host could have produced.
        Assert.Equal(_ca!.SubjectName.Name, _certRep!.Issued!.IssuerName.Name);
    }

    // --- GetCACert returns the published chain ------------------------------------------------

    [When("a client asks for the CA certificate")]
    public async Task WhenAClientAsksForTheCaCertificate()
    {
        var result = await _scepClient!.GetCaCert().ConfigureAwait(false);
        _caCerts = result.Certificates;
    }

    [Then("the CA certificate is the one the backing CA publishes")]
    public void ThenTheCaCertificateIsTheOneTheBackingCaPublishes()
    {
        Assert.Contains(_caCerts, c => c.SubjectName.Name == _ca!.SubjectName.Name);
    }

    // --- Renewal supersedes the previous certificate at the CA -------------------------------

    [When("the client renews it through the SCEP host with a new key")]
    public async Task WhenTheClientReneWsItWithANewKey()
    {
        var newKey = RSA.Create(2048);
        var csr = ScepTestClient.CreateCsr(newKey, Subject, challenge: null);
        var response = await _scepClient!.Enroll(
            csr, _held!, _ra!,
            Convert.ToHexString(RandomNumberGenerator.GetBytes(8)),
            RandomNumberGenerator.GetBytes(16),
            messageType: "17").ConfigureAwait(false);
        _certRep = ScepTestResponse.Read(
            await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false), _held!);
        Assert.Equal("0", _certRep!.PkiStatus);
        _renewed = _certRep!.Issued!;
    }

    [Then("the renewal keeps the subject and rotates the key")]
    public void ThenTheRenewedCertificateHasTheSameSubjectAndANewKey()
    {
        Assert.Equal(_held!.SubjectName.Name, _renewed!.SubjectName.Name);
        Assert.NotEqual(_held!.GetSerialNumberString(), _renewed!.GetSerialNumberString());
    }

    [Then("the superseded certificate is revoked at the backing CA")]
    public async Task ThenThePreviousCertificateIsRevoked()
    {
        var ca = _scepHost!.Services.GetRequiredService<ICertificateAuthority>();
        var crl = await ca.GetRevocationList("rsa", CancellationToken.None).ConfigureAwait(false);
        var list = CertificateRevocationListBuilder.Load(crl, out _);
        Assert.True(list.RemoveEntry(Convert.FromHexString(_held!.GetSerialNumberString())),
            "The renewed certificate is not on the revocation list the CA returned.");
    }

    // --- A non-HTTPS backing CA is rejected at startup ----------------------------------------

    [Given("a non-HTTPS SCEP backing CA configuration")]
    public void GivenANonHttpsScepBackingCaConfiguration()
    {
        try
        {
            var options = CaClientOptions
                .FromConfiguration(new ConfigurationBuilder()
                    .AddInMemoryCollection(new Dictionary<string, string?>
                    {
                        ["Ca:RemoteUrl"] = "http://localhost:5001/"
                    })
                    .Build());
            _ = new CaClient(new HttpClient(), options, NullLogger<CaClient>.Instance);
        }
        catch (Exception ex)
        {
            _startupError = ex;
        }
    }

    [When("the SCEP host is configured")]
    public void WhenTheScepHostIsConfigured()
    {
        // The non-HTTPS startup error, if any, was already captured when the client was built.
    }

    [Then("startup is rejected")]
    public void ThenStartupIsRejected()
    {
        Assert.NotNull(_startupError);
    }

    // --- Lifecycle ----------------------------------------------------------------------------

    public void Dispose()
    {
        _scepHost?.Dispose();
        _caHost?.Dispose();
    }
}
