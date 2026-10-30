namespace OpenCertServer.Est.Tests.Steps;

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Hosting;
using OpenCertServer.Ca;
using OpenCertServer.Ca.Server;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Ca.Utils.Ocsp;
using OpenCertServer.Est.Server;
using Reqnroll;
using Xunit;

[Binding]
public sealed class ReEnrollmentProfileSteps
{
    private TestServer _server = null!;
    private IHost _host = null!;
    private CaProfileSet _profiles = null!;
    private IStoreCertificates _store = null!;
    private X509Certificate2 _original = null!;
    private HttpStatusCode _status;
    private string _body = "";
    private int _inventoryCount;
    private string _targetProfile = "";
    private CertificateStatus _originalStatus;

    [Given("EST profiles sharing one issuer with {string} permissions")]
    public async Task GivenProfilesSharingOneIssuer(string permissions)
    {
        var samePermissions = permissions == "identical";
        var issuer = CertificateAuthority.CreateSelfSignedRsa(
            "issuer", new X500DistinguishedName("CN=Shared issuer"), TimeSpan.FromDays(365));
        CaProfile Profile(string name, bool server) => new()
        {
            Name = name,
            PrivateKey = issuer.PrivateKey,
            CertificateChain = issuer.CertificateChain,
            CertificateValidity = TimeSpan.FromDays(server ? 90 : 30),
            KeyUsage = X509KeyUsageFlags.DigitalSignature,
            ExtendedKeyUsages = server ? ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"] : ["1.3.6.1.5.5.7.3.2"],
            CertificatePolicies = server ? [] : ["1.3.6.1.4.1.67091.10.1"]
        };
        _profiles = new CaProfileSet("vpn-server",
            Profile("vpn-user", samePermissions), Profile("vpn-server", true));
        _store = permissions == "legacy store" ? new LegacyStore() : new InMemoryCertificateStore();
        _host = await new HostBuilder().ConfigureWebHost(builder => builder.UseTestServer()
            .ConfigureServices(services =>
            {
                services.AddRouting();
                services.AddAuthorization();
                services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
                    .AddCertificate(options =>
                    {
                        options.ChainTrustValidationMode = X509ChainTrustMode.CustomRootTrust;
                        options.CustomTrustStore.AddRange(issuer.CertificateChain);
                        options.RevocationMode = X509RevocationMode.NoCheck;
                    });
                services.AddSingleton(_store);
                services.AddCertificateAuthority(new CaConfiguration(_profiles, [], [], []));
                services.AddEstServer<TestCsrAttributesLoader>();
            })
            .Configure(app => app.UseEstServer(reEnrollPolicy:
                new AuthorizationPolicyBuilder(CertificateAuthenticationDefaults.AuthenticationScheme)
                    .RequireAuthenticatedUser().Build()))).StartAsync();
        _server = _host.GetTestServer();
    }

    [When("a certificate from {string} with {string} issuance records is renewed through {string} using {string}")]
    public async Task WhenRenewed(string source, string records, string target, string transport)
    {
        var authority = _server.Services.GetRequiredService<ICertificateAuthority>();
        ICertificateAuthority issuingAuthority = records is "present" or "revoked" or "collision"
            ? authority : new CertificateAuthority(
            new CaConfiguration(_profiles, [], [], []), new InMemoryCertificateStore(),
            new AcceptTestChain(), new RandomNumberCertificateIdGenerator(), NullLogger<CertificateAuthority>.Instance);
        using var key = RSA.Create(2048);
        CertificateRequest Request() => new("CN=test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        var issued = Assert.IsType<SignCertificateResponse.Success>(
            await issuingAuthority.SignCertificateRequest(Request(), source == "default" ? null : source));
        _original = issued.Certificate;
        if (records == "imported")
        {
            await _store.AddCertificate(_original);
        }

        if (records == "collision")
        {
            using var recorded = _original;
            var profile = await _profiles.GetProfile(source);
            _original = Request().Create(profile.CertificateChain[0].SubjectName,
                X509SignatureGenerator.CreateForRSA((RSA)profile.PrivateKey, RSASignaturePadding.Pkcs1),
                recorded.NotBefore, recorded.NotAfter, recorded.GetSerialNumber().Reverse().ToArray());
            Assert.NotEqual(recorded.Thumbprint, _original.Thumbprint);
        }

        if (records == "revoked")
        {
            Assert.True(await authority.RevokeCertificate(_original.SerialNumber, X509RevocationReason.KeyCompromise));
        }

        _inventoryCount = await _store.GetInventory().CountAsync();
        _targetProfile = target == "default" ? "vpn-server" : target;
        (_, _originalStatus, _) = await _store.GetCertificateStatus(
            CertId.Create(_original, HashAlgorithmName.SHA256));
        if (transport == "EST")
        {
            using var client = new HttpClient(new TestMessageHandler(_server, _original));
            var route = target == "default" ? "" : $"{target}/";
            using var response = await client.PostAsync(
                $"https://localhost/.well-known/est/{route}simplereenroll",
                new StringContent(Request().ToPkcs10Base64(), System.Text.Encoding.UTF8, "application/pkcs10"));
            _status = response.StatusCode;
            _body = await response.Content.ReadAsStringAsync();
        }
        else
        {
            var result = await authority.SignCertificateRequest(
                Request(), target == "default" ? null : target, reenrollingFrom: _original);
            _status = result is SignCertificateResponse.Success ? HttpStatusCode.OK : HttpStatusCode.BadRequest;
            _body = result is SignCertificateResponse.Error error ? string.Join("\n", error.Errors) : "";
        }
    }

    [Then("profile-bound renewal is {string}")]
    public async Task ThenRenewalIs(string outcome)
    {
        Assert.Equal(outcome == "accepted" ? HttpStatusCode.OK : HttpStatusCode.BadRequest, _status);
        if (outcome != "accepted")
        {
            Assert.Contains(outcome == "revoked" ? "revoked" : "issuing profile", _body);
            Assert.Equal(_inventoryCount, await _store.GetInventory().CountAsync());
            var (_, status, _) = await _store.GetCertificateStatus(
                CertId.Create(_original, HashAlgorithmName.SHA256));
            Assert.NotEqual(X509RevocationReason.Superseded,
                (await _store.GetInventory().ToArrayAsync()).SingleOrDefault()?.RevocationReason);
            Assert.Equal(_originalStatus, status);
        }
        else
        {
            var inventory = await _store.GetInventory().ToArrayAsync();
            Assert.Equal(_inventoryCount + 1, inventory.Length);
            Assert.Equal(X509RevocationReason.Superseded,
                inventory.Single(item => item.SerialNumber == _original.SerialNumber).RevocationReason);
            var renewed = inventory.Single(item => item.SerialNumber != _original.SerialNumber);
            Assert.Equal(_targetProfile, await _store.GetIssuingProfile(renewed.Thumbprint));
        }
    }

    [AfterScenario("profile-bound-renewal")]
    public void Cleanup()
    {
        _original?.Dispose();
        _host?.Dispose();
        _profiles?.Dispose();
    }

    private sealed class AcceptTestChain : IValidateX509Chains
    {
        public Task<bool> Validate(X509Chain chain, CancellationToken cancellationToken = default) =>
            Task.FromResult(true);
    }

    // Models an existing custom store that implements only the original persistence contract.
    private sealed class LegacyStore : IStoreCertificates
    {
        private readonly InMemoryCertificateStore _inner = new();

        public Task AddCertificate(X509Certificate2 certificate, CancellationToken cancellationToken = default) =>
            _inner.AddCertificate(certificate, cancellationToken);

        public Task<bool> RemoveCertificate(
            string serialNumber, X509RevocationReason reason, CancellationToken cancellationToken = default) =>
            _inner.RemoveCertificate(serialNumber, reason, cancellationToken);

        public IAsyncEnumerable<CertificateItemInfo> GetRevocationList(
            int page = 0, int pageSize = 100, CancellationToken cancellationToken = default) =>
            _inner.GetRevocationList(page, pageSize, cancellationToken);

        public Task<(CertId, CertificateStatus, RevokedInfo?)> GetCertificateStatus(
            CertId certId, CancellationToken cancellationToken = default) =>
            _inner.GetCertificateStatus(certId, cancellationToken);

        public IAsyncEnumerable<CertificateItemInfo> GetInventory(
            int page = 0, int pageSize = 100, CancellationToken cancellationToken = default) =>
            _inner.GetInventory(page, pageSize, cancellationToken);

        public IAsyncEnumerable<X509Certificate2> GetCertificatesById(
            CancellationToken cancellationToken, params IEnumerable<ReadOnlyMemory<byte>> ids) =>
            _inner.GetCertificatesById(cancellationToken, ids);

        public IAsyncEnumerable<X509Certificate2> GetCertificatesByThumbprint(
            IEnumerable<ReadOnlyMemory<char>> thumbprint, CancellationToken cancellationToken = default) =>
            _inner.GetCertificatesByThumbprint(thumbprint, cancellationToken);
    }
}
