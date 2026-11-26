namespace OpenCertServer.Contrib.Intune.Tests.Steps;

using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Ca.Utils.Ocsp;
using Reqnroll;
using Xunit;

[Binding]
public sealed class IntuneDeviceReportBatch : IDisposable
{
    private readonly FakeIntune _fake = new();
    private readonly CountingStore _store = new();
    private Microsoft.Extensions.Hosting.IHost? _host;
    private X509Certificate2? _ca;
    private X509Certificate2? _ra;
    private IntuneDeviceReport? _report;

    [Given("an Intune report inventory with multiple trusted and untrusted profiles")]
    public async Task GivenInventory()
    {
        (_host, _ca, _ra) = TestHostBuilder.Build(_fake, configureServices: services =>
        {
            services.RemoveAll<IStoreCertificates>();
            services.AddSingleton<IStoreCertificates>(_store);
        });
        using var key = ECDsa.Create();
        var issuerRequest = new CertificateRequest("CN=report issuer", key, HashAlgorithmName.SHA256);
        using var issuer = issuerRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(2));
        for (var i = 0; i < 101; i++)
        {
            var request = new CertificateRequest($"CN={Guid.NewGuid()}", key, HashAlgorithmName.SHA256);
            using var certificate = request.Create(issuer.SubjectName, X509SignatureGenerator.CreateForECDsa(key),
                DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1), [(byte)(i + 1)]);
            if (i == 4 || i == 100)
            {
                await _store.AddCertificate(certificate);
            }
            else
            {
                await _store.AddCertificate(certificate, i == 3 ? "ecdsa" : "rsa");
            }
        }
    }

    [When("the Intune inventory report is requested")]
    public async Task WhenReportIsRequested()
    {
        var client = _host!.GetTestClient();
        client.DefaultRequestHeaders.Add("X-Test-Role", TestHostBuilder.SyncRole);
        _report = await client.GetFromJsonAsync<IntuneDeviceReport>("/scep/intune/devices");
    }

    [Then("the report includes only trusted devices with bounded store reads")]
    public async Task ThenReportIsBatched()
    {
        Assert.NotNull(_report);
        Assert.Equal(98, _report.Certificates.Count);
        Assert.All(_report.Certificates, c => Assert.Equal("rsa", c.Profile));
        Assert.True(_report.HasMore);
        Assert.Equal(0, _store.SingleProfileReads);
        Assert.Equal(1, _store.BatchProfileReads);
        Assert.Equal(0, _store.SerialReads);
        Assert.Equal(1, _store.CertificateReads);
        var client = _host!.GetTestClient();
        client.DefaultRequestHeaders.Add("X-Test-Role", TestHostBuilder.SyncRole);
        var lastPage = await client.GetFromJsonAsync<IntuneDeviceReport>("/scep/intune/devices?page=1");
        Assert.NotNull(lastPage);
        Assert.Empty(lastPage.Certificates);
        Assert.False(lastPage.HasMore);
        Assert.Equal(2, _store.BatchProfileReads);
        Assert.Equal(1, _store.CertificateReads);
    }

    public void Dispose()
    {
        _host?.Dispose();
        _ca?.Dispose();
        _ra?.Dispose();
        _fake.Dispose();
    }

    private sealed class CountingStore : IStoreCertificates
    {
        private readonly InMemoryCertificateStore _inner = new();
        public int SingleProfileReads { get; private set; }
        public int BatchProfileReads { get; private set; }
        public int SerialReads { get; private set; }
        public int CertificateReads { get; private set; }
        public Task AddCertificate(X509Certificate2 certificate, CancellationToken cancellationToken = default) =>
            _inner.AddCertificate(certificate, cancellationToken);
        public Task AddCertificate(X509Certificate2 certificate, string issuingProfile, CancellationToken cancellationToken = default) =>
            _inner.AddCertificate(certificate, issuingProfile, cancellationToken);
        public Task<string?> GetIssuingProfile(string thumbprint, CancellationToken cancellationToken = default)
        {
            SingleProfileReads++;
            return _inner.GetIssuingProfile(thumbprint, cancellationToken);
        }
        public Task<IReadOnlyDictionary<string, string?>> GetIssuingProfiles(
            IEnumerable<string> thumbprints, CancellationToken cancellationToken = default)
        {
            BatchProfileReads++;
            return _inner.GetIssuingProfiles(thumbprints, cancellationToken);
        }
        public Task<bool> RemoveCertificate(string serialNumber, X509RevocationReason reason, CancellationToken cancellationToken = default) =>
            _inner.RemoveCertificate(serialNumber, reason, cancellationToken);
        public IAsyncEnumerable<CertificateItemInfo> GetRevocationList(string? issuingProfile, int page = 0, int pageSize = 100, CancellationToken cancellationToken = default) =>
            _inner.GetRevocationList(issuingProfile, page, pageSize, cancellationToken);
        public Task<(CertId, CertificateStatus, RevokedInfo?)> GetCertificateStatus(CertId certId, CancellationToken cancellationToken = default) =>
            _inner.GetCertificateStatus(certId, cancellationToken);
        public IAsyncEnumerable<CertificateItemInfo> GetInventory(int page = 0, int pageSize = 100, CancellationToken cancellationToken = default) =>
            _inner.GetInventory(page, pageSize, cancellationToken);
        public IAsyncEnumerable<X509Certificate2> GetCertificatesById(CancellationToken cancellationToken, params IEnumerable<ReadOnlyMemory<byte>> ids)
        {
            SerialReads++;
            return _inner.GetCertificatesById(cancellationToken, ids);
        }
        public IAsyncEnumerable<X509Certificate2> GetCertificatesByThumbprint(IEnumerable<ReadOnlyMemory<char>> thumbprint, CancellationToken cancellationToken = default)
        {
            CertificateReads++;
            return _inner.GetCertificatesByThumbprint(thumbprint, cancellationToken);
        }
    }
}
