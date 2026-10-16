namespace OpenCertServer.Contrib.Intune.Tests.Steps;

using System.Formats.Asn1;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.Ca;
using Reqnroll;
using Xunit;

[Binding]
public sealed class IntuneRevocationSync : IDisposable
{
    private readonly FakeIntune _fake = new();
    private IHost? _host;
    private int _maxRevocations = 25;
    private readonly Dictionary<string, X509Certificate2> _byLabel = new(StringComparer.Ordinal);
    private SyncReport? _report;
    private Task<SyncReport>? _running;
    private HttpResponseMessage? _http;

    // --- Given --------------------------------------------------------------

    [Given("a CA with a certificate for the user {string}")]
    [Given("a certificate for the user {string}")]
    public Task GivenUserCertificate(string upn) =>
        Issue(upn, $"CN={upn}", upn: upn, intuneDeviceId: null);

    [Given("a certificate for the user {string} on the Intune device {string}")]
    public Task GivenUserOnDevice(string upn, string deviceId) =>
        Issue(upn, $"CN={upn}", upn: upn, intuneDeviceId: deviceId);

    [Given("a device certificate for the Entra device {string}")]
    public Task GivenDeviceCertificate(string entraDeviceId) =>
        Issue("device", $"CN={entraDeviceId}", upn: null, intuneDeviceId: null);

    [Given("a server certificate for {string}")]
    public Task GivenServerCertificate(string host) =>
        Issue(host, $"CN={host}", upn: null, intuneDeviceId: null, dns: host);

    [Given("the directory knows all of them as enabled")]
    public void GivenDirectory()
    {
        _fake.Users["anna@contoso.test"] = true;
        _fake.Users["bert@contoso.test"] = true;
        _fake.ManagedDevices["11111111-1111-1111-1111-111111111111"] = 0;
        _fake.EntraDevices["22222222-2222-2222-2222-222222222222"] = true;
    }

    [Given("the user {string} is disabled")]
    public void GivenUserDisabled(string upn) => _fake.Users[upn] = false;

    [Given("the user {string} is deleted")]
    public void GivenUserDeleted(string upn) => _fake.Users.TryRemove(upn, out _);

    [Given("the Intune device {string} is retired")]
    public void GivenDeviceRetired(string id) => _fake.ManagedDevices.TryRemove(id, out _);

    [Given("the Entra device {string} is disabled")]
    public void GivenEntraDeviceDisabled(string id) => _fake.EntraDevices[id] = false;

    [Given("Graph answers with HTTP 429")]
    public void GivenGraphThrottled() => _fake.Graph = GraphBehaviour.Throttle;

    [Given("Graph is unreachable")]
    public void GivenGraphDown() => _fake.Graph = GraphBehaviour.Unreachable;

    [Given("the sync may revoke at most {int} certificate per run")]
    public void GivenLimit(int limit)
    {
        // The limit is read at construction; rebuild the host with it and re-issue nothing -
        // the store is per host, so the certificates must be issued again.
        _maxRevocations = limit;
        var issued = _byLabel.ToList();
        _byLabel.Clear();
        _host?.Dispose();
        _host = null;
        foreach (var (label, certificate) in issued)
        {
            var identity = CertificateIdentity.Read(certificate);
            var dns = label.Contains('.') && identity.UserPrincipalName is null ? label : null;
            GivenCertificateAgain(label, certificate.Subject, identity.UserPrincipalName, identity.IntuneDeviceId, dns).GetAwaiter().GetResult();
        }
    }

    [Given("Graph answers only when released")]
    public void GivenGraphGate() => _fake.GraphGate = new SemaphoreSlim(0, 1);

    // --- When ---------------------------------------------------------------

    [When("the sync runs")]
    public async Task WhenSyncRuns() => _report = await Sync().Run(dryRun: false, CancellationToken.None).ConfigureAwait(false);

    [When("the sync runs as a dry run")]
    public async Task WhenDryRun() => _report = await Sync().Run(dryRun: true, CancellationToken.None).ConfigureAwait(false);

    [When("the sync is started")]
    public async Task WhenSyncStarted()
    {
        _running = Sync().Run(dryRun: false, CancellationToken.None);
        // Give the first run time to reach the gate.
        var waited = 0;
        while (!Sync().IsRunning && waited++ < 100)
        {
            await Task.Delay(10).ConfigureAwait(false);
        }

        Assert.True(Sync().IsRunning);
    }

    [When("the sync endpoint is called without authentication")]
    public async Task WhenEndpointAnonymous()
    {
        _http = await Host.GetTestClient().PostAsync("/scep/intune/sync?dryRun=true", null).ConfigureAwait(false);
    }

    [When("the sync endpoint is called by the configured caller as a dry run")]
    public async Task WhenEndpointAuthorized()
    {
        var client = Host.GetTestClient();
        client.DefaultRequestHeaders.Add("X-Test-Role", TestHostBuilder.SyncRole);
        _http = await client.PostAsync("/scep/intune/sync?dryRun=true", null).ConfigureAwait(false);
    }

    // --- Then ---------------------------------------------------------------

    [Then("{int} certificates were checked")]
    public void ThenChecked(int count) => Assert.Equal(count, _report!.Checked);

    [Then("nothing was revoked")]
    public async Task ThenNothingRevoked()
    {
        Assert.Empty(_report!.Revoked);
        foreach (var certificate in _byLabel.Values)
        {
            Assert.False(await IsRevoked(certificate).ConfigureAwait(false), $"{certificate.Subject} was revoked");
        }
    }

    [Then("the certificate for {string} is revoked with {string}")]
    public async Task ThenRevoked(string label, string reason)
    {
        var certificate = _byLabel[label];
        var entry = Assert.Single(_report!.Revoked, r => r.SerialNumber == certificate.SerialNumber);
        Assert.Equal(reason, entry.Reason);
        Assert.True(await IsRevoked(certificate).ConfigureAwait(false), "the store still says valid");
    }

    [Then("the device certificate is revoked with {string}")]
    public Task ThenDeviceRevoked(string reason) => ThenRevoked("device", reason);

    [Then("the certificate for {string} is still valid")]
    public async Task ThenStillValid(string label) =>
        Assert.False(await IsRevoked(_byLabel[label]).ConfigureAwait(false));

    [Then("{int} certificates are reported as unknown")]
    public void ThenUnknown(int count) => Assert.Equal(count, _report!.Unknown.Count);

    [Then("the report lists {string} as to be revoked")]
    public void ThenListed(string label)
    {
        Assert.True(_report!.DryRun);
        Assert.Single(_report.Revoked, r => r.SerialNumber == _byLabel[label].SerialNumber);
    }

    [Then("the run was aborted")]
    public void ThenAborted()
    {
        Assert.NotNull(_report!.Aborted);
        Assert.False(_report.AlreadyRunning);
        Assert.Empty(_report.Revoked);
    }

    [Then("the second run was rejected as already running")]
    public void ThenRejected()
    {
        Assert.True(_report!.AlreadyRunning);
        Assert.Empty(_report.Revoked);
    }

    [Then("Graph is released")]
    public async Task ThenReleased()
    {
        _fake.GraphGate!.Release();
        var first = await _running!.ConfigureAwait(false);
        Assert.False(first.AlreadyRunning);
        Assert.Equal(3, first.Checked);
    }

    [Then("the endpoint answers HTTP {int}")]
    public void ThenHttp(int status) => Assert.Equal((HttpStatusCode)status, _http!.StatusCode);

    [Then("the endpoint answers HTTP 200 with a report")]
    public async Task ThenHttpReport()
    {
        Assert.Equal(HttpStatusCode.OK, _http!.StatusCode);
        var report = await _http.Content.ReadFromJsonAsync<SyncReport>().ConfigureAwait(false);
        Assert.NotNull(report);
        Assert.True(report.DryRun);
        Assert.Equal(3, report.Checked);
    }

    // --- Helpers ------------------------------------------------------------

    private IHost Host => _host ??= TestHostBuilder.Build(_fake, _maxRevocations).Host;

    private Intune.IntuneRevocationSync Sync() => Host.Services.GetRequiredService<Intune.IntuneRevocationSync>();

    private Task Issue(string label, string subject, string? upn, string? intuneDeviceId, string? dns = null) =>
        GivenCertificateAgain(label, subject, upn, intuneDeviceId, dns);

    private async Task GivenCertificateAgain(string label, string subject, string? upn, string? intuneDeviceId, string? dns)
    {
        using var key = RSA.Create(2048);
        var csr = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        if (upn is not null || intuneDeviceId is not null || dns is not null)
        {
            csr.CertificateExtensions.Add(new X509Extension(Oids.SubjectAltName, SubjectAlternativeNames(upn, intuneDeviceId, dns), false));
        }

        var ca = Host.Services.GetRequiredService<ICertificateAuthority>();
        var response = await ca.SignCertificateRequest(csr, "rsa").ConfigureAwait(false);
        var success = Assert.IsType<SignCertificateResponse.Success>(response);
        _byLabel[label] = success.Certificate;
    }

    /// <summary>
    /// A SAN as Intune writes it: the UPN as otherName 1.3.6.1.4.1.311.20.2.3, the Intune
    /// device id as a URI, a DNS name for a server.
    /// </summary>
    private static byte[] SubjectAlternativeNames(string? upn, string? intuneDeviceId, string? dns)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            if (upn is not null)
            {
                var otherName = new Asn1Tag(TagClass.ContextSpecific, 0);
                using (writer.PushSequence(otherName))
                {
                    writer.WriteObjectIdentifier(Oids.UserPrincipalName);
                    using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                    {
                        writer.WriteCharacterString(UniversalTagNumber.UTF8String, upn);
                    }
                }
            }

            if (dns is not null)
            {
                writer.WriteCharacterString(UniversalTagNumber.IA5String, dns, new Asn1Tag(TagClass.ContextSpecific, 2));
            }

            if (intuneDeviceId is not null)
            {
                writer.WriteCharacterString(UniversalTagNumber.IA5String, $"IntuneDeviceId://{intuneDeviceId}", new Asn1Tag(TagClass.ContextSpecific, 6));
            }
        }

        return writer.Encode();
    }

    private async Task<bool> IsRevoked(X509Certificate2 certificate)
    {
        var store = Host.Services.GetRequiredService<IStoreCertificates>();
        await foreach (var item in store.GetInventory(0, 1000).ConfigureAwait(false))
        {
            if (string.Equals(item.SerialNumber, certificate.SerialNumber, StringComparison.OrdinalIgnoreCase))
            {
                return item.IsRevoked;
            }
        }

        throw new InvalidOperationException($"{certificate.Subject} is not in the store");
    }

    public void Dispose()
    {
        _host?.Dispose();
        _fake.Dispose();
    }
}
