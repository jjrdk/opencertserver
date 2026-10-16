namespace OpenCertServer.Contrib.Intune.Tests.Steps;

using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Hosting;
using OpenCertServer.Scep.Tests;
using Reqnroll;
using Xunit;

[Binding]
public sealed class IntuneChallenge : IDisposable
{
    private const string Subject = "CN=Testgeraet, O=contoso";
    private const string Challenge = "intune-challenge-blob";

    private readonly FakeIntune _fake = new();
    private IHost _host = null!;
    private X509Certificate2 _ra = null!;
    private HttpResponseMessage? _response;
    private ScepTestResponse? _certRep;
    private RSA? _clientKey;
    private X509Certificate2? _clientSigner;
    private X509Certificate2? _held;
    private string _transactionId = NewTransactionId();

    [Given("a SCEP server that asks Intune about every request")]
    public void GivenServer()
    {
        (_host, _, _ra) = TestHostBuilder.Build(_fake);
    }

    [Given("a SCEP server that asks Intune about every request, authenticating with a certificate")]
    public void GivenServerWithCertificate()
    {
        (_host, _, _ra) = TestHostBuilder.Build(_fake, withCertificate: true);
    }

    [Given("Intune refuses with {string}")]
    public void GivenRefuses(string code)
    {
        _fake.Intune = IntuneBehaviour.Refuse;
        _fake.RefusalCode = code;
    }

    [Given("Intune is unreachable")]
    public void GivenUnreachable() => _fake.Intune = IntuneBehaviour.Unreachable;

    [Given("Intune answers with HTTP 429")]
    public void GivenThrottled() => _fake.Intune = IntuneBehaviour.Throttle;

    [Given("a device holding a certificate issued through Intune")]
    public async Task GivenHeld()
    {
        await Enroll(Challenge, "rsa").ConfigureAwait(false);
        ThenSuccess();
        _held = _certRep!.Issued!.CopyWithPrivateKey(_clientKey!);
    }

    [When("a device enrolls with the challenge Intune handed out")]
    [When("another device enrolls with the challenge Intune handed out")]
    public Task WhenEnroll() => Enroll(Challenge, "rsa");

    // The profile allows keyUsage from the CSR but not basicConstraints; keyCertSign/cRLSign
    // without a CA profile is what the CA refuses (RFC 5280 4.2.1.3) - after Intune said yes.
    [When("a device enrolls asking for keyCertSign and cRLSign")]
    public async Task WhenEnrollAsCa()
    {
        _clientKey = RSA.Create(2048);
        _clientSigner = ScepTestClient.CreateTransientSigner(_clientKey);
        _transactionId = NewTransactionId();
        var csr = ScepTestClient.CreateCsr(_clientKey, Subject, Challenge);
        csr.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        _response = await new ScepTestClient(_host.GetTestClient(), "/scep/rsa")
            .Enroll(csr, _clientSigner, _ra, _transactionId, RandomNumberGenerator.GetBytes(16))
            .ConfigureAwait(false);
        await ReadCertRep().ConfigureAwait(false);
    }

    [When("a device enrolls without a challenge password")]
    public Task WhenEnrollWithout() => Enroll(null, "rsa");

    [When("the device renews it with a new key")]
    public async Task WhenRenew()
    {
        var newKey = RSA.Create(2048);
        _clientSigner = _held!;
        _transactionId = NewTransactionId();
        var client = new ScepTestClient(_host.GetTestClient(), "/scep/rsa");
        _response = await client.Enroll(
                ScepTestClient.CreateCsr(newKey, Subject, challenge: null),
                _held!, _ra, _transactionId, RandomNumberGenerator.GetBytes(16), messageType: "17")
            .ConfigureAwait(false);
        await ReadCertRep().ConfigureAwait(false);
    }

    [Then("the server answers SUCCESS")]
    public void ThenSuccess()
    {
        Assert.Equal("3", _certRep!.MessageType);
        Assert.Equal("0", _certRep.PkiStatus);
        Assert.NotNull(_certRep.Issued);
    }

    [Then("the server answers FAILURE with failInfo badRequest")]
    public void ThenFailure()
    {
        Assert.Equal("2", _certRep!.PkiStatus);
        Assert.Equal("2", _certRep.FailInfo);
    }

    [Then("no certificate is returned")]
    public void ThenNoCertificate() => Assert.Null(_certRep!.Issued);

    [Then("Intune was asked with the transaction id and the request")]
    public void ThenAsked()
    {
        var call = Assert.Single(_fake.CallsTo("validateRequest"));
        var request = call!["request"]!;
        Assert.Equal(_transactionId, request["transactionId"]!.GetValue<string>());
        Assert.Equal("OpenCertServer tests", request["callerInfo"]!.GetValue<string>());
        var csr = Convert.FromBase64String(request["certificateRequest"]!.GetValue<string>());
        var parsed = CertificateRequest.LoadSigningRequest(csr, HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
        Assert.Equal(Subject, parsed.SubjectName.Name);
    }

    [Then("Intune was not asked")]
    public void ThenNotAsked() => Assert.Empty(_fake.CallsTo("validateRequest"));

    [Then("Intune was asked once in total")]
    public void ThenAskedOnce() => Assert.Single(_fake.CallsTo("validateRequest"));

    [Then("Intune received the success notification with thumbprint and serial number")]
    public void ThenSuccessNotified()
    {
        var call = Assert.Single(_fake.CallsTo("successNotification"));
        var notification = call!["notification"]!;
        Assert.Equal(_transactionId, notification["transactionId"]!.GetValue<string>());
        Assert.Equal(_certRep!.Issued!.Thumbprint, notification["certificateThumbprint"]!.GetValue<string>());
        Assert.Equal(_certRep.Issued.SerialNumber, notification["certificateSerialNumber"]!.GetValue<string>());
        Assert.Contains(_certRep.Issued.NotAfter.ToUniversalTime().Year.ToString(), notification["certificateExpirationDateUtc"]!.GetValue<string>());
        Assert.Empty(_fake.CallsTo("failureNotification"));
    }

    [Then("Intune received the failure notification")]
    public void ThenFailureNotified()
    {
        var call = Assert.Single(_fake.CallsTo("failureNotification"));
        var notification = call!["notification"]!;
        Assert.Equal(_transactionId, notification["transactionId"]!.GetValue<string>());
        Assert.False(string.IsNullOrEmpty(notification["errorDescription"]!.GetValue<string>()));
        Assert.Empty(_fake.CallsTo("successNotification"));
    }

    [Then("Intune received no failure notification")]
    public void ThenNoFailureNotified()
    {
        Assert.Empty(_fake.CallsTo("failureNotification"));
        Assert.Empty(_fake.CallsTo("successNotification"));
    }

    [Then("the validation service was discovered once")]
    public void ThenDiscoveredOnce() =>
        Assert.Single(_fake.Calls, c => c.Path.Contains("/servicePrincipals/", StringComparison.Ordinal));

    [Then("a token for the Intune resource was requested once")]
    public void ThenIntuneTokenOnce()
    {
        // Two tokens in total - one for Graph (discovery), one for Intune - and both reused for the second enrollment.
        Assert.Equal(2, _fake.TokenRequests);
    }

    [Then("every token was requested with an assertion signed by that certificate")]
    public void ThenAssertions()
    {
        Assert.True(_fake.TokenRequests > 0);
        Assert.Equal(_fake.TokenRequests, _fake.TokenRequestsWithAssertion);
    }

    [Then("every Intune call carried the api-version {string}")]
    public void ThenApiVersion(string version)
    {
        var intuneCalls = _fake.Calls.Where(c => c.Path.Contains("/ScepActions/", StringComparison.OrdinalIgnoreCase)).ToList();
        Assert.NotEmpty(intuneCalls);
        Assert.All(intuneCalls, c => Assert.Equal(version, c.ApiVersion));
    }

    private async Task Enroll(string? challenge, string profile)
    {
        _clientKey = RSA.Create(2048);
        _clientSigner = ScepTestClient.CreateTransientSigner(_clientKey);
        _transactionId = NewTransactionId();
        var client = new ScepTestClient(_host.GetTestClient(), $"/scep/{profile}");
        _response = await client.Enroll(
                ScepTestClient.CreateCsr(_clientKey, Subject, challenge),
                _clientSigner, _ra, _transactionId, RandomNumberGenerator.GetBytes(16))
            .ConfigureAwait(false);
        await ReadCertRep().ConfigureAwait(false);
    }

    private async Task ReadCertRep()
    {
        Assert.Equal(HttpStatusCode.OK, _response!.StatusCode);
        var body = await _response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
        _certRep = ScepTestResponse.Read(body, _clientSigner!);
    }

    private static string NewTransactionId() => Convert.ToHexString(RandomNumberGenerator.GetBytes(8));

    public void Dispose()
    {
        _host?.Dispose();
        _fake.Dispose();
    }
}
