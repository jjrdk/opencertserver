namespace OpenCertServer.Contrib.Intune.Tests.Steps;

using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenCertServer.Scep.Tests;
using Reqnroll;
using Xunit;

[Binding]
public sealed class DynamicScep : IDisposable
{
    private const string DeviceId = "22222222-2222-2222-2222-222222222222";
    private readonly FakeIntune _intune = new();
    private readonly WebhookHandler _webhook = new();
    private IHost? _host;
    private X509Certificate2? _ra;
    private RSA? _key;
    private X509Certificate2? _signer;
    private ScepTestResponse? _response;
    private HttpResponseMessage? _report;
    private Exception? _configurationError;

    [Given("an Intune SCEP server with a webhook that allows enrollment")]
    public void GivenAllowed() => Start();

    [Given("an Intune SCEP server with an unavailable webhook")]
    public void GivenUnavailable()
    {
        _webhook.Status = HttpStatusCode.ServiceUnavailable;
        Start();
    }

    [Given("an Intune SCEP server with an unreachable webhook")]
    public void GivenUnreachable()
    {
        _webhook.Unreachable = true;
        Start();
    }

    [Given("an Intune SCEP server with a malformed webhook response")]
    public void GivenMalformed()
    {
        _webhook.Body = "not json";
        Start();
    }

    [Given("an Intune SCEP server with a webhook that refuses enrollment")]
    public void GivenRefused()
    {
        _webhook.Body = """{"allowed":false}""";
        Start();
    }

    [Given("an Intune SCEP server with a webhook response without a decision")]
    public void GivenNoDecision()
    {
        _webhook.Body = "{}";
        Start();
    }

    private void Start()
    {
        (_host, _, _ra) = TestHostBuilder.Build(_intune, configureServices: services =>
            services.AddIntuneDynamicChallenge(
                new DynamicChallengeOptions { Webhook = new Uri("https://webhook.test/authorize"), Secret = "test-token" },
                http => http.ConfigurePrimaryHttpMessageHandler(() => _webhook)));
    }

    [Given("Intune refuses the dynamic enrollment")]
    public void GivenIntuneRefuses() => _intune.Intune = IntuneBehaviour.Refuse;

    [When("a managed device enrolls through the webhook")]
    public async Task Enroll()
    {
        _key = RSA.Create(2048);
        _signer = ScepTestClient.CreateTransientSigner(_key);
        var client = new ScepTestClient(_host!.GetTestClient(), "/scep/rsa");
        using var response = await client.Enroll(
            ScepTestClient.CreateCsr(_key, $"CN={DeviceId}", "intune-challenge-blob"),
            _signer, _ra!, Convert.ToHexString(RandomNumberGenerator.GetBytes(8)), RandomNumberGenerator.GetBytes(16));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        _response = ScepTestResponse.Read(await response.Content.ReadAsByteArrayAsync(), _signer);
    }

    [Then("the dynamic enrollment succeeds")]
    public void ThenSuccess() => Assert.Equal("0", _response!.PkiStatus);

    [Then("the dynamic enrollment fails")]
    public void ThenFailure() => Assert.Equal("2", _response!.PkiStatus);

    [Then("Intune and the webhook both validated the request")]
    public async Task ThenBothValidated()
    {
        Assert.Single(_intune.CallsTo("validateRequest"));
        Assert.Single(_intune.CallsTo("successNotification"));
        Assert.Equal(1, _webhook.Calls);
        Assert.Equal("Bearer", _webhook.Scheme);
        Assert.Equal("test-token", _webhook.Token);
        Assert.Contains("certificateRequest", _webhook.RequestBody);
        var simulator = Environment.GetEnvironmentVariable("OPENCERTSERVER_INTUNE_SIMULATOR_URL");
        if (simulator is not null)
        {
            await VerifySimulator(new Uri(simulator));
        }
    }

    private static async Task VerifySimulator(Uri address)
    {
        Assert.True(address.IsLoopback && address.Scheme == Uri.UriSchemeHttp,
            "The optional simulator must use a loopback HTTP address.");
        using var control = new HttpClient { BaseAddress = address };
        using var challengeResponse = await control.PostAsync("challenge", null);
        challengeResponse.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await challengeResponse.Content.ReadAsStringAsync());
        var root = json.RootElement;
        var urls = root.GetProperty("urls");
        var challenge = root.GetProperty("challengePassword").GetString();
        var options = new IntuneOptions
        {
            TenantId = urls.GetProperty("tenant").GetString()!,
            ClientId = urls.GetProperty("appId").GetString()!,
            ClientSecret = urls.GetProperty("authPassword").GetString()!,
            LoginBase = address,
            GraphBase = address,
            IntuneResource = address,
            SyncProfiles = ["rsa"]
        };
        using var unused = new FakeIntune();
        using var webhook = new WebhookHandler();
        var (host, ca, ra) = TestHostBuilder.Build(unused, intuneOptions: options,
            intuneHandler: () => new HttpClientHandler(), configureServices: services =>
                services.AddIntuneDynamicChallenge(
                    new DynamicChallengeOptions { Webhook = new Uri("https://webhook.test/authorize"), Secret = "test-token" },
                    http => http.ConfigurePrimaryHttpMessageHandler(() => webhook)));
        using (host)
        using (ca)
        using (ra)
        using (var key = RSA.Create(2048))
        using (var signer = ScepTestClient.CreateTransientSigner(key))
        {
            var client = new ScepTestClient(host.GetTestClient(), "/scep/rsa");
            using var response = await client.Enroll(ScepTestClient.CreateCsr(key, $"CN={DeviceId}", challenge),
                signer, ra, Convert.ToHexString(RandomNumberGenerator.GetBytes(8)), RandomNumberGenerator.GetBytes(16));
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var certRep = ScepTestResponse.Read(await response.Content.ReadAsByteArrayAsync(), signer);
            Assert.Equal("0", certRep.PkiStatus);
            Assert.Equal(1, webhook.Calls);
        }
    }

    [Then("Intune receives a failure notification for the webhook denial")]
    public void ThenIntuneNotified()
    {
        Assert.Single(_intune.CallsTo("failureNotification"));
        Assert.Empty(_intune.CallsTo("successNotification"));
    }

    [Then("the webhook was not called")]
    public void ThenWebhookNotCalled() => Assert.Equal(0, _webhook.Calls);

    [Then("the device appears in the authorized certificate report")]
    public async Task ThenDeviceReported()
    {
        var client = _host!.GetTestClient();
        client.DefaultRequestHeaders.Add("X-Test-Role", TestHostBuilder.SyncRole);
        var report = await client.GetFromJsonAsync<IntuneDeviceReport>("/scep/intune/devices");
        var certificate = Assert.Single(report!.Certificates);
        Assert.Equal(DeviceId, certificate.EntraDeviceId);
        Assert.Equal("rsa", certificate.Profile);
        Assert.False(certificate.IsRevoked);
    }

    [When("the dynamic device report is requested anonymously")]
    public async Task RequestReport() => _report = await _host!.GetTestClient().GetAsync("/scep/intune/devices");

    [Then("the dynamic device report is unauthorized")]
    public void ThenUnauthorized() => Assert.Equal(HttpStatusCode.Unauthorized, _report!.StatusCode);

    [Given("a dynamic webhook configured with an insecure URL")]
    public void GivenInsecureUrl()
    {
        _configurationError = Record.Exception(() => new ServiceCollection().AddIntuneDynamicChallenge(
            new DynamicChallengeOptions { Webhook = new Uri("http://webhook.test/authorize"), Secret = "test-token" }));
    }

    [Then("dynamic webhook registration is rejected")]
    public void ThenRegistrationRejected() => Assert.IsType<InvalidOperationException>(_configurationError);

    public void Dispose()
    {
        _report?.Dispose();
        _signer?.Dispose();
        _key?.Dispose();
        _host?.Dispose();
        _intune.Dispose();
        _webhook.Dispose();
    }

    private sealed class WebhookHandler : HttpMessageHandler
    {
        public HttpStatusCode Status { get; set; } = HttpStatusCode.OK;
        public string Body { get; set; } = """{"allowed":true}""";
        public int Calls { get; private set; }
        public string? Scheme { get; private set; }
        public string? Token { get; private set; }
        public string RequestBody { get; private set; } = "";
        public bool Unreachable { get; set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            if (Unreachable)
            {
                throw new HttpRequestException("Webhook unreachable.");
            }
            Scheme = request.Headers.Authorization?.Scheme;
            Token = request.Headers.Authorization?.Parameter;
            RequestBody = await request.Content!.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(Status) { Content = new StringContent(Body, System.Text.Encoding.UTF8, "application/json") };
        }
    }
}
