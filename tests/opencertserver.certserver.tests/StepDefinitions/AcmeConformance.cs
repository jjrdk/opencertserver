namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Net;
using System.Text;
using System.Text.Json;
using System.Diagnostics.CodeAnalysis;
using CertesSlim;
using CertesSlim.Acme;
using CertesSlim.Json;
using Microsoft.IdentityModel.Tokens;
using Reqnroll;
using Xunit;

public partial class CertificateServerFeatures
{
    private AcmeConformanceState AcmeState
    {
        get
        {
            if (_scenarioContext.TryGetValue(nameof(AcmeConformanceState), out var value) &&
                value is AcmeConformanceState state)
            {
                return state;
            }

            state = new AcmeConformanceState();
            _scenarioContext[nameof(AcmeConformanceState)] = state;
            return state;
        }
    }

    [BeforeScenario("@acme")]
    public void ResetAcmeConformanceState()
    {
        _scenarioContext.Remove(nameof(AcmeConformanceState));
    }

    [When("the client requests a new nonce with HEAD")]
    public async Task WhenTheClientRequestsANewNonceWithHead()
    {
        await SendAcmeRequestAsync(HttpMethod.Head, "/new-nonce");
    }

    [When("the client requests a new nonce with GET")]
    public async Task WhenTheClientRequestsANewNonceWithGet()
    {
        await SendAcmeRequestAsync(HttpMethod.Get, "/new-nonce");
    }

    [When("the client sends a POST request to an ACME resource")]
    public async Task WhenTheClientSendsAPostRequestToAnAcmeResource()
    {
        await SendSuccessfulNewAccountRequestAsync();
    }

    [When("the client successfully POSTs to an ACME resource")]
    public async Task WhenTheClientSuccessfullyPostsToAnAcmeResource()
    {
        await SendSuccessfulNewAccountRequestAsync();
    }

    [When("the ACME server rejects a request for a protocol reason")]
    public async Task WhenTheAcmeServerRejectsARequestForAProtocolReason()
    {
        await SendReplayNonceFailureAsync();
    }

    [When("the ACME server returns an error response to a POST request")]
    public async Task WhenTheAcmeServerReturnsAnErrorResponseToAPostRequest()
    {
        await SendReplayNonceFailureAsync();
    }

    [Then("the ACME server MUST return a Replay-Nonce header")]
    [Then("the ACME server SHOULD return a Replay-Nonce header")]
    public void ThenTheAcmeServerMustReturnAReplayNonceHeader()
    {
        Assert.NotNull(AcmeState.Response);
        Assert.True(AcmeState.Response!.Headers.TryGetValues("Replay-Nonce", out var values));
        Assert.False(string.IsNullOrWhiteSpace(values.Single()));
    }

    [Then("the newNonce response body MUST be empty")]
    public void ThenTheNewNonceResponseBodyMustBeEmpty()
    {
        Assert.NotNull(AcmeState.ResponseBytes);
        Assert.Empty(AcmeState.ResponseBytes!);
    }

    [Then("the newNonce response status code MUST indicate success")]
    public void ThenTheNewNonceResponseStatusCodeMustIndicateSuccess()
    {
        Assert.NotNull(AcmeState.Response);
        Assert.True((int)AcmeState.Response!.StatusCode is >= 200 and < 300,
            $"Expected a successful newNonce response but got {(int)AcmeState.Response.StatusCode}.");
    }

    [Then("the JWS protected header MUST contain a nonce from the ACME server")]
    public void ThenTheJwsProtectedHeaderMustContainANonceFromTheAcmeServer()
    {
        Assert.NotNull(AcmeState.SignedPayload);
        Assert.False(string.IsNullOrWhiteSpace(AcmeState.RequestNonce));

        using var document = JsonDocument.Parse(Base64UrlEncoder.Decode(AcmeState.SignedPayload!.Protected));
        Assert.True(document.RootElement.TryGetProperty("nonce", out var nonceProperty));
        Assert.Equal(AcmeState.RequestNonce, nonceProperty.GetString());
    }

    [Then("the ACME server MUST reject a reused or otherwise unacceptable nonce")]
    public async Task ThenTheAcmeServerMustRejectAReusedOrOtherwiseUnacceptableNonce()
    {
        Assert.NotNull(AcmeState.SignedPayload);

        await SendAcmeRequestAsync(HttpMethod.Post, "/new-account", AcmeState.SignedPayload);

        Assert.Equal(HttpStatusCode.BadRequest, AcmeState.Response?.StatusCode);
    }

    [Then("the rejection MUST use the \"(.+)\" ACME error type")]
    public void ThenTheRejectionMustUseTheAcmeErrorType(string errorType)
    {
        using var problem = ParseProblemDocument();
        var type = problem.RootElement.GetProperty("type").GetString();
        Assert.NotNull(type);
        Assert.EndsWith($":{errorType}", type, StringComparison.Ordinal);
    }

    [Then("the rejection response MUST include a fresh Replay-Nonce header")]
    [Then("the response MUST include a fresh Replay-Nonce header")]
    public void ThenTheResponseMustIncludeAFreshReplayNonceHeader()
    {
        Assert.NotNull(AcmeState.Response);
        Assert.True(AcmeState.Response!.Headers.TryGetValues("Replay-Nonce", out var values));
        var replayNonce = values.Single();
        Assert.False(string.IsNullOrWhiteSpace(replayNonce));

        if (!string.IsNullOrWhiteSpace(AcmeState.RequestNonce))
        {
            Assert.NotEqual(AcmeState.RequestNonce, replayNonce);
        }
    }

    [Scope(Tag = "acme")]
    [Then("the response content type MUST be \"(.+)\"")]
    public void ThenTheAcmeResponseContentTypeMustBe(string mediaType)
    {
        Assert.Equal(mediaType, AcmeState.Response?.Content.Headers.ContentType?.MediaType);
    }

    [Then("the body MUST contain the ACME problem \"type\"")]
    public void ThenTheBodyMustContainTheAcmeProblemType()
    {
        using var problem = ParseProblemDocument();
        Assert.True(problem.RootElement.TryGetProperty("type", out var typeProperty));
        Assert.False(string.IsNullOrWhiteSpace(typeProperty.GetString()));
    }

    [Then("the body MUST contain the human-readable \"detail\"")]
    public void ThenTheBodyMustContainTheHumanReadableDetail()
    {
        using var problem = ParseProblemDocument();
        Assert.True(problem.RootElement.TryGetProperty("detail", out var detailProperty));
        Assert.False(string.IsNullOrWhiteSpace(detailProperty.GetString()));
    }

    [Then("the body MUST contain the HTTP \"status\"")]
    public void ThenTheBodyMustContainTheHttpStatus()
    {
        using var problem = ParseProblemDocument();
        Assert.True(problem.RootElement.TryGetProperty("status", out var statusProperty));
        Assert.Equal((int)(AcmeState.Response?.StatusCode ?? 0), statusProperty.GetInt32());
    }

    [Then("the problem type MUST be an \"urn:ietf:params:acme:error:\" URN")]
    public void ThenTheProblemTypeMustBeAnAcmeUrn()
    {
        using var problem = ParseProblemDocument();
        var type = problem.RootElement.GetProperty("type").GetString();
        Assert.NotNull(type);
        Assert.StartsWith("urn:ietf:params:acme:error:", type, StringComparison.Ordinal);
    }

    private async Task SendSuccessfulNewAccountRequestAsync()
    {
        using var captureHandler = new AcmeCaptureHandler(_server.CreateHandler());
        using var client = new HttpClient(captureHandler)
        {
            BaseAddress = new Uri("http://localhost")
        };

        var directoryUri = new Uri(client.BaseAddress!, "/directory");
        var acmeContext = new AcmeContext(
            directoryUri,
            accountKey: AcmeState.Key ??= KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha256),
            http: new AcmeHttpClient(directoryUri, client));

        _ = await acmeContext.NewAccount(["mailto:test@example.com"], true);

        var exchange = captureHandler.Exchanges.LastOrDefault(x =>
            x.Method == HttpMethod.Post &&
            string.Equals(x.RequestUri.AbsolutePath, "/new-account", StringComparison.Ordinal));

        Assert.NotNull(exchange);

        AcmeState.Response = exchange.Response;
        AcmeState.ResponseBytes = exchange.ResponseBytes;
        AcmeState.RawRequestBody = exchange.RequestBody;
        using var requestDocument = JsonDocument.Parse(exchange.RequestBody);
        AcmeState.SignedPayload = new JwsPayload
        {
            Protected = requestDocument.RootElement.GetProperty("protected").GetString(),
            Payload = requestDocument.RootElement.GetProperty("payload").GetString(),
            Signature = requestDocument.RootElement.GetProperty("signature").GetString()
        };
        Assert.NotNull(AcmeState.SignedPayload);

        using var protectedHeader = JsonDocument.Parse(Base64UrlEncoder.Decode(AcmeState.SignedPayload!.Protected));
        AcmeState.RequestNonce = protectedHeader.RootElement.GetProperty("nonce").GetString();

        if (AcmeState.Response?.StatusCode != HttpStatusCode.Created)
        {
            var body = Encoding.UTF8.GetString(AcmeState.ResponseBytes ?? []);
            throw new Xunit.Sdk.XunitException(
                $"Expected 201 Created from /new-account but got {(int?)AcmeState.Response?.StatusCode} with body: {body}");
        }
    }

    private async Task SendReplayNonceFailureAsync()
    {
        await SendSuccessfulNewAccountRequestAsync();
        Assert.False(string.IsNullOrWhiteSpace(AcmeState.RawRequestBody));
        await SendRawAcmeRequestAsync(HttpMethod.Post, "/new-account", AcmeState.RawRequestBody!);
        Assert.Equal(HttpStatusCode.BadRequest, AcmeState.Response?.StatusCode);
    }

    [UnconditionalSuppressMessage("Trimming", "IL2026",
        Justification = "These conformance tests build small JSON payloads at runtime in the test host only.")]
    [UnconditionalSuppressMessage("AOT", "IL3050",
        Justification = "These conformance tests run in the normal test runtime and do not target AOT publishing.")]
    private async Task SendAcmeRequestAsync(HttpMethod method, string path, JwsPayload? payload = null)
    {
        await SendRawAcmeRequestAsync(method, path,
            payload == null ? null : JsonSerializer.Serialize(payload));
    }

    private JsonDocument ParseProblemDocument()
    {
        Assert.NotNull(AcmeState.ResponseBytes);
        return JsonDocument.Parse(AcmeState.ResponseBytes!);
    }

    [UnconditionalSuppressMessage("Trimming", "IL2026",
        Justification = "These conformance tests build small JSON payloads at runtime in the test host only.")]
    [UnconditionalSuppressMessage("AOT", "IL3050",
        Justification = "These conformance tests run in the normal test runtime and do not target AOT publishing.")]
    private async Task SendRawAcmeRequestAsync(HttpMethod method, string path, string? requestBody)
    {
        using var client = _server.CreateClient();
        using var request = new HttpRequestMessage(method, path);
        if (requestBody != null)
        {
            request.Content = new StringContent(requestBody, Encoding.UTF8, "application/jose+json");
        }

        var response = await client.SendAsync(request);
        AcmeState.Response = response;
        AcmeState.ResponseBytes = await response.Content.ReadAsByteArrayAsync();
    }

    private sealed class AcmeConformanceState
    {
        public HttpResponseMessage? Response { get; set; }

        public byte[]? ResponseBytes { get; set; }

        public string? RequestNonce { get; set; }

        public string? RawRequestBody { get; set; }

        public JwsPayload? SignedPayload { get; set; }

        public IKey? Key { get; set; }
    }

    private sealed class AcmeCaptureHandler : DelegatingHandler
    {
        public AcmeCaptureHandler(HttpMessageHandler innerHandler)
            : base(innerHandler)
        {
        }

        public List<AcmeExchange> Exchanges { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var requestBody = request.Content == null
                ? string.Empty
                : await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

            var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
            var responseBytes = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);

            var clonedResponse = new HttpResponseMessage(response.StatusCode)
            {
                ReasonPhrase = response.ReasonPhrase,
                Version = response.Version,
                RequestMessage = response.RequestMessage,
                Content = new ByteArrayContent(responseBytes)
            };

            foreach (var header in response.Headers)
            {
                _ = clonedResponse.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            foreach (var header in response.Content.Headers)
            {
                _ = clonedResponse.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            Exchanges.Add(new AcmeExchange(request.Method, request.RequestUri!, requestBody, clonedResponse, responseBytes));

            var replacementContent = new ByteArrayContent(responseBytes);
            foreach (var header in response.Content.Headers)
            {
                _ = replacementContent.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            response.Content = replacementContent;

            return response;
        }
    }

    private sealed record AcmeExchange(
        HttpMethod Method,
        Uri RequestUri,
        string RequestBody,
        HttpResponseMessage Response,
        byte[] ResponseBytes);
}







