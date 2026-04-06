namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Diagnostics.CodeAnalysis;
using CertesSlim;
using CertesSlim.Acme;
using CertesSlim.Json;
using Microsoft.IdentityModel.Tokens;
using Reqnroll;
using Xunit;
using AcmeAccount = CertesSlim.Acme.Resource.Account;
using AcmeAccountStatus = CertesSlim.Acme.Resource.AccountStatus;
using AcmeOrderList = CertesSlim.Acme.Resource.OrderList;

public partial class CertificateServerFeatures
{
    private static readonly JsonSerializerOptions AcmeJsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    [UnconditionalSuppressMessage("AOT", "IL3050",
        Justification = "These conformance tests run in the regular test runtime and do not target AOT publishing.")]
    static CertificateServerFeatures()
    {
        AcmeJsonOptions.Converters.Add(new JsonStringEnumConverter());
    }

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

    [When("an ACME client creates a new account")]
    public async Task WhenAnAcmeClientCreatesANewAccount()
    {
        await SendSuccessfulNewAccountRequestAsync();
        AcmeState.AccountResponse = DeserializeAccountResponse();
        AcmeState.AccountUrl = AcmeState.Response?.Headers.Location;
        AcmeState.OrdersUrl = AcmeState.AccountResponse?.Orders;
    }

    [When("the client requests onlyReturnExisting for an existing account key")]
    public async Task WhenTheClientRequestsOnlyReturnExistingForAnExistingAccountKey()
    {
        await EnsureAccountCreatedAsync();
        await SendOnlyReturnExistingRequestAsync(AcmeState.Key!, expectSuccess: true).ConfigureAwait(false);

        AcmeState.AccountResponse = DeserializeAccountResponse();
        AcmeState.AccountUrl = AcmeState.Response?.Headers.Location;
        AcmeState.OrdersUrl = AcmeState.AccountResponse?.Orders;
    }

    [When("the client requests onlyReturnExisting for an unknown account key")]
    public async Task WhenTheClientRequestsOnlyReturnExistingForAnUnknownAccountKey()
    {
        AcmeState.UnknownKey = KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha256);
        await SendOnlyReturnExistingRequestAsync(AcmeState.UnknownKey, expectSuccess: false).ConfigureAwait(false);
    }

    [When("the client fetches an existing account by its account URL")]
    public async Task WhenTheClientFetchesAnExistingAccountByItsAccountUrl()
    {
        await EnsureAccountCreatedAsync();
        AcmeState.AccountResponse = await AcmeState.AccountContext!.Resource().ConfigureAwait(false);
    }

    [When("the client updates an existing account")]
    public async Task WhenTheClientUpdatesAnExistingAccount()
    {
        await EnsureAccountCreatedAsync();

        AcmeState.ExpectedContacts = ["mailto:updated@example.com", "mailto:security@example.com"];
        AcmeState.AccountResponse = await AcmeState.AccountContext!
            .Update(AcmeState.ExpectedContacts, agreeTermsOfService: true)
            .ConfigureAwait(false);
        AcmeState.AccountResponse = await AcmeState.AccountContext.Resource().ConfigureAwait(false);
    }

    [When("the client POSTs an account object with status \"deactivated\" to its account URL")]
    public async Task WhenTheClientPostsAnAccountObjectWithStatusDeactivatedToItsAccountUrl()
    {
        await EnsureAccountCreatedAsync();
        AcmeState.AccountResponse = await AcmeState.AccountContext!.Deactivate().ConfigureAwait(false);
    }

    [When("the client fetches the account orders URL")]
    public async Task WhenTheClientFetchesTheAccountOrdersUrl()
    {
        await EnsureAccountCreatedAsync();

        var orderContext = await AcmeState.Context!.NewOrder(null, ["localhost"]).ConfigureAwait(false);
        AcmeState.ExpectedOrderUrls = [orderContext.Location];
        var account = await AcmeState.AccountContext!.Resource().ConfigureAwait(false);
        AcmeState.OrdersUrl = account.Orders;
        Assert.NotNull(AcmeState.OrdersUrl);

        var signedPayload = await AcmeState.Context.Sign<object?>(null, AcmeState.OrdersUrl!).ConfigureAwait(false);
        await SendAcmeRequestAsync(HttpMethod.Post, AcmeState.OrdersUrl!.ToString(), signedPayload).ConfigureAwait(false);
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
    [Then("the ACME server MUST reject the request with the \"(.+)\" ACME error type")]
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

    [Then(@"the response MUST use status code (\d+)")]
    [Then(@"the ACME server MUST return status code (\d+)")]
    public void ThenTheResponseMustUseStatusCode(int expectedStatusCode)
    {
        Assert.Equal((HttpStatusCode)expectedStatusCode, AcmeState.Response?.StatusCode);
    }

    [Then("the response MUST include the account URL in the Location header")]
    public void ThenTheResponseMustIncludeTheAccountUrlInTheLocationHeader()
    {
        Assert.NotNull(AcmeState.Response?.Headers.Location);
        Assert.True(AcmeState.Response!.Headers.Location!.IsAbsoluteUri);
        Assert.Equal(Uri.UriSchemeHttps, AcmeState.Response.Headers.Location.Scheme);
        AcmeState.AccountUrl = AcmeState.Response.Headers.Location;
    }

    [Then("the response body MUST be an account object whose status is \"valid\"")]
    [Then("the response body MUST describe the existing account")]
    public void ThenTheResponseBodyMustDescribeAValidAccount()
    {
        var account = AcmeState.AccountResponse ?? DeserializeAccountResponse();
        Assert.Equal(AcmeAccountStatus.Valid, account.Status);
        Assert.NotNull(account.Orders);
        Assert.True(account.Orders!.IsAbsoluteUri);
        Assert.Equal(Uri.UriSchemeHttps, account.Orders.Scheme);
    }

    [Then("the account object MUST include the orders URL")]
    public void ThenTheAccountObjectMustIncludeTheOrdersUrl()
    {
        var account = AcmeState.AccountResponse ?? DeserializeAccountResponse();
        Assert.NotNull(account.Orders);
        Assert.True(account.Orders!.IsAbsoluteUri);
        Assert.Equal(Uri.UriSchemeHttps, account.Orders.Scheme);
        AcmeState.OrdersUrl = account.Orders;
    }

    [Then("the ACME server MUST NOT create a new account")]
    public async Task ThenTheAcmeServerMustNotCreateANewAccount()
    {
        Assert.NotNull(AcmeState.UnknownKey);
        await SendOnlyReturnExistingRequestAsync(AcmeState.UnknownKey!, expectSuccess: false).ConfigureAwait(false);
        Assert.Equal(HttpStatusCode.BadRequest, AcmeState.Response?.StatusCode);
    }

    [Then("the ACME server MUST return the current account object")]
    [Then("the response MUST return the updated account object")]
    public void ThenTheAcmeServerMustReturnTheCurrentAccountObject()
    {
        Assert.NotNull(AcmeState.AccountResponse);
        Assert.NotNull(AcmeState.AccountResponse!.Status);
        Assert.NotNull(AcmeState.AccountResponse.Orders);
    }

    [Then("the ACME server MUST apply contact changes carried in the account object")]
    public void ThenTheAcmeServerMustApplyContactChangesCarriedInTheAccountObject()
    {
        Assert.NotNull(AcmeState.AccountResponse?.Contact);
        Assert.Equal(AcmeState.ExpectedContacts, AcmeState.AccountResponse!.Contact);
    }

    [Then("the ACME server MUST record agreement to updated terms of service when requested")]
    public void ThenTheAcmeServerMustRecordAgreementToUpdatedTermsOfServiceWhenRequested()
    {
        Assert.True(AcmeState.AccountResponse?.TermsOfServiceAgreed);
    }

    [Then("the ACME server MUST deactivate the account")]
    [Then("the returned account object MUST have status \"deactivated\"")]
    public void ThenTheReturnedAccountObjectMustHaveStatusDeactivated()
    {
        Assert.Equal(AcmeAccountStatus.Deactivated, AcmeState.AccountResponse?.Status);
    }

    [Then("the ACME server MUST return the list of order URLs for that account")]
    public void ThenTheAcmeServerMustReturnTheListOfOrderUrlsForThatAccount()
    {
        var orderList = DeserializeResponse<AcmeOrderList>();
        Assert.NotNull(orderList.Orders);
        Assert.Contains(AcmeState.ExpectedOrderUrls!.Single(), orderList.Orders);
        Assert.All(orderList.Orders, orderUrl =>
        {
            Assert.True(orderUrl.IsAbsoluteUri);
            Assert.Equal(Uri.UriSchemeHttps, orderUrl.Scheme);
        });
    }

    [Then("if the result is paginated the ACME server MUST use Link headers with relation \"next\"")]
    public void ThenIfTheResultIsPaginatedTheAcmeServerMustUseLinkHeadersWithRelationNext()
    {
        if (AcmeState.Response == null || !AcmeState.Response.Headers.TryGetValues("Link", out var values))
        {
            return;
        }

        var nextLinks = values.Where(value => value.Contains("rel=\"next\"", StringComparison.OrdinalIgnoreCase)).ToList();
        Assert.All(nextLinks, nextLink => Assert.Contains("rel=\"next\"", nextLink, StringComparison.OrdinalIgnoreCase));
    }

    private async Task SendSuccessfulNewAccountRequestAsync()
    {
        using var captureHandler = new AcmeCaptureHandler(_server.CreateHandler());
        var capturedContext = CreateAcmeContext(captureHandler, AcmeState.Key ??= KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha256));

        _ = await capturedContext.NewAccount(["mailto:test@example.com"], true).ConfigureAwait(false);

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

        AcmeState.Context = CreateAcmeContext(_server.CreateClient(), AcmeState.Key!);
        AcmeState.AccountContext = await AcmeState.Context.Account().ConfigureAwait(false);
    }

    private async Task SendOnlyReturnExistingRequestAsync(IKey key, bool expectSuccess)
    {
        await SendJwkSignedNewAccountRequestAsync(key, new
        {
            onlyReturnExisting = true
        }).ConfigureAwait(false);

        if (expectSuccess)
        {
            Assert.Equal(HttpStatusCode.OK, AcmeState.Response?.StatusCode);
            return;
        }

        Assert.Equal(HttpStatusCode.BadRequest, AcmeState.Response?.StatusCode);
    }

    private async Task EnsureAccountCreatedAsync()
    {
        if (AcmeState.AccountContext != null && AcmeState.Context != null)
        {
            return;
        }

        await SendSuccessfulNewAccountRequestAsync().ConfigureAwait(false);
        AcmeState.AccountResponse = DeserializeAccountResponse();
        AcmeState.AccountUrl = AcmeState.Response?.Headers.Location;
        AcmeState.OrdersUrl = AcmeState.AccountResponse?.Orders;
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
        Justification = "These conformance tests run in the regular test runtime and do not target AOT publishing.")]
    private async Task SendJwkSignedNewAccountRequestAsync<TPayload>(IKey key, TPayload payload)
    {
        using var client = _server.CreateClient();
        client.BaseAddress = new Uri("http://localhost");

        var requestUrl = new Uri(client.BaseAddress, "/new-account");
        var acmeHttpClient = new AcmeHttpClient(new Uri(client.BaseAddress, "/directory"), client);
        var nonce = await acmeHttpClient.ConsumeNonce().ConfigureAwait(false);
        var signedPayload = CreateJwkSignedPayload(key, payload, requestUrl, nonce);
        await SendAcmeRequestAsync(HttpMethod.Post, requestUrl.ToString(), signedPayload).ConfigureAwait(false);
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
        Justification = "These conformance tests deserialize small ACME account payloads in the normal test runtime only.")]
    [UnconditionalSuppressMessage("AOT", "IL3050",
        Justification = "These conformance tests run in the standard test runtime and do not target AOT publishing.")]
    private AcmeAccount DeserializeAccountResponse()
    {
        Assert.NotNull(AcmeState.ResponseBytes);
        return JsonSerializer.Deserialize<AcmeAccount>(AcmeState.ResponseBytes!, AcmeJsonOptions)
               ?? throw new Xunit.Sdk.XunitException("Could not deserialize ACME account response.");
    }

    [UnconditionalSuppressMessage("Trimming", "IL2026",
        Justification = "These conformance tests deserialize small ACME payloads in the normal test runtime only.")]
    [UnconditionalSuppressMessage("AOT", "IL3050",
        Justification = "These conformance tests run in the standard test runtime and do not target AOT publishing.")]
    private T DeserializeResponse<T>()
    {
        Assert.NotNull(AcmeState.ResponseBytes);
        return JsonSerializer.Deserialize<T>(AcmeState.ResponseBytes!)
               ?? throw new Xunit.Sdk.XunitException($"Could not deserialize ACME response as {typeof(T).Name}.");
    }

    private AcmeContext CreateAcmeContext(HttpMessageHandler handler, IKey key)
    {
        var client = new HttpClient(handler)
        {
            BaseAddress = new Uri("http://localhost")
        };

        return CreateAcmeContext(client, key);
    }

    private AcmeContext CreateAcmeContext(HttpClient client, IKey key)
    {
        client.BaseAddress ??= new Uri("http://localhost");

        var directoryUri = new Uri(client.BaseAddress!, "/directory");
        return new AcmeContext(directoryUri, accountKey: key, http: new AcmeHttpClient(directoryUri, client));
    }

    [UnconditionalSuppressMessage("Trimming", "IL2026",
        Justification = "These conformance tests build small JSON payloads at runtime in the test host only.")]
    [UnconditionalSuppressMessage("AOT", "IL3050",
        Justification = "These conformance tests run in the standard test runtime and do not target AOT publishing.")]
    private static JwsPayload CreateJwkSignedPayload<TPayload>(IKey key, TPayload payload, Uri requestUrl, string nonce)
    {
        var protectedHeader = new
        {
            alg = ToJwsAlgorithm(key.Algorithm),
            jwk = key.JsonWebKey,
            nonce,
            url = requestUrl
        };

        var protectedHeaderJson = JsonSerializer.Serialize(protectedHeader);
        var payloadJson = payload == null ? string.Empty : JsonSerializer.Serialize(payload);

        var protectedHeaderEncoded = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(protectedHeaderJson));
        var payloadEncoded = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payloadJson));
        var signingBytes = Encoding.UTF8.GetBytes($"{protectedHeaderEncoded}.{payloadEncoded}");

        var signatureBytes = key.SecurityKey switch
        {
            ECDsaSecurityKey e => e.ECDsa.SignData(signingBytes, key.HashAlgorithm),
            RsaSecurityKey r => r.Rsa.SignData(signingBytes, key.HashAlgorithm, System.Security.Cryptography.RSASignaturePadding.Pss),
            _ => throw new NotSupportedException("Unsupported key type.")
        };

        return new JwsPayload
        {
            Protected = protectedHeaderEncoded,
            Payload = payloadEncoded,
            Signature = Base64UrlEncoder.Encode(signatureBytes)
        };
    }

    private static string ToJwsAlgorithm(string algorithm)
        => algorithm switch
        {
            SecurityAlgorithms.EcdsaSha256 => "ES256",
            SecurityAlgorithms.EcdsaSha384 => "ES384",
            SecurityAlgorithms.EcdsaSha512 => "ES512",
            SecurityAlgorithms.RsaSha256 => "RS256",
            SecurityAlgorithms.RsaSha384 => "RS384",
            SecurityAlgorithms.RsaSha512 => "RS512",
            _ => throw new ArgumentException($"Unsupported algorithm '{algorithm}'.", nameof(algorithm))
        };

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

        public AcmeContext? Context { get; set; }

        public IAccountContext? AccountContext { get; set; }

        public AcmeAccount? AccountResponse { get; set; }

        public Uri? AccountUrl { get; set; }

        public Uri? OrdersUrl { get; set; }

        public IList<string>? ExpectedContacts { get; set; }

        public IList<Uri>? ExpectedOrderUrls { get; set; }

        public string? RequestNonce { get; set; }

        public string? RawRequestBody { get; set; }

        public JwsPayload? SignedPayload { get; set; }

        public IKey? Key { get; set; }

        public IKey? UnknownKey { get; set; }
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







