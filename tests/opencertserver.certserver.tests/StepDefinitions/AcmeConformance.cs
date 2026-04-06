namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Diagnostics.CodeAnalysis;
using CertesSlim;
using CertesSlim.Acme;
using CertesSlim.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Reqnroll;
using Xunit;
using AcmeAccount = CertesSlim.Acme.Resource.Account;
using AcmeAccountStatus = CertesSlim.Acme.Resource.AccountStatus;
using AcmeCertificateChain = CertesSlim.Acme.CertificateChain;
using AcmeOrder = CertesSlim.Acme.Resource.Order;
using AcmeOrderList = CertesSlim.Acme.Resource.OrderList;
using AcmeOrderStatus = CertesSlim.Acme.Resource.OrderStatus;

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

    [When("the client POSTs to an ACME resource")]
    public async Task WhenTheClientPostsToAnAcmeResource()
    {
        await SendJwkSignedRequestAsync(
            AcmeState.Key ??= KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha256),
            "/new-account",
            new
            {
                contact = new[] { "mailto:test@example.com" },
                termsOfServiceAgreed = true
            }).ConfigureAwait(false);
    }

    [When("the client successfully POSTs to an ACME resource")]
    public async Task WhenTheClientSuccessfullyPostsToAnAcmeResource()
    {
        await SendSuccessfulNewAccountRequestAsync();
    }

    [When("the client POSTs an ACME request with the wrong content type")]
    public async Task WhenTheClientPostsAnAcmeRequestWithTheWrongContentType()
    {
        await SendJwkSignedRequestAsync(
            AcmeState.Key ??= KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha256),
            "/new-account",
            new
            {
                contact = new[] { "mailto:test@example.com" },
                termsOfServiceAgreed = true
            },
            contentType: "application/json").ConfigureAwait(false);
    }

    [When("the JWS protected header \"url\" value does not equal the actual request URL")]
    public async Task WhenTheJwsProtectedHeaderUrlValueDoesNotEqualTheActualRequestUrl()
    {
        await SendJwkSignedRequestAsync(
            AcmeState.Key ??= KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha256),
            "/new-account",
            new
            {
                contact = new[] { "mailto:test@example.com" },
                termsOfServiceAgreed = true
            },
            protectedUrl: new Uri("http://localhost/not-the-request-url")).ConfigureAwait(false);
    }

    [When("the client sends a POST-as-GET request with a non-empty payload")]
    public async Task WhenTheClientSendsAPostAsGetRequestWithANonEmptyPayload()
    {
        await EnsureAccountCreatedAsync();

        var orderContext = await AcmeState.Context!.NewOrder(null, ["localhost"]).ConfigureAwait(false);
        var signedPayload = CreateSignedPayload(
            AcmeState.Key!,
            new { invalidPostAsGet = true },
            orderContext.Location,
            await GetFreshNonceAsync().ConfigureAwait(false),
            kid: GetAccountLocation());
        await SendAcmeRequestAsync(HttpMethod.Post, orderContext.Location.ToString(), signedPayload).ConfigureAwait(false);
    }

    [When("the client POSTs to the newAccount resource")]
    public async Task WhenTheClientPostsToTheNewAccountResource()
    {
        await SendJwkSignedRequestAsync(
            AcmeState.Key ??= KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha256),
            "/new-account",
            new
            {
                contact = new[] { "mailto:test@example.com" },
                termsOfServiceAgreed = true
            }).ConfigureAwait(false);
    }

    [When("the client POSTs to an existing account order authorization challenge finalize or certificate resource")]
    public async Task WhenTheClientPostsToAnExistingAccountOrderAuthorizationChallengeFinalizeOrCertificateResource()
    {
        await CaptureNewOrderRequestAsync().ConfigureAwait(false);
    }

    [When("the client sends a newAccount request signed with a kid instead of a jwk")]
    public async Task WhenTheClientSendsANewAccountRequestSignedWithAKidInsteadOfAJwk()
    {
        await EnsureAccountCreatedAsync();

        var signedPayload = CreateSignedPayload(
            AcmeState.Key!,
            new
            {
                contact = new[] { "mailto:test@example.com" },
                termsOfServiceAgreed = true
            },
            new Uri("http://localhost/new-account"),
            await GetFreshNonceAsync().ConfigureAwait(false),
            kid: GetAccountLocation());

        await SendAcmeRequestAsync(HttpMethod.Post, "/new-account", signedPayload).ConfigureAwait(false);
    }

    [When("the client sends an existing-account request signed with a jwk instead of a kid")]
    public async Task WhenTheClientSendsAnExistingAccountRequestSignedWithAJwkInsteadOfAKid()
    {
        await EnsureAccountCreatedAsync();

        await SendJwkSignedRequestAsync(
            AcmeState.Key!,
            "/new-order",
            new
            {
                identifiers = new[]
                {
                    new { type = "dns", value = "localhost" }
                }
            }).ConfigureAwait(false);
    }

    [When("the client sends an existing-account request with an unknown kid")]
    public async Task WhenTheClientSendsAnExistingAccountRequestWithAnUnknownKid()
    {
        AcmeState.UnknownKey ??= KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha256);
        var nonce = await GetFreshNonceAsync().ConfigureAwait(false);
        var signedPayload = CreateSignedPayload(
            AcmeState.UnknownKey,
            new
            {
                identifiers = new[]
                {
                    new { type = "dns", value = "localhost" }
                }
            },
            new Uri("http://localhost/new-order"),
            nonce,
            kid: new Uri("http://localhost/account/does-not-exist"));

        await SendAcmeRequestAsync(HttpMethod.Post, "/new-order", signedPayload).ConfigureAwait(false);
    }

    [When("the client uses an unsupported JWS signature algorithm")]
    public async Task WhenTheClientUsesAnUnsupportedJwsSignatureAlgorithm()
    {
        await SendJwkSignedRequestAsync(
            AcmeState.Key ??= KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha256),
            "/new-account",
            new
            {
                contact = new[] { "mailto:test@example.com" },
                termsOfServiceAgreed = true
            },
            algOverride: "HS256").ConfigureAwait(false);
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

    [When("the client creates a new order")]
    public async Task WhenTheClientCreatesANewOrder()
    {
        await CreatePendingOrderAsync().ConfigureAwait(false);
    }

    [When("the client fetches an order")]
    public async Task WhenTheClientFetchesAnOrder()
    {
        AcmeState.ExpectedNotBefore = DateTimeOffset.UtcNow.AddHours(6).ToUniversalTime();
        AcmeState.ExpectedNotAfter = AcmeState.ExpectedNotBefore.Value.AddDays(2);

        await CreatePendingOrderAsync(notBefore: AcmeState.ExpectedNotBefore, notAfter: AcmeState.ExpectedNotAfter)
            .ConfigureAwait(false);
    }

    [When("the client submits a new-order request without identifiers")]
    public async Task WhenTheClientSubmitsANewOrderRequestWithoutIdentifiers()
    {
        await EnsureAccountCreatedAsync().ConfigureAwait(false);
        await SendKidSignedRequestAsync(
            "/new-order",
            new
            {
                identifiers = Array.Empty<object>()
            }).ConfigureAwait(false);
    }

    [When("not all authorizations for an order are valid")]
    public async Task WhenNotAllAuthorizationsForAnOrderAreValid()
    {
        await CreatePendingOrderAsync().ConfigureAwait(false);
        await FinalizeCurrentOrderAsync(CreateCsrBase64(AcmeState.ExpectedIdentifiers!)).ConfigureAwait(false);
    }

    [When("the client finalizes a ready order")]
    public async Task WhenTheClientFinalizesAReadyOrder()
    {
        await CreateReadyOrderAsync().ConfigureAwait(false);
        await FinalizeCurrentOrderAsync(CreateCsrBase64(AcmeState.ExpectedIdentifiers!)).ConfigureAwait(false);
    }

    [When("the client finalizes a ready order with a CSR that has no subjectAltName extension")]
    public async Task WhenTheClientFinalizesAReadyOrderWithACsrThatHasNoSubjectAltNameExtension()
    {
        await CreateReadyOrderAsync().ConfigureAwait(false);
        await FinalizeCurrentOrderAsync(CreateCsrBase64(Array.Empty<string>(), includeSubjectAlternativeNames: false))
            .ConfigureAwait(false);
    }

    [When("the client finalizes a ready order with a CSR whose identifiers do not exactly match the order")]
    public async Task WhenTheClientFinalizesAReadyOrderWithACsrWhoseIdentifiersDoNotExactlyMatchTheOrder()
    {
        await CreateReadyOrderAsync().ConfigureAwait(false);
        await FinalizeCurrentOrderAsync(CreateCsrBase64(["localhost", "extra.local"])).ConfigureAwait(false);
    }

    [When("the ACME server accepts a CSR for a ready order")]
    public async Task WhenTheAcmeServerAcceptsACsrForAReadyOrder()
    {
        await CreateReadyOrderAsync().ConfigureAwait(false);
        await FinalizeCurrentOrderAsync(CreateCsrBase64(AcmeState.ExpectedIdentifiers!)).ConfigureAwait(false);
    }

    [When("certificate issuance fails after finalization")]
    public async Task WhenCertificateIssuanceFailsAfterFinalization()
    {
        await CreateReadyOrderAsync().ConfigureAwait(false);
        GetRequiredService<TestAcmeIssuer>().FailNextIssuance = true;
        await FinalizeCurrentOrderAsync(CreateCsrBase64(AcmeState.ExpectedIdentifiers!)).ConfigureAwait(false);
    }

    [When("the client finalizes a ready order with accepted notBefore and notAfter values")]
    public async Task WhenTheClientFinalizesAReadyOrderWithAcceptedNotBeforeAndNotAfterValues()
    {
        AcmeState.ExpectedNotBefore = DateTimeOffset.UtcNow.AddHours(8).ToUniversalTime();
        AcmeState.ExpectedNotAfter = AcmeState.ExpectedNotBefore.Value.AddDays(5);

        await CreateReadyOrderAsync(notBefore: AcmeState.ExpectedNotBefore, notAfter: AcmeState.ExpectedNotAfter)
            .ConfigureAwait(false);
        await FinalizeCurrentOrderAsync(CreateCsrBase64(AcmeState.ExpectedIdentifiers!)).ConfigureAwait(false);
        await DownloadCurrentCertificateAsync().ConfigureAwait(false);
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

    [Scope(Tag = "acme")]
    [Then("the request content type MUST be \"(.+)\"")]
    public void ThenTheAcmeRequestContentTypeMustBe(string mediaType)
    {
        Assert.Equal(mediaType, AcmeState.RequestContentType);
    }

    [Then("the request body MUST be a flattened JWS JSON serialization")]
    public void ThenTheRequestBodyMustBeAFlattenedJwsJsonSerialization()
    {
        using var requestDocument = ParseRequestDocument();
        Assert.Equal(JsonValueKind.Object, requestDocument.RootElement.ValueKind);
        Assert.True(requestDocument.RootElement.TryGetProperty("protected", out _));
        Assert.True(requestDocument.RootElement.TryGetProperty("payload", out _));
        Assert.True(requestDocument.RootElement.TryGetProperty("signature", out _));
        Assert.False(requestDocument.RootElement.TryGetProperty("signatures", out _));
    }

    [Then("the JWS object MUST contain exactly one signature")]
    public void ThenTheJwsObjectMustContainExactlyOneSignature()
    {
        using var requestDocument = ParseRequestDocument();
        Assert.True(requestDocument.RootElement.TryGetProperty("signature", out var signatureProperty));
        Assert.False(string.IsNullOrWhiteSpace(signatureProperty.GetString()));
        Assert.False(requestDocument.RootElement.TryGetProperty("signatures", out _));
    }

    [Then("the JWS protected header MUST contain the \"(.+)\" member")]
    [Then("the JWS protected header MUST contain a \"(.+)\" member")]
    public void ThenTheJwsProtectedHeaderMustContainTheMember(string memberName)
    {
        using var protectedHeader = ParseProtectedHeader();
        Assert.True(protectedHeader.RootElement.TryGetProperty(memberName, out _),
            $"Expected protected header to contain '{memberName}'.");
    }

    [Then("the JWS protected header MUST contain either \"jwk\" or \"kid\"")]
    public void ThenTheJwsProtectedHeaderMustContainEitherJwkOrKid()
    {
        using var protectedHeader = ParseProtectedHeader();
        var hasJwk = protectedHeader.RootElement.TryGetProperty("jwk", out _);
        var hasKid = protectedHeader.RootElement.TryGetProperty("kid", out _);
        Assert.True(hasJwk || hasKid);
    }

    [Then("the JWS protected header MUST NOT contain a \"(.+)\" member")]
    public void ThenTheJwsProtectedHeaderMustNotContainAMember(string memberName)
    {
        using var protectedHeader = ParseProtectedHeader();
        Assert.False(protectedHeader.RootElement.TryGetProperty(memberName, out _),
            $"Expected protected header not to contain '{memberName}'.");
    }

    [Then("the JWS protected header MUST NOT contain both \"jwk\" and \"kid\"")]
    public void ThenTheJwsProtectedHeaderMustNotContainBothJwkAndKid()
    {
        using var protectedHeader = ParseProtectedHeader();
        var hasJwk = protectedHeader.RootElement.TryGetProperty("jwk", out _);
        var hasKid = protectedHeader.RootElement.TryGetProperty("kid", out _);
        Assert.False(hasJwk && hasKid);
    }

    [Then("the ACME server MUST reject the request")]
    public void ThenTheAcmeServerMustRejectTheRequest()
    {
        Assert.NotNull(AcmeState.Response);
        Assert.True((int)AcmeState.Response!.StatusCode >= 400,
            $"Expected an ACME error response but got {(int)AcmeState.Response.StatusCode}.");
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

    [Then("the response MUST include the order URL in the Location header")]
    public void ThenTheResponseMustIncludeTheOrderUrlInTheLocationHeader()
    {
        Assert.NotNull(AcmeState.Response?.Headers.Location);
        Assert.True(AcmeState.Response!.Headers.Location!.IsAbsoluteUri);
        Assert.Equal(Uri.UriSchemeHttps, AcmeState.Response.Headers.Location.Scheme);
        AcmeState.OrderUrl = AcmeState.Response.Headers.Location;
    }

    [Then("the response body MUST be an order object")]
    [Then("the response MUST return the order object")]
    [Then("the ACME server MUST return the current order object")]
    public void ThenTheResponseMustBeAnOrderObject()
    {
        var order = AcmeState.OrderResponse ?? DeserializeOrderResponse();
        Assert.NotNull(order.Status);
        Assert.NotNull(order.Identifiers);
        Assert.NotNull(order.Authorizations);
        AcmeState.OrderResponse = order;
    }

    [Then("the order object MUST contain every requested identifier")]
    public void ThenTheOrderObjectMustContainEveryRequestedIdentifier()
    {
        var order = AcmeState.OrderResponse ?? DeserializeOrderResponse();
        Assert.NotNull(AcmeState.ExpectedIdentifiers);
        var identifiers = order.Identifiers!.Select(i => i.Value!.Trim().ToLowerInvariant()).OrderBy(static x => x).ToArray();
        var expected = AcmeState.ExpectedIdentifiers!.Select(i => i.Trim().ToLowerInvariant()).OrderBy(static x => x).ToArray();
        Assert.Equal(expected, identifiers);
    }

    [Then("the order object MUST contain one authorization URL per identifier")]
    public void ThenTheOrderObjectMustContainOneAuthorizationUrlPerIdentifier()
    {
        var order = AcmeState.OrderResponse ?? DeserializeOrderResponse();
        Assert.NotNull(order.Authorizations);
        Assert.NotNull(AcmeState.ExpectedIdentifiers);
        Assert.Equal(AcmeState.ExpectedIdentifiers!.Count, order.Authorizations!.Count);
        Assert.All(order.Authorizations, authorizationUrl =>
        {
            Assert.True(authorizationUrl.IsAbsoluteUri);
            Assert.Equal(Uri.UriSchemeHttps, authorizationUrl.Scheme);
        });
    }

    [Then("the order object MUST contain a finalize URL")]
    public void ThenTheOrderObjectMustContainAFinalizeUrl()
    {
        var order = AcmeState.OrderResponse ?? DeserializeOrderResponse();
        Assert.NotNull(order.Finalize);
        Assert.True(order.Finalize!.IsAbsoluteUri);
        Assert.Equal(Uri.UriSchemeHttps, order.Finalize.Scheme);
    }

    [Then("the order object status MUST initially be \"pending\"")]
    public void ThenTheOrderObjectStatusMustInitiallyBePending()
    {
        Assert.Equal(AcmeOrderStatus.Pending, (AcmeState.OrderResponse ?? DeserializeOrderResponse()).Status);
    }

    [Then("the order object MUST contain its status")]
    public void ThenTheOrderObjectMustContainItsStatus()
    {
        Assert.NotNull((AcmeState.OrderResponse ?? DeserializeOrderResponse()).Status);
    }

    [Then("the order object SHOULD contain an expires timestamp while it is pending ready or processing")]
    public void ThenTheOrderObjectShouldContainAnExpiresTimestampWhileItIsPendingReadyOrProcessing()
    {
        var order = AcmeState.OrderResponse ?? DeserializeOrderResponse();
        Assert.True(order.Status is AcmeOrderStatus.Pending or AcmeOrderStatus.Ready or AcmeOrderStatus.Processing);
        Assert.NotNull(order.Expires);
    }

    [Then("the order object MUST reflect any accepted notBefore value")]
    public void ThenTheOrderObjectMustReflectAnyAcceptedNotBeforeValue()
    {
        if (!AcmeState.ExpectedNotBefore.HasValue)
        {
            return;
        }

        var order = AcmeState.OrderResponse ?? DeserializeOrderResponse();
        Assert.NotNull(order.NotBefore);
        Assert.Equal(AcmeState.ExpectedNotBefore.Value.ToUniversalTime(), order.NotBefore!.Value.ToUniversalTime());
    }

    [Then("the order object MUST reflect any accepted notAfter value")]
    public void ThenTheOrderObjectMustReflectAnyAcceptedNotAfterValue()
    {
        if (!AcmeState.ExpectedNotAfter.HasValue)
        {
            return;
        }

        var order = AcmeState.OrderResponse ?? DeserializeOrderResponse();
        Assert.NotNull(order.NotAfter);
        Assert.Equal(AcmeState.ExpectedNotAfter.Value.ToUniversalTime(), order.NotAfter!.Value.ToUniversalTime());
    }

    [Then("the certificate URL MUST be absent until the order becomes \"valid\"")]
    public void ThenTheCertificateUrlMustBeAbsentUntilTheOrderBecomesValid()
    {
        var order = AcmeState.OrderResponse ?? DeserializeOrderResponse();
        if (order.Status == AcmeOrderStatus.Valid)
        {
            Assert.NotNull(order.Certificate);
            return;
        }

        Assert.Null(order.Certificate);
    }

    [Then("if the order becomes \"invalid\" the order object MUST include an error object")]
    [Then("the order object MUST contain an error object explaining the failure")]
    public void ThenTheOrderObjectMustContainAnErrorObjectExplainingTheFailure()
    {
        var order = AcmeState.OrderResponse ?? DeserializeOrderResponse();
        if (order.Status != AcmeOrderStatus.Invalid)
        {
            return;
        }

        Assert.NotNull(order.Error);
        Assert.False(string.IsNullOrWhiteSpace(order.Error!.Detail));
    }

    [Then("the order MUST remain \"pending\" or become \"invalid\"")]
    public async Task ThenTheOrderMustRemainPendingOrBecomeInvalid()
    {
        var order = await GetRequiredService<OpenCertServer.Acme.Abstractions.Storage.IStoreOrders>()
            .LoadOrder(GetOrderId(), CancellationToken.None)
            .ConfigureAwait(false);

        Assert.NotNull(order);
        Assert.True(
            order!.Status is CertesSlim.Acme.Resource.OrderStatus.Pending or CertesSlim.Acme.Resource.OrderStatus.Invalid,
            $"Expected the order to remain pending or become invalid, but it was {order.Status}.");
    }

    [Then("the ACME server MUST NOT finalize the order")]
    public void ThenTheAcmeServerMustNotFinalizeTheOrder()
    {
        Assert.Equal(HttpStatusCode.Conflict, AcmeState.Response?.StatusCode);
    }

    [Then("the request body MUST contain a base64url-encoded CSR")]
    public void ThenTheRequestBodyMustContainABase64UrlEncodedCsr()
    {
        using var payloadDocument = ParseDecodedPayloadDocument();
        Assert.True(payloadDocument.RootElement.TryGetProperty("csr", out var csrProperty));
        var csr = csrProperty.GetString();
        Assert.False(string.IsNullOrWhiteSpace(csr));
        _ = Base64UrlEncoder.DecodeBytes(csr);
        AcmeState.FinalizeRequestCsr = csr;
    }

    [Then("the ACME server MUST verify that the identifiers requested in the CSR match the order's identifiers")]
    public void ThenTheAcmeServerMustVerifyThatTheIdentifiersRequestedInTheCsrMatchTheOrdersIdentifiers()
    {
        Assert.False(string.IsNullOrWhiteSpace(AcmeState.FinalizeRequestCsr));
        var request = LoadCertificateRequest(AcmeState.FinalizeRequestCsr!);
        var csrNames = request.CertificateExtensions
            .OfType<X509SubjectAlternativeNameExtension>()
            .SelectMany(ext => ext.EnumerateDnsNames())
            .Select(name => name.Trim().ToLowerInvariant())
            .OrderBy(static x => x)
            .ToArray();
        var expected = AcmeState.ExpectedIdentifiers!
            .Select(name => name.Trim().ToLowerInvariant())
            .OrderBy(static x => x)
            .ToArray();
        Assert.Equal(expected, csrNames);
    }

    [Then("the ACME server MUST reject a malformed or unacceptable CSR")]
    public async Task ThenTheAcmeServerMustRejectAMalformedOrUnacceptableCsr()
    {
        await CreateReadyOrderAsync().ConfigureAwait(false);
        await FinalizeCurrentOrderAsync("not-a-valid-csr").ConfigureAwait(false);
        Assert.Equal(HttpStatusCode.BadRequest, AcmeState.Response?.StatusCode);
    }

    [Then("the order status MUST become either \"processing\" or \"valid\"")]
    public void ThenTheOrderStatusMustBecomeEitherProcessingOrValid()
    {
        var status = (AcmeState.OrderResponse ?? DeserializeOrderResponse()).Status;
        Assert.True(
            status is AcmeOrderStatus.Processing or AcmeOrderStatus.Valid,
            $"Expected the order status to be processing or valid, but it was {status}.");
    }

    [Then("if issuance is not complete the ACME server MAY include a Retry-After header")]
    public void ThenIfIssuanceIsNotCompleteTheAcmeServerMayIncludeARetryAfterHeader()
    {
        if ((AcmeState.OrderResponse ?? DeserializeOrderResponse()).Status != AcmeOrderStatus.Processing)
        {
            return;
        }

        Assert.True(AcmeState.Response?.Headers.TryGetValues("Retry-After", out _) != false);
    }

    [Then("the ACME server MUST mark the order \"invalid\"")]
    public void ThenTheAcmeServerMustMarkTheOrderInvalid()
    {
        Assert.Equal(AcmeOrderStatus.Invalid, (AcmeState.OrderResponse ?? DeserializeOrderResponse()).Status);
    }

    [Then("the issued certificate MUST honor the accepted notBefore value")]
    public void ThenTheIssuedCertificateMustHonorTheAcceptedNotBeforeValue()
    {
        Assert.NotNull(AcmeState.IssuedCertificateChain);
        Assert.NotNull(AcmeState.ExpectedNotBefore);
        Assert.Equal(
            TruncateToSecond(AcmeState.ExpectedNotBefore!.Value.ToUniversalTime().UtcDateTime),
            TruncateToSecond(AcmeState.IssuedCertificateChain!.Certificate.NotBefore.ToUniversalTime()));
    }

    [Then("the issued certificate MUST honor the accepted notAfter value")]
    public void ThenTheIssuedCertificateMustHonorTheAcceptedNotAfterValue()
    {
        Assert.NotNull(AcmeState.IssuedCertificateChain);
        Assert.NotNull(AcmeState.ExpectedNotAfter);
        Assert.Equal(
            TruncateToSecond(AcmeState.ExpectedNotAfter!.Value.ToUniversalTime().UtcDateTime),
            TruncateToSecond(AcmeState.IssuedCertificateChain!.Certificate.NotAfter.ToUniversalTime()));
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

        StoreExchange(exchange);

        if (AcmeState.Response?.StatusCode != HttpStatusCode.Created)
        {
            var body = Encoding.UTF8.GetString(AcmeState.ResponseBytes ?? []);
            throw new Xunit.Sdk.XunitException(
                $"Expected 201 Created from /new-account but got {(int?)AcmeState.Response?.StatusCode} with body: {body}");
        }

        AcmeState.Context = CreateAcmeContext(_server.CreateClient(), AcmeState.Key!);
        AcmeState.AccountContext = await AcmeState.Context.Account().ConfigureAwait(false);
    }

    private async Task CaptureNewOrderRequestAsync()
    {
        await EnsureAccountCreatedAsync().ConfigureAwait(false);

        using var captureHandler = new AcmeCaptureHandler(_server.CreateHandler());
        var capturedContext = CreateAcmeContext(captureHandler, AcmeState.Key!);

        _ = await capturedContext.NewOrder(null, ["localhost"]).ConfigureAwait(false);

        var exchange = captureHandler.Exchanges.LastOrDefault(x =>
            x.Method == HttpMethod.Post &&
            string.Equals(x.RequestUri.AbsolutePath, "/new-order", StringComparison.Ordinal));

        Assert.NotNull(exchange);
        StoreExchange(exchange);
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
        => await SendJwkSignedRequestAsync(key, "/new-account", payload).ConfigureAwait(false);

    [UnconditionalSuppressMessage("Trimming", "IL2026",
        Justification = "These conformance tests build small JSON payloads at runtime in the test host only.")]
    [UnconditionalSuppressMessage("AOT", "IL3050",
        Justification = "These conformance tests run in the regular test runtime and do not target AOT publishing.")]
    private async Task SendJwkSignedRequestAsync<TPayload>(
        IKey key,
        string path,
        TPayload payload,
        string contentType = "application/jose+json",
        string? algOverride = null,
        Uri? protectedUrl = null)
    {
        var requestUrl = new Uri(new Uri("http://localhost"), path);
        var nonce = await GetFreshNonceAsync().ConfigureAwait(false);
        var signedPayload = CreateSignedPayload(key, payload, protectedUrl ?? requestUrl, nonce, algOverride: algOverride);
        await SendAcmeRequestAsync(HttpMethod.Post, requestUrl.ToString(), signedPayload, contentType).ConfigureAwait(false);
    }

    [UnconditionalSuppressMessage("Trimming", "IL2026",
        Justification = "These conformance tests build small JSON payloads at runtime in the test host only.")]
    [UnconditionalSuppressMessage("AOT", "IL3050",
        Justification = "These conformance tests run in the normal test runtime and do not target AOT publishing.")]
    private async Task SendAcmeRequestAsync(HttpMethod method, string path, JwsPayload? payload = null)
    {
        await SendRawAcmeRequestAsync(method, path,
            payload == null ? null : JsonSerializer.Serialize(payload), "application/jose+json");
    }

    [UnconditionalSuppressMessage("Trimming", "IL2026",
        Justification = "These conformance tests serialize small ACME payloads in the normal test runtime only.")]
    [UnconditionalSuppressMessage("AOT", "IL3050",
        Justification = "These conformance tests run in the standard test runtime and do not target AOT publishing.")]
    private async Task SendAcmeRequestAsync(HttpMethod method, string path, JwsPayload payload, string contentType)
    {
        await SendRawAcmeRequestAsync(method, path, JsonSerializer.Serialize(payload), contentType);
    }

    private JsonDocument ParseProblemDocument()
    {
        Assert.NotNull(AcmeState.ResponseBytes);
        return JsonDocument.Parse(AcmeState.ResponseBytes!);
    }

    private JsonDocument ParseRequestDocument()
    {
        Assert.False(string.IsNullOrWhiteSpace(AcmeState.RawRequestBody));
        return JsonDocument.Parse(AcmeState.RawRequestBody!);
    }

    private JsonDocument ParseProtectedHeader()
    {
        Assert.NotNull(AcmeState.SignedPayload);
        return JsonDocument.Parse(Base64UrlEncoder.Decode(AcmeState.SignedPayload!.Protected));
    }

    private JsonDocument ParseDecodedPayloadDocument()
    {
        Assert.NotNull(AcmeState.SignedPayload);
        return JsonDocument.Parse(Base64UrlEncoder.Decode(AcmeState.SignedPayload!.Payload));
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
        Justification = "These conformance tests deserialize small ACME order payloads in the normal test runtime only.")]
    [UnconditionalSuppressMessage("AOT", "IL3050",
        Justification = "These conformance tests run in the standard test runtime and do not target AOT publishing.")]
    private AcmeOrder DeserializeOrderResponse()
    {
        Assert.NotNull(AcmeState.ResponseBytes);
        return JsonSerializer.Deserialize<AcmeOrder>(AcmeState.ResponseBytes!, AcmeJsonOptions)
               ?? throw new Xunit.Sdk.XunitException("Could not deserialize ACME order response.");
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

    private async Task CreatePendingOrderAsync(
        IList<string>? identifiers = null,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null)
    {
        await EnsureAccountCreatedAsync().ConfigureAwait(false);

        identifiers ??= ["localhost"];
        AcmeState.ExpectedIdentifiers = identifiers.ToList();
        AcmeState.ExpectedNotBefore = notBefore;
        AcmeState.ExpectedNotAfter = notAfter;

        using var captureHandler = new AcmeCaptureHandler(_server.CreateHandler());
        var capturedContext = CreateAcmeContext(captureHandler, AcmeState.Key!);

        var orderContext = await capturedContext.NewOrder(null, identifiers, notBefore, notAfter).ConfigureAwait(false);
        var exchange = captureHandler.Exchanges.LastOrDefault(x =>
            x.Method == HttpMethod.Post &&
            string.Equals(x.RequestUri.AbsolutePath, "/new-order", StringComparison.Ordinal));

        Assert.NotNull(exchange);
        StoreExchange(exchange);

        AcmeState.OrderUrl = AcmeState.Response?.Headers.Location ?? orderContext.Location;
        Assert.NotNull(AcmeState.OrderUrl);

        AcmeState.OrderContext = AcmeState.Context!.Order(AcmeState.OrderUrl!);
        AcmeState.OrderResponse = DeserializeOrderResponse();
    }

    private async Task CreateReadyOrderAsync(
        IList<string>? identifiers = null,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null)
    {
        await CreatePendingOrderAsync(identifiers, notBefore, notAfter).ConfigureAwait(false);

        var orderStore = GetRequiredService<OpenCertServer.Acme.Abstractions.Storage.IStoreOrders>();
        var orderId = GetOrderId();
        var order = await orderStore.LoadOrder(orderId, CancellationToken.None).ConfigureAwait(false)
            ?? throw new InvalidOperationException("Could not load the pending order from the store.");

        foreach (var authorization in order.Authorizations)
        {
            authorization.Status = CertesSlim.Acme.Resource.AuthorizationStatus.Valid;
            foreach (var challenge in authorization.Challenges)
            {
                challenge.Status = CertesSlim.Acme.Resource.ChallengeStatus.Valid;
                challenge.Validated = DateTimeOffset.UtcNow;
            }
        }

        order.SetStatusFromAuthorizations();
        await orderStore.SaveOrder(order, CancellationToken.None).ConfigureAwait(false);
        AcmeState.OrderResponse = new AcmeOrder
        {
            Status = AcmeOrderStatus.Ready,
            Finalize = GetFinalizeUrl(),
            Identifiers = AcmeState.ExpectedIdentifiers!
                .Select(identifier => new CertesSlim.Acme.Resource.Identifier
                {
                    Type = CertesSlim.Acme.Resource.IdentifierType.Dns,
                    Value = identifier
                })
                .ToList(),
            Authorizations = order.Authorizations
                .Select(auth => new Uri($"https://localhost/order/{order.OrderId}/auth/{auth.AuthorizationId}"))
                .ToList()
        };
    }

    private async Task FinalizeCurrentOrderAsync(string csr)
    {
        var finalizeUrl = AcmeState.OrderResponse?.Finalize ?? GetFinalizeUrl();
        AcmeState.FinalizeRequestCsr = csr;

        var signedPayload = CreateSignedPayload(
            AcmeState.Key!,
            new { csr },
            finalizeUrl,
            await GetFreshNonceAsync().ConfigureAwait(false),
            kid: GetAccountLocation());

        StoreSignedRequest(HttpMethod.Post, signedPayload, "application/jose+json");

        var orderStore = GetRequiredService<OpenCertServer.Acme.Abstractions.Storage.IStoreOrders>();
        var storedOrder = await orderStore.LoadOrder(GetOrderId(), CancellationToken.None).ConfigureAwait(false)
            ?? throw new InvalidOperationException("Could not load the current ACME order from the store.");
        var account = await GetRequiredService<OpenCertServer.Acme.Abstractions.Services.IAccountService>()
            .LoadAccount(storedOrder.AccountId, CancellationToken.None)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException("Could not load the ACME account for the current order.");

        try
        {
            var updatedOrder = await GetRequiredService<OpenCertServer.Acme.Abstractions.Services.IOrderService>()
                .ProcessCsr(account, storedOrder.OrderId, csr, CancellationToken.None)
                .ConfigureAwait(false);

            AcmeState.OrderResponse = MapOrder(updatedOrder);
            SetJsonResponse(HttpStatusCode.OK, AcmeState.OrderResponse);
        }
        catch (OpenCertServer.Acme.Abstractions.Exceptions.BadCsrException ex)
        {
            SetProblemResponse(HttpStatusCode.BadRequest, "badCSR", ex.Message);
        }
        catch (OpenCertServer.Acme.Abstractions.Exceptions.ConflictRequestException ex)
        {
            SetProblemResponse(HttpStatusCode.Conflict, "orderNotReady", ex.Message);
        }
    }

    private async Task FetchCurrentOrderAsync()
    {
        Assert.NotNull(AcmeState.OrderUrl);

        var signedPayload = CreateSignedPayload(
            AcmeState.Key!,
            (object?)null,
            AcmeState.OrderUrl!,
            await GetFreshNonceAsync().ConfigureAwait(false),
            kid: GetAccountLocation());

        await SendAcmeRequestAsync(HttpMethod.Post, AcmeState.OrderUrl!.ToString(), signedPayload).ConfigureAwait(false);
        AcmeState.OrderResponse = DeserializeOrderResponse();
    }

    private Uri GetFinalizeUrl()
        => new($"https://localhost/order/{GetOrderId()}/finalize");

    private async Task DownloadCurrentCertificateAsync()
    {
        var storedOrder = await GetRequiredService<OpenCertServer.Acme.Abstractions.Storage.IStoreOrders>()
            .LoadOrder(GetOrderId(), CancellationToken.None)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException("Could not load the current ACME order from the store.");
        var account = await GetRequiredService<OpenCertServer.Acme.Abstractions.Services.IAccountService>()
            .LoadAccount(storedOrder.AccountId, CancellationToken.None)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException("Could not load the ACME account for the current order.");

        var certificateBytes = await GetRequiredService<OpenCertServer.Acme.Abstractions.Services.IOrderService>()
            .GetCertificate(account, storedOrder.OrderId, CancellationToken.None)
            .ConfigureAwait(false);

        AcmeState.Response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(certificateBytes)
        };
        AcmeState.Response.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/pem-certificate-chain");
        AcmeState.ResponseBytes = certificateBytes;
        AcmeState.IssuedCertificateChain = new AcmeCertificateChain(Encoding.UTF8.GetString(certificateBytes));
    }

    [UnconditionalSuppressMessage("Trimming", "IL2026",
        Justification = "These conformance tests serialize small ACME payloads in the normal test runtime only.")]
    [UnconditionalSuppressMessage("AOT", "IL3050",
        Justification = "These conformance tests run in the standard test runtime and do not target AOT publishing.")]
    private void StoreSignedRequest(HttpMethod method, JwsPayload signedPayload, string contentType)
    {
        AcmeState.SignedPayload = signedPayload;
        AcmeState.RawRequestBody = JsonSerializer.Serialize(signedPayload);
        AcmeState.RequestContentType = contentType;

        using var protectedHeader = JsonDocument.Parse(Base64UrlEncoder.Decode(signedPayload.Protected));
        AcmeState.RequestNonce = protectedHeader.RootElement.TryGetProperty("nonce", out var nonceProperty)
            ? nonceProperty.GetString()
            : null;
    }

    [UnconditionalSuppressMessage("Trimming", "IL2026",
        Justification = "These conformance tests serialize small ACME payloads in the normal test runtime only.")]
    [UnconditionalSuppressMessage("AOT", "IL3050",
        Justification = "These conformance tests run in the standard test runtime and do not target AOT publishing.")]
    private void SetJsonResponse<T>(HttpStatusCode statusCode, T resource)
    {
        AcmeState.ResponseBytes = JsonSerializer.SerializeToUtf8Bytes(resource, AcmeJsonOptions);
        AcmeState.Response = new HttpResponseMessage(statusCode)
        {
            Content = new ByteArrayContent(AcmeState.ResponseBytes)
        };
        AcmeState.Response.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
    }

    [UnconditionalSuppressMessage("Trimming", "IL2026",
        Justification = "These conformance tests serialize ACME problem payloads in the normal test runtime only.")]
    [UnconditionalSuppressMessage("AOT", "IL3050",
        Justification = "These conformance tests run in the standard test runtime and do not target AOT publishing.")]
    private void SetProblemResponse(HttpStatusCode statusCode, string errorType, string detail)
    {
        var problem = new
        {
            type = $"urn:ietf:params:acme:error:{errorType}",
            detail,
            status = (int)statusCode
        };

        AcmeState.ResponseBytes = JsonSerializer.SerializeToUtf8Bytes(problem, AcmeJsonOptions);
        AcmeState.Response = new HttpResponseMessage(statusCode)
        {
            Content = new ByteArrayContent(AcmeState.ResponseBytes)
        };
        AcmeState.Response.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/problem+json");
    }

    private AcmeOrder MapOrder(OpenCertServer.Acme.Abstractions.Model.Order order)
    {
        var orderId = order.OrderId;
        return new AcmeOrder
        {
            Status = order.Status,
            Expires = order.Expires,
            NotBefore = order.NotBefore,
            NotAfter = order.NotAfter,
            Identifiers = order.Identifiers.Select(identifier => new CertesSlim.Acme.Resource.Identifier
            {
                Type = CertesSlim.Acme.Resource.IdentifierType.Dns,
                Value = identifier.Value
            }).ToList(),
            Authorizations = order.Authorizations
                .Select(auth => new Uri($"https://localhost/order/{orderId}/auth/{auth.AuthorizationId}"))
                .ToList(),
            Finalize = new Uri($"https://localhost/order/{orderId}/finalize"),
            Certificate = order.Status == AcmeOrderStatus.Valid
                ? new Uri($"https://localhost/order/{orderId}/certificate")
                : null,
            Error = order.Error == null
                ? null
                : new CertesSlim.Acme.Resource.ErrorDetails
                {
                    Title = order.Error.Type,
                    Detail = order.Error.Detail,
                    Status = HttpStatusCode.BadRequest
                }
        };
    }

    private async Task SendKidSignedRequestAsync<TPayload>(string path, TPayload payload)
    {
        await EnsureAccountCreatedAsync().ConfigureAwait(false);

        var requestUrl = new Uri(new Uri("http://localhost"), path);
        var signedPayload = CreateSignedPayload(
            AcmeState.Key!,
            payload,
            requestUrl,
            await GetFreshNonceAsync().ConfigureAwait(false),
            kid: GetAccountLocation());

        await SendAcmeRequestAsync(HttpMethod.Post, requestUrl.ToString(), signedPayload).ConfigureAwait(false);
    }

    private static string CreateCsrBase64(IList<string> dnsNames, bool includeSubjectAlternativeNames = true)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            new X500DistinguishedName("CN=localhost"),
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);

        if (includeSubjectAlternativeNames)
        {
            var subjectAlternativeNames = new SubjectAlternativeNameBuilder();
            foreach (var dnsName in dnsNames)
            {
                subjectAlternativeNames.AddDnsName(dnsName);
            }

            if (dnsNames.Count > 0)
            {
                request.CertificateExtensions.Add(subjectAlternativeNames.Build());
            }
        }

        return Base64UrlEncoder.Encode(request.CreateSigningRequest());
    }

    private static CertificateRequest LoadCertificateRequest(string csr)
    {
        var csrBytes = Base64UrlEncoder.DecodeBytes(csr);
        return CertificateRequest.LoadSigningRequest(
            csrBytes,
            HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions,
            RSASignaturePadding.Pss);
    }

    private string GetOrderId()
    {
        Assert.NotNull(AcmeState.OrderUrl);
        return AcmeState.OrderUrl!.Segments.Last().TrimEnd('/');
    }

    private Uri GetAccountLocation()
        => AcmeState.AccountContext?.Location ?? AcmeState.AccountUrl ?? throw new InvalidOperationException("No ACME account location is available.");

    private static DateTime TruncateToSecond(DateTime value)
        => new(value.Ticks - (value.Ticks % TimeSpan.TicksPerSecond), value.Kind);

    private T GetRequiredService<T>() where T : notnull
        => _server.Services.GetRequiredService<T>();

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

    private async Task<string> GetFreshNonceAsync()
    {
        using var client = _server.CreateClient();
        client.BaseAddress = new Uri("http://localhost");

        var directoryUri = new Uri(client.BaseAddress, "/directory");
        var acmeHttpClient = new AcmeHttpClient(directoryUri, client);
        return await acmeHttpClient.ConsumeNonce().ConfigureAwait(false);
    }

    [UnconditionalSuppressMessage("Trimming", "IL2026",
        Justification = "These conformance tests build small JSON payloads at runtime in the test host only.")]
    [UnconditionalSuppressMessage("AOT", "IL3050",
        Justification = "These conformance tests run in the standard test runtime and do not target AOT publishing.")]
    private static JwsPayload CreateSignedPayload<TPayload>(
        IKey key,
        TPayload payload,
        Uri requestUrl,
        string nonce,
        Uri? kid = null,
        string? algOverride = null)
    {
        var alg = algOverride ?? ToJwsAlgorithm(key.Algorithm);
        object protectedHeader = kid == null
            ? new
            {
                alg,
                jwk = key.JsonWebKey,
                nonce,
                url = requestUrl
            }
            : new
            {
                alg,
                kid,
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
    private async Task SendRawAcmeRequestAsync(HttpMethod method, string path, string? requestBody, string? contentType = "application/jose+json")
    {
        using var client = _server.CreateClient();
        using var request = new HttpRequestMessage(method, path);
        if (requestBody != null)
        {
            request.Content = new StringContent(requestBody, Encoding.UTF8, contentType);
        }

        var response = await client.SendAsync(request);
        AcmeState.Response = response;
        AcmeState.ResponseBytes = await response.Content.ReadAsByteArrayAsync();
        AcmeState.RawRequestBody = requestBody;
        AcmeState.RequestContentType = request.Content?.Headers.ContentType?.MediaType;
        if (!string.IsNullOrWhiteSpace(requestBody))
        {
            using var requestDocument = JsonDocument.Parse(requestBody);
            if (requestDocument.RootElement.TryGetProperty("protected", out var protectedProperty) &&
                requestDocument.RootElement.TryGetProperty("payload", out var payloadProperty) &&
                requestDocument.RootElement.TryGetProperty("signature", out var signatureProperty))
            {
                AcmeState.SignedPayload = new JwsPayload
                {
                    Protected = protectedProperty.GetString(),
                    Payload = payloadProperty.GetString(),
                    Signature = signatureProperty.GetString()
                };
            }
        }
    }

    private void StoreExchange(AcmeExchange exchange)
    {
        AcmeState.Response = exchange.Response;
        AcmeState.ResponseBytes = exchange.ResponseBytes;
        AcmeState.RawRequestBody = exchange.RequestBody;
        AcmeState.RequestContentType = exchange.RequestContentType;
        using var requestDocument = JsonDocument.Parse(exchange.RequestBody);
        AcmeState.SignedPayload = new JwsPayload
        {
            Protected = requestDocument.RootElement.GetProperty("protected").GetString(),
            Payload = requestDocument.RootElement.GetProperty("payload").GetString(),
            Signature = requestDocument.RootElement.GetProperty("signature").GetString()
        };
        Assert.NotNull(AcmeState.SignedPayload);

        using var protectedHeader = JsonDocument.Parse(Base64UrlEncoder.Decode(AcmeState.SignedPayload!.Protected));
        AcmeState.RequestNonce = protectedHeader.RootElement.TryGetProperty("nonce", out var nonceProperty)
            ? nonceProperty.GetString()
            : null;
    }

    private sealed class AcmeConformanceState
    {
        public HttpResponseMessage? Response { get; set; }

        public byte[]? ResponseBytes { get; set; }

        public AcmeContext? Context { get; set; }

        public IAccountContext? AccountContext { get; set; }

        public IOrderContext? OrderContext { get; set; }

        public AcmeAccount? AccountResponse { get; set; }

        public AcmeOrder? OrderResponse { get; set; }

        public Uri? AccountUrl { get; set; }

        public Uri? OrderUrl { get; set; }

        public Uri? OrdersUrl { get; set; }

        public string? RequestContentType { get; set; }

        public IList<string>? ExpectedContacts { get; set; }

        public IList<string>? ExpectedIdentifiers { get; set; }

        public IList<Uri>? ExpectedOrderUrls { get; set; }

        public DateTimeOffset? ExpectedNotBefore { get; set; }

        public DateTimeOffset? ExpectedNotAfter { get; set; }

        public string? RequestNonce { get; set; }

        public string? FinalizeRequestCsr { get; set; }

        public string? RawRequestBody { get; set; }

        public JwsPayload? SignedPayload { get; set; }

        public IKey? Key { get; set; }

        public IKey? UnknownKey { get; set; }

        public AcmeCertificateChain? IssuedCertificateChain { get; set; }
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

            Exchanges.Add(new AcmeExchange(
                request.Method,
                request.RequestUri!,
                requestBody,
                request.Content?.Headers.ContentType?.MediaType,
                clonedResponse,
                responseBytes));

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
        string? RequestContentType,
        HttpResponseMessage Response,
        byte[] ResponseBytes);
}







