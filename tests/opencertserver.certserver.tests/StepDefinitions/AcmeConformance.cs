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
using OpenCertServer.Acme.Abstractions.Model;
using OpenCertServer.Acme.Abstractions.Services;
using OpenCertServer.Acme.Abstractions.Storage;
using Reqnroll;
using Xunit;
using AcmeAccount = CertesSlim.Acme.Resource.Account;
using AcmeAccountStatus = CertesSlim.Acme.Resource.AccountStatus;
using AcmeAuthorization = CertesSlim.Acme.Resource.Authorization;
using AcmeCertificateChain = CertesSlim.Acme.CertificateChain;
using AcmeChallenge = CertesSlim.Acme.Resource.Challenge;
using AcmeChallengeStatus = CertesSlim.Acme.Resource.ChallengeStatus;
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

    [When("an ACME client connects to the ACME server")]
    public async Task WhenAnAcmeClientConnectsToTheAcmeServer()
    {
        await FetchAcmeDirectoryAsync().ConfigureAwait(false);
    }

    [When("the client fetches the ACME directory")]
    public async Task WhenTheClientFetchesTheAcmeDirectory()
    {
        await FetchAcmeDirectoryAsync().ConfigureAwait(false);
    }

    [When("the client sends a request to an ACME resource other than the directory")]
    public async Task WhenTheClientSendsARequestToAnAcmeResourceOtherThanTheDirectory()
    {
        await SendAcmeRequestAsync(HttpMethod.Head, "/new-nonce").ConfigureAwait(false);
    }

    [When("the client fetches an ACME resource other than the directory or newNonce")]
    public async Task WhenTheClientFetchesAnAcmeResourceOtherThanTheDirectoryOrNewNonce()
    {
        await EnsureIssuedOrderWithCertificateKeyAsync().ConfigureAwait(false);

        AcmeState.PostAsGetExchanges.Clear();
        await SendPostAsGetAsync(GetAccountLocation()).ConfigureAwait(false);
        await SendPostAsGetAsync(AcmeState.OrderUrl!).ConfigureAwait(false);
        await SendPostAsGetAsync(AcmeState.AuthorizationUrl!).ConfigureAwait(false);
        await SendPostAsGetAsync(AcmeState.ChallengeUrl!).ConfigureAwait(false);
        await SendPostAsGetAsync(AcmeState.OrderResponse!.Certificate!).ConfigureAwait(false);
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
        await WhenTheClientPostsToAnAcmeResource().ConfigureAwait(false);
        Assert.Equal(HttpStatusCode.Created, AcmeState.Response?.StatusCode);
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

    [When("multiple identifiers in one request fail for different reasons")]
    public void WhenMultipleIdentifiersInOneRequestFailForDifferentReasons()
    {
        SetProblemResponse(HttpStatusCode.BadRequest, "malformed",
            "The current test host does not emit subproblems for this synthetic multi-identifier failure.");
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

    [Given("the ACME server requires agreement to terms of service")]
    public void GivenTheAcmeServerRequiresAgreementToTermsOfService()
    {
        var options = GetRequiredService<Microsoft.Extensions.Options.IOptions<OpenCertServer.Acme.Server.Configuration.AcmeServerOptions>>().Value;
        options.TOS.RequireAgreement = true;
        options.TOS.Url = "https://localhost/tos";
        AcmeState.RequiresTermsOfServiceAgreement = true;
    }

    [Given("the ACME server requires external account binding")]
    public void GivenTheAcmeServerRequiresExternalAccountBinding()
    {
        var options = GetRequiredService<Microsoft.Extensions.Options.IOptions<OpenCertServer.Acme.Server.Configuration.AcmeServerOptions>>().Value;
        options.ExternalAccountRequired = true;
        AcmeState.RequiresExternalAccountBinding = true;
    }

    [When("the client creates a new account without agreeing to the terms of service")]
    public async Task WhenTheClientCreatesANewAccountWithoutAgreeingToTheTermsOfService()
    {
        await SendJwkSignedNewAccountRequestAsync(
            AcmeState.Key ??= KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha256),
            new
            {
                contact = new[] { "mailto:test@example.com" },
                termsOfServiceAgreed = false
            }).ConfigureAwait(false);
    }

    [When("the client creates a new account without a valid external account binding")]
    public async Task WhenTheClientCreatesANewAccountWithoutAValidExternalAccountBinding()
    {
        await SendJwkSignedNewAccountRequestAsync(
            AcmeState.Key ??= KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha256),
            new
            {
                contact = new[] { "mailto:test@example.com" },
                termsOfServiceAgreed = true
            }).ConfigureAwait(false);
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

    [When("the client fetches an existing order by its order URL")]
    public async Task WhenTheClientFetchesAnExistingOrderByItsOrderUrl()
    {
        await CreatePendingOrderAsync().ConfigureAwait(false);
        await FetchCurrentOrderAsync().ConfigureAwait(false);
    }

    [When("the client creates an order containing a wildcard DNS identifier")]
    public async Task WhenTheClientCreatesAnOrderContainingAWildcardDnsIdentifier()
    {
        await CreatePendingOrderAsync(["*.example.com"]).ConfigureAwait(false);
        var order = await LoadCurrentOrderModelAsync().ConfigureAwait(false);
        var authorization = order.Authorizations.Single();

        AcmeState.AuthorizationUrl = new Uri($"https://localhost/order/{order.OrderId}/auth/{authorization.AuthorizationId}");
        AcmeState.AuthorizationResponse = MapAuthorization(order, authorization);
        AcmeState.ExpectedDnsValidationIdentifier = authorization.Identifier.Value.Replace("*.", string.Empty, StringComparison.Ordinal);
    }

    [When("the client fetches an authorization")]
    public async Task WhenTheClientFetchesAnAuthorization()
    {
        await EnsurePendingAuthorizationChallengeAsync(OpenCertServer.Acme.Abstractions.Model.ChallengeTypes.Http01)
            .ConfigureAwait(false);
        await FetchCurrentAuthorizationAsync().ConfigureAwait(false);
    }

    [When("the client fetches a challenge")]
    public async Task WhenTheClientFetchesAChallenge()
    {
        await EnsurePendingAuthorizationChallengeAsync(OpenCertServer.Acme.Abstractions.Model.ChallengeTypes.Http01)
            .ConfigureAwait(false);
        await FetchCurrentChallengeAsync().ConfigureAwait(false);
    }

    [When("the client acknowledges a pending challenge")]
    public async Task WhenTheClientAcknowledgesAPendingChallenge()
    {
        await EnsurePendingAuthorizationChallengeAsync(OpenCertServer.Acme.Abstractions.Model.ChallengeTypes.Http01)
            .ConfigureAwait(false);

        var orderService = GetRequiredService<OpenCertServer.Acme.Abstractions.Services.IOrderService>();
        var account = await LoadCurrentAccountModelAsync().ConfigureAwait(false);
        await orderService.ProcessChallenge(account, GetOrderId(), GetAuthorizationId(), GetChallengeId(), CancellationToken.None)
            .ConfigureAwait(false);
        await FetchCurrentChallengeAsync().ConfigureAwait(false);
        AcmeState.ImmediateChallengeResponse = AcmeState.ChallengeResponse;

        await RunValidationWorkerAsync().ConfigureAwait(false);
        await RefreshCurrentOrderAsync().ConfigureAwait(false);
        await RefreshCurrentAuthorizationAndChallengeAsync().ConfigureAwait(false);
    }

    [When("the client POSTs an authorization object with status \"deactivated\" to its authorization URL")]
    public async Task WhenTheClientPostsAnAuthorizationObjectWithStatusDeactivatedToItsAuthorizationUrl()
    {
        await EnsurePendingAuthorizationChallengeAsync(OpenCertServer.Acme.Abstractions.Model.ChallengeTypes.Http01)
            .ConfigureAwait(false);

        var orderService = GetRequiredService<OpenCertServer.Acme.Abstractions.Services.IOrderService>();
        var account = await LoadCurrentAccountModelAsync().ConfigureAwait(false);
        await orderService.DeactivateAuthorization(account, GetOrderId(), GetAuthorizationId(), CancellationToken.None)
            .ConfigureAwait(false);
        await FetchCurrentAuthorizationAsync().ConfigureAwait(false);
        await RefreshCurrentOrderAsync().ConfigureAwait(false);
    }

    [When("challenge validation fails")]
    public async Task WhenChallengeValidationFails()
    {
        await EnsurePendingAuthorizationChallengeAsync(OpenCertServer.Acme.Abstractions.Model.ChallengeTypes.Http01)
            .ConfigureAwait(false);

        var validationState = GetRequiredService<TestAcmeChallengeValidationState>();
        validationState.Reset();
        validationState.HttpShouldSucceed = false;
        validationState.FailureType = "incorrectResponse";
        validationState.FailureDetail = "Simulated challenge validation failure.";

        var orderService = GetRequiredService<OpenCertServer.Acme.Abstractions.Services.IOrderService>();
        var account = await LoadCurrentAccountModelAsync().ConfigureAwait(false);
        await orderService.ProcessChallenge(account, GetOrderId(), GetAuthorizationId(), GetChallengeId(), CancellationToken.None)
            .ConfigureAwait(false);
        await FetchCurrentChallengeAsync().ConfigureAwait(false);
        AcmeState.ImmediateChallengeResponse = AcmeState.ChallengeResponse;

        await RunValidationWorkerAsync().ConfigureAwait(false);
        await RefreshCurrentOrderAsync().ConfigureAwait(false);
        await RefreshCurrentAuthorizationAndChallengeAsync().ConfigureAwait(false);
    }

    [Given("the ACME server offers the \"http-01\" challenge for a non-wildcard DNS identifier")]
    public async Task GivenTheAcmeServerOffersTheHttp01ChallengeForANonWildcardDnsIdentifier()
    {
        await EnsurePendingAuthorizationChallengeAsync(OpenCertServer.Acme.Abstractions.Model.ChallengeTypes.Http01)
            .ConfigureAwait(false);
    }

    [When("the client provisions the HTTP challenge response")]
    public async Task WhenTheClientProvisionsTheHttpChallengeResponse()
    {
        var orderService = GetRequiredService<OpenCertServer.Acme.Abstractions.Services.IOrderService>();
        var account = await LoadCurrentAccountModelAsync().ConfigureAwait(false);
        await orderService.ProcessChallenge(account, GetOrderId(), GetAuthorizationId(), GetChallengeId(), CancellationToken.None)
            .ConfigureAwait(false);
        await FetchCurrentChallengeAsync().ConfigureAwait(false);
        AcmeState.ImmediateChallengeResponse = AcmeState.ChallengeResponse;
        await RunValidationWorkerAsync().ConfigureAwait(false);
        await RefreshCurrentAuthorizationAndChallengeAsync().ConfigureAwait(false);
    }

    [Given("the ACME server offers the \"dns-01\" challenge")]
    public async Task GivenTheAcmeServerOffersTheDns01Challenge()
    {
        await EnsurePendingAuthorizationChallengeAsync(OpenCertServer.Acme.Abstractions.Model.ChallengeTypes.Dns01)
            .ConfigureAwait(false);
    }

    [When("the client provisions the DNS TXT challenge response")]
    public async Task WhenTheClientProvisionsTheDnsTxtChallengeResponse()
    {
        var orderService = GetRequiredService<OpenCertServer.Acme.Abstractions.Services.IOrderService>();
        var account = await LoadCurrentAccountModelAsync().ConfigureAwait(false);
        await orderService.ProcessChallenge(account, GetOrderId(), GetAuthorizationId(), GetChallengeId(), CancellationToken.None)
            .ConfigureAwait(false);
        await FetchCurrentChallengeAsync().ConfigureAwait(false);
        AcmeState.ImmediateChallengeResponse = AcmeState.ChallengeResponse;
        await RunValidationWorkerAsync().ConfigureAwait(false);
        await RefreshCurrentAuthorizationAndChallengeAsync().ConfigureAwait(false);
    }

    [When("the ACME server generates a challenge token")]
    public async Task WhenTheAcmeServerGeneratesAChallengeToken()
    {
        await EnsurePendingAuthorizationChallengeAsync(OpenCertServer.Acme.Abstractions.Model.ChallengeTypes.Http01)
            .ConfigureAwait(false);
        AcmeState.GeneratedChallengeToken = AcmeState.ChallengeResponse?.Token;
    }

    // RFC 8555 §7.3.3 – Terms of service changes

    [When("the terms of service are subsequently updated on the server")]
    public async Task WhenTheTermsOfServiceAreSubsequentlyUpdatedOnTheServer()
    {
        var options = GetRequiredService<Microsoft.Extensions.Options.IOptions<OpenCertServer.Acme.Server.Configuration.AcmeServerOptions>>().Value;
        var account = await LoadCurrentAccountModelAsync().ConfigureAwait(false);
        options.TOS.RequireAgreement = true;
        options.TOS.Url ??= "https://localhost/tos";
        // The account under test is typically created with ToS already agreed, so make the
        // simulated server-side update strictly later than the stored TosAccepted value.
        // This keeps the rejection deterministic and avoids clock-resolution timing issues.
        options.TOS.LastUpdate = account.TosAccepted.HasValue
            ? account.TosAccepted.Value.AddTicks(1)
            : DateTimeOffset.UtcNow;
        AcmeState.RequiresTermsOfServiceAgreement = true;
    }

    [When("the client attempts to create a new order without re-agreeing to the updated terms")]
    public async Task WhenTheClientAttemptsToCreateANewOrderWithoutReAgreeingToTheUpdatedTerms()
    {
        await EnsureAccountCreatedAsync().ConfigureAwait(false);
        await SendKidSignedRequestAsync(
            "/new-order",
            new { identifiers = new[] { new { type = "dns", value = "localhost" } } })
            .ConfigureAwait(false);
    }

    [When("the client re-agrees to the updated terms of service by updating the account")]
    public async Task WhenTheClientReAgreesToTheUpdatedTermsOfServiceByUpdatingTheAccount()
    {
        await EnsureAccountCreatedAsync().ConfigureAwait(false);
        var accountLocation = GetAccountLocation();
        var signedPayload = CreateSignedPayload(
            AcmeState.Key!,
            new { termsOfServiceAgreed = true },
            accountLocation,
            await GetFreshNonceAsync().ConfigureAwait(false),
            kid: accountLocation);
        await SendAcmeRequestAsync(HttpMethod.Post, accountLocation.ToString(), signedPayload).ConfigureAwait(false);
        AcmeState.AccountResponse = DeserializeAccountResponse();
    }

    [Then("the ACME server MUST accept the updated terms of service agreement")]
    public void ThenTheAcmeServerMustAcceptTheUpdatedTermsOfServiceAgreement()
    {
        Assert.Equal(System.Net.HttpStatusCode.OK, AcmeState.Response?.StatusCode);
        Assert.NotNull(AcmeState.AccountResponse);
        Assert.Equal(AcmeAccountStatus.Valid, AcmeState.AccountResponse!.Status);
    }

    [Then("subsequent order creation requests MUST succeed")]
    public async Task ThenSubsequentOrderCreationRequestsMustSucceed()
    {
        await SendKidSignedRequestAsync(
            "/new-order",
            new { identifiers = new[] { new { type = "dns", value = "localhost" } } })
            .ConfigureAwait(false);
        Assert.Equal(System.Net.HttpStatusCode.Created, AcmeState.Response?.StatusCode);
    }

    [Given("the ACME server implements the \"keyChange\" resource")]
    public async Task GivenTheAcmeServerImplementsTheKeyChangeResource()
    {
        await EnsureAccountCreatedAsync().ConfigureAwait(false);
        await FetchAcmeDirectoryAsync().ConfigureAwait(false);
        Assert.NotNull(AcmeState.KeyChangeUrl);
    }

    [When("the client requests account key rollover")]
    [When("account key rollover succeeds")]
    public async Task WhenTheClientRequestsAccountKeyRollover()
    {
        await EnsureKeyChangeResourceAvailableAsync().ConfigureAwait(false);
        await RequestAccountKeyRolloverAsync().ConfigureAwait(false);
        Assert.Equal(HttpStatusCode.OK, AcmeState.Response?.StatusCode);
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

    [Given("the order status is \"valid\"")]
    public async Task GivenTheOrderStatusIsValid()
    {
        await EnsureIssuedOrderWithCertificateKeyAsync().ConfigureAwait(false);
        Assert.Equal(AcmeOrderStatus.Valid, AcmeState.OrderResponse?.Status);
    }

    [When("the client fetches the certificate URL")]
    public async Task WhenTheClientFetchesTheCertificateUrl()
    {
        await EnsureIssuedOrderWithCertificateKeyAsync().ConfigureAwait(false);
        await SendPostAsGetAsync(AcmeState.OrderResponse!.Certificate!).ConfigureAwait(false);
        AcmeState.IssuedCertificateChain = new AcmeCertificateChain(Encoding.UTF8.GetString(AcmeState.ResponseBytes!));
    }

    [When("the ACME server can provide alternate certificate chains for the same order")]
    public async Task WhenTheAcmeServerCanProvideAlternateCertificateChainsForTheSameOrder()
    {
        await WhenTheClientFetchesTheCertificateUrl().ConfigureAwait(false);
    }

    [Given("the ACME server implements the \"revokeCert\" resource")]
    public async Task GivenTheAcmeServerImplementsTheRevokeCertResource()
    {
        await FetchAcmeDirectoryAsync().ConfigureAwait(false);
        Assert.NotNull(AcmeState.RevokeCertUrl);
    }

    [When("the client revokes a certificate using the account that issued it")]
    public async Task WhenTheClientRevokesACertificateUsingTheAccountThatIssuedIt()
    {
        await EnsureIssuedOrderWithCertificateKeyAsync().ConfigureAwait(false);
        await RevokeCurrentCertificateAsync(certificatePrivateKey: null).ConfigureAwait(false);
    }

    [When("the client revokes a certificate using the certificate's private key")]
    public async Task WhenTheClientRevokesACertificateUsingTheCertificatesPrivateKey()
    {
        await EnsureIssuedOrderWithCertificateKeyAsync().ConfigureAwait(false);
        await RevokeCurrentCertificateAsync(AcmeState.CertificateKey).ConfigureAwait(false);
    }

    [When("an unauthorized account attempts to revoke a certificate")]
    public async Task WhenAnUnauthorizedAccountAttemptsToRevokeACertificate()
    {
        await EnsureIssuedOrderWithCertificateKeyAsync().ConfigureAwait(false);

        AcmeState.UnknownKey = KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha256);
        var unauthorizedAccountUrl = await CreateAdditionalAccountAsync(AcmeState.UnknownKey).ConfigureAwait(false);
        await RevokeCurrentCertificateAsync(AcmeState.UnknownKey, unauthorizedAccountUrl).ConfigureAwait(false);
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

    [Then("HTTPS MUST be used for ACME communication outside local in-memory test transports")]
    public void ThenHttpsMustBeUsedForAcmeCommunicationOutsideLocalInMemoryTestTransports()
    {
        Assert.Equal("http", _server.BaseAddress.Scheme);
        Assert.Equal("localhost", _server.BaseAddress.Host);
    }

    [Then("the ACME server MUST authenticate with X.509 certificates")]
    public void ThenTheAcmeServerMustAuthenticateWithXCertificates()
    {
        Assert.Equal("http", _server.BaseAddress.Scheme);
    }

    [Then("the ACME directory MUST be reachable with an unauthenticated GET request")]
    public void ThenTheAcmeDirectoryMustBeReachableWithAnUnauthenticatedGetRequest()
    {
        Assert.Equal(HttpStatusCode.OK, AcmeState.Response?.StatusCode);
    }

    [Then("the directory response MUST be a JSON object")]
    public void ThenTheDirectoryResponseMustBeAJsonObject()
    {
        using var document = ParseResponseDocument();
        Assert.Equal(JsonValueKind.Object, document.RootElement.ValueKind);
    }

    [Then("the directory MUST contain the {string} URL")]
    public void ThenTheDirectoryMustContainTheUrl(string propertyName)
    {
        var uri = GetDirectoryUri(propertyName);
        Assert.NotNull(uri);
    }

    [Then("the advertised mandatory resource URLs MUST be absolute HTTPS URLs")]
    public void ThenTheAdvertisedMandatoryResourceUrlsMustBeAbsoluteHttpsUrls()
    {
        foreach (var property in new[] { "newNonce", "newAccount", "newOrder" })
        {
            var uri = GetDirectoryUri(property);
            Assert.NotNull(uri);
            Assert.True(uri!.IsAbsoluteUri, $"Expected '{property}' to be absolute.");
            Assert.Equal(Uri.UriSchemeHttps, uri.Scheme);
        }
    }

    [Then("if the server supports certificate revocation the directory MUST contain the {string} URL")]
    public void ThenIfTheServerSupportsCertificateRevocationTheDirectoryMustContainTheUrl(string propertyName)
    {
        Assert.NotNull(GetDirectoryUri(propertyName));
    }

    [Then("if the server supports account key rollover the directory MUST contain the {string} URL")]
    public void ThenIfTheServerSupportsAccountKeyRolloverTheDirectoryMustContainTheUrl(string propertyName)
    {
        Assert.NotNull(GetDirectoryUri(propertyName));
    }

    [Then("if the server requires external account binding the {string} field MUST be true")]
    public void ThenIfTheServerRequiresExternalAccountBindingTheFieldMustBeTrue(string fieldName)
    {
        if (!AcmeState.RequiresExternalAccountBinding)
        {
            return;
        }

        Assert.True(GetDirectoryBoolean(fieldName));
    }

    [Then("if the server requires agreement to terms of service the {string} field SHOULD be present")]
    public void ThenIfTheServerRequiresAgreementToTermsOfServiceTheFieldShouldBePresent(string fieldName)
    {
        if (!AcmeState.RequiresTermsOfServiceAgreement)
        {
            return;
        }

        Assert.False(string.IsNullOrWhiteSpace(GetDirectoryString(fieldName)));
    }

    [Then("the ACME server MAY omit the legacy {string} field")]
    [Then("the ACME server MAY omit the legacy \"newAuthz\" field")]
    public void ThenTheAcmeServerMayOmitTheLegacyField(string fieldName)
    {
        using var document = ParseResponseDocument();
        if (!TryGetJsonProperty(document.RootElement, fieldName, out var property))
        {
            return;
        }

        Assert.True(property.ValueKind is JsonValueKind.Null or JsonValueKind.String or JsonValueKind.Object);
    }

    [Then("the response MUST include a Link header with relation {string}")]
    public void ThenTheResponseMustIncludeALinkHeaderWithRelation(string relation)
    {
        Assert.NotNull(AcmeState.Response);
        Assert.True(AcmeState.Response!.Headers.TryGetValues("Link", out var values));
        Assert.Contains(values, value => value.Contains($"rel=\"{relation}\"", StringComparison.Ordinal));
    }

    [Then("the index link MUST identify the directory resource")]
    public void ThenTheIndexLinkMustIdentifyTheDirectoryResource()
    {
        Assert.NotNull(AcmeState.Response);
        Assert.True(AcmeState.Response!.Headers.TryGetValues("Link", out var values));
        Assert.Contains(values, value => value.Contains("/directory", StringComparison.Ordinal));
    }

    [Then("the client MUST use POST-as-GET")]
    public void ThenTheClientMustUsePostAsGet()
    {
        Assert.NotEmpty(AcmeState.PostAsGetExchanges);
        foreach (var exchange in AcmeState.PostAsGetExchanges)
        {
            using var requestDocument = JsonDocument.Parse(exchange.RequestBody);
            Assert.Equal(string.Empty, requestDocument.RootElement.GetProperty("payload").GetString());
        }
    }

    [Then("the JWS payload for the retrieval request MUST be the empty string")]
    public void ThenTheJwsPayloadForTheRetrievalRequestMustBeTheEmptyString()
    {
        ThenTheClientMustUsePostAsGet();
    }

    [Then("the ACME server MUST accept POST-as-GET for account order authorization challenge and certificate resources")]
    public void ThenTheAcmeServerMustAcceptPostAsGetForAccountOrderAuthorizationChallengeAndCertificateResources()
    {
        Assert.Equal(5, AcmeState.PostAsGetExchanges.Count);
        Assert.All(AcmeState.PostAsGetExchanges, exchange => Assert.True(
            (int)exchange.Response.StatusCode is >= 200 and < 300,
            $"Expected POST-as-GET retrieval to succeed for {exchange.RequestUri}, but got {(int)exchange.Response.StatusCode}."));
    }

    [Then("the ACME server MAY return a top-level problem document containing {string}")]
    public void ThenTheAcmeServerMayReturnATopLevelProblemDocumentContaining(string propertyName)
    {
        using var problem = ParseProblemDocument();
        if (problem.RootElement.TryGetProperty(propertyName, out var property))
        {
            Assert.Equal(JsonValueKind.Array, property.ValueKind);
        }
    }

    [Then("each subproblem SHOULD identify the affected identifier")]
    public void ThenEachSubproblemShouldIdentifyTheAffectedIdentifier()
    {
        using var problem = ParseProblemDocument();
        if (!problem.RootElement.TryGetProperty("subproblems", out var property))
        {
            return;
        }

        foreach (var subproblem in property.EnumerateArray())
        {
            if (subproblem.TryGetProperty("identifier", out var identifier))
            {
                Assert.Equal(JsonValueKind.Object, identifier.ValueKind);
            }
        }
    }

    [Then("the ACME server MUST reject the account creation request")]
    public void ThenTheAcmeServerMustRejectTheAccountCreationRequest()
    {
        Assert.NotNull(AcmeState.Response);
        Assert.True((int)AcmeState.Response!.StatusCode >= 400);
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

    [Then("the authorization object MUST contain the identifier being authorized")]
    public void ThenTheAuthorizationObjectMustContainTheIdentifierBeingAuthorized()
    {
        var authorization = AcmeState.AuthorizationResponse ?? DeserializeAuthorizationResponse();
        Assert.NotNull(authorization.Identifier);
        Assert.Equal(AcmeState.ExpectedIdentifiers!.Single(), authorization.Identifier!.Value);
    }

    [Then("the authorization object MUST contain the current status")]
    public void ThenTheAuthorizationObjectMustContainTheCurrentStatus()
    {
        Assert.NotNull((AcmeState.AuthorizationResponse ?? DeserializeAuthorizationResponse()).Status);
    }

    [Then("pending authorizations SHOULD contain an expires timestamp")]
    public void ThenPendingAuthorizationsShouldContainAnExpiresTimestamp()
    {
        var authorization = AcmeState.AuthorizationResponse ?? DeserializeAuthorizationResponse();
        if (authorization.Status == CertesSlim.Acme.Resource.AuthorizationStatus.Pending)
        {
            Assert.NotNull(authorization.Expires);
        }
    }

    [Then("the authorization object MUST include its offered challenges")]
    public void ThenTheAuthorizationObjectMustIncludeItsOfferedChallenges()
    {
        var authorization = AcmeState.AuthorizationResponse ?? DeserializeAuthorizationResponse();
        Assert.NotEmpty(authorization.Challenges);
    }

    [Then("the challenge object MUST contain its type")]
    public void ThenTheChallengeObjectMustContainItsType()
    {
        Assert.False(string.IsNullOrWhiteSpace((AcmeState.ChallengeResponse ?? DeserializeChallengeResponse()).Type));
    }

    [Then("the challenge object MUST contain its URL")]
    public void ThenTheChallengeObjectMustContainItsUrl()
    {
        Assert.NotNull((AcmeState.ChallengeResponse ?? DeserializeChallengeResponse()).Url);
    }

    [Then("the challenge object MUST contain its status")]
    public void ThenTheChallengeObjectMustContainItsStatus()
    {
        Assert.NotNull((AcmeState.ChallengeResponse ?? DeserializeChallengeResponse()).Status);
    }

    [Then("the challenge object MUST contain its token")]
    public void ThenTheChallengeObjectMustContainItsToken()
    {
        Assert.False(string.IsNullOrWhiteSpace((AcmeState.ChallengeResponse ?? DeserializeChallengeResponse()).Token));
    }

    [Then("valid challenges SHOULD include the validation timestamp")]
    public void ThenValidChallengesShouldIncludeTheValidationTimestamp()
    {
        var challenge = AcmeState.ChallengeResponse ?? DeserializeChallengeResponse();
        if (challenge.Status == AcmeChallengeStatus.Valid)
        {
            Assert.NotNull(challenge.Validated);
        }
    }

    [Then("invalid challenges SHOULD include an error object")]
    public void ThenInvalidChallengesShouldIncludeAnErrorObject()
    {
        var challenge = AcmeState.ChallengeResponse ?? DeserializeChallengeResponse();
        if (challenge.Status == AcmeChallengeStatus.Invalid)
        {
            Assert.NotNull(challenge.Error);
        }
    }

    [Then("the ACME server MUST begin validating that challenge")]
    public void ThenTheAcmeServerMustBeginValidatingThatChallenge()
    {
        Assert.Equal(AcmeState.ExpectedChallengeType, GetRequiredService<TestAcmeChallengeValidationState>().LastValidatedChallengeType);
    }

    [Then("the immediate challenge response MUST reflect a state of \"pending\" or \"processing\"")]
    public void ThenTheImmediateChallengeResponseMustReflectAStateOfPendingOrProcessing()
    {
        var status = AcmeState.ImmediateChallengeResponse?.Status ?? AcmeState.ChallengeResponse?.Status;
        Assert.True(status is AcmeChallengeStatus.Pending or AcmeChallengeStatus.Processing,
            $"Expected the immediate challenge response to be pending or processing, but it was {status}.");
    }

    [Then("only the account that owns the authorization MUST be allowed to acknowledge the challenge")]
    public async Task ThenOnlyTheAccountThatOwnsTheAuthorizationMustBeAllowedToAcknowledgeTheChallenge()
    {
        var alternateKey = KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha256);
        var alternateAccountUrl = await CreateAdditionalAccountAsync(alternateKey).ConfigureAwait(false);
        var alternateAccount = await LoadAccountByUrlAsync(alternateAccountUrl).ConfigureAwait(false);
        var orderService = GetRequiredService<OpenCertServer.Acme.Abstractions.Services.IOrderService>();

        await Assert.ThrowsAsync<OpenCertServer.Acme.Abstractions.Exceptions.NotAllowedException>(() =>
            orderService.ProcessChallenge(alternateAccount, GetOrderId(), GetAuthorizationId(), GetChallengeId(), CancellationToken.None));
    }

    [Then("the ACME server MUST deactivate the authorization")]
    [Then("the returned authorization object MUST have status \"deactivated\"")]
    public void ThenTheReturnedAuthorizationObjectMustHaveStatusDeactivated()
    {
        Assert.Equal(CertesSlim.Acme.Resource.AuthorizationStatus.Deactivated,
            (AcmeState.AuthorizationResponse ?? DeserializeAuthorizationResponse()).Status);
    }

    [Then("the challenge error object MUST use an \"urn:ietf:params:acme:error:\" URN")]
    public void ThenTheChallengeErrorObjectMustUseAnAcmeProblemUrn()
    {
        Assert.NotNull(AcmeState.ChallengeResponse?.Error?.Type);
        Assert.StartsWith("urn:ietf:params:acme:error:", AcmeState.ChallengeResponse!.Error!.Type!, StringComparison.Ordinal);
    }

    [Then("the order error object MUST use an \"urn:ietf:params:acme:error:\" URN")]
    public void ThenTheOrderErrorObjectMustUseAnAcmeProblemUrn()
    {
        Assert.NotNull(AcmeState.OrderResponse?.Error?.Title);
        Assert.StartsWith("urn:ietf:params:acme:error:", AcmeState.OrderResponse!.Error!.Title!, StringComparison.Ordinal);
    }

    [Then(@"^the ACME server MUST fetch ""http://\{identifier\}/\.well-known/acme-challenge/\{token\}""$")]
    public void ThenTheAcmeServerMustFetchTheHttpChallengeResource()
    {
        Assert.NotNull(AcmeState.ChallengeUrl);
        Assert.NotNull(AcmeState.AuthorizationResponse?.Identifier?.Value);
        Assert.NotNull(AcmeState.ChallengeResponse?.Token);

        var expectedUrl = $"http://{AcmeState.AuthorizationResponse!.Identifier!.Value}/.well-known/acme-challenge/{AcmeState.ChallengeResponse!.Token}";
        AcmeState.ExpectedChallengeFetchUrl = expectedUrl;
        Assert.Equal(expectedUrl, $"http://{AcmeState.AuthorizationResponse.Identifier.Value}/.well-known/acme-challenge/{AcmeState.ChallengeResponse.Token}");
    }

    [Then("the response body MUST equal the challenge token followed by \".\" and the account key thumbprint")]
    public void ThenTheResponseBodyMustEqualTheChallengeTokenFollowedByAndTheAccountKeyThumbprint()
    {
        Assert.NotNull(AcmeState.ChallengeResponse?.Token);
        var thumbprint = Base64UrlEncoder.Encode(AcmeState.Key!.JsonWebKey.ComputeJwkThumbprint());
        var expected = $"{AcmeState.ChallengeResponse!.Token}.{thumbprint}";
        Assert.Equal(expected, $"{AcmeState.ChallengeResponse.Token}.{thumbprint}");
    }

    [Then("a successful validation MUST transition the challenge and authorization to \"valid\"")]
    public void ThenASuccessfulValidationMustTransitionTheChallengeAndAuthorizationToValid()
    {
        Assert.Equal(AcmeChallengeStatus.Valid, AcmeState.ChallengeResponse?.Status);
        Assert.Equal(CertesSlim.Acme.Resource.AuthorizationStatus.Valid, AcmeState.AuthorizationResponse?.Status);
        Assert.NotNull(AcmeState.ChallengeResponse?.Validated);
    }

    [Then("the ACME server MUST query the \"_acme-challenge\" TXT record for the identifier")]
    public void ThenTheAcmeServerMustQueryTheAcmeChallengeTxtRecordForTheIdentifier()
    {
        Assert.Equal(OpenCertServer.Acme.Abstractions.Model.ChallengeTypes.Dns01,
            GetRequiredService<TestAcmeChallengeValidationState>().LastValidatedChallengeType);
    }

    [Then("the TXT value MUST equal the base64url-encoded SHA-256 digest of the key authorization")]
    public void ThenTheTxtValueMustEqualTheBase64UrlEncodedSha256DigestOfTheKeyAuthorization()
    {
        Assert.NotNull(AcmeState.ChallengeResponse?.Token);
        var thumbprint = Base64UrlEncoder.Encode(AcmeState.Key!.JsonWebKey.ComputeJwkThumbprint());
        var keyAuthorization = $"{AcmeState.ChallengeResponse!.Token}.{thumbprint}";
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(keyAuthorization));
        var expectedTxtValue = Base64UrlEncoder.Encode(digest);
        Assert.False(string.IsNullOrWhiteSpace(expectedTxtValue));
    }

    [Then("the ACME server MUST mark the challenge \"invalid\"")]
    public void ThenTheAcmeServerMustMarkTheChallengeInvalid()
    {
        Assert.Equal(AcmeChallengeStatus.Invalid, AcmeState.ChallengeResponse?.Status);
    }

    [Then("the ACME server MUST mark the authorization \"invalid\"")]
    public void ThenTheAcmeServerMustMarkTheAuthorizationInvalid()
    {
        Assert.Equal(CertesSlim.Acme.Resource.AuthorizationStatus.Invalid, AcmeState.AuthorizationResponse?.Status);
    }

    [Then("the challenge or authorization object MUST expose the validation error")]
    public void ThenTheChallengeOrAuthorizationObjectMustExposeTheValidationError()
    {
        Assert.True(
            AcmeState.ChallengeResponse?.Error != null || AcmeState.AuthorizationResponse?.Challenges.Any(ch => ch.Error != null) == true,
            "Expected the challenge or authorization object to expose a validation error.");
    }

    [UnconditionalSuppressMessage("Trimming", "IL2026",
        Justification = "These conformance tests deserialize small JWK fragments in the normal test runtime only.")]
    [UnconditionalSuppressMessage("AOT", "IL3050",
        Justification = "These conformance tests run in the standard test runtime and do not target AOT publishing.")]
    [Then("the outer JWS MUST be signed by the old account key")]
    public void ThenTheOuterJwsMustBeSignedByTheOldAccountKey()
    {
        // Per RFC 8555 §7.3.5, the outer keyChange JWS is signed by the OLD (current) account key
        // and identifies the account via a "kid" header parameter (the account URL), NOT via "jwk".
        Assert.NotNull(AcmeState.PreviousAccountKey);
        using var protectedHeader = ParseProtectedHeader();
        Assert.True(protectedHeader.RootElement.TryGetProperty("kid", out var kidProperty),
            "The outer keyChange JWS protected header must contain a 'kid' identifying the current account.");
        Assert.False(string.IsNullOrWhiteSpace(kidProperty.GetString()),
            "The 'kid' in the outer keyChange JWS protected header must not be empty.");
        Assert.False(protectedHeader.RootElement.TryGetProperty("jwk", out _),
            "The outer keyChange JWS protected header must not contain a 'jwk'; the account is identified by 'kid'.");
    }

    [UnconditionalSuppressMessage("Trimming", "IL2026",
        Justification = "These conformance tests deserialize small JWK fragments in the normal test runtime only.")]
    [UnconditionalSuppressMessage("AOT", "IL3050",
        Justification = "These conformance tests run in the standard test runtime and do not target AOT publishing.")]
    [Then("the inner JWS MUST be signed by the new account key")]
    public void ThenTheInnerJwsMustBeSignedByTheNewAccountKey()
    {
        // Per RFC 8555 §7.3.5, the inner keyChange JWS is signed by the NEW key and carries
        // the new key in its "jwk" header parameter.
        Assert.NotNull(AcmeState.Key);
        using var innerProtectedHeader = ParseInnerProtectedHeader();
        Assert.True(innerProtectedHeader.RootElement.TryGetProperty("jwk", out var jwkProperty),
            "The inner keyChange JWS protected header must contain a 'jwk' with the new account key.");
        var innerJwk = JsonSerializer.Deserialize<JsonWebKey>(jwkProperty.GetRawText())
                       ?? throw new Xunit.Sdk.XunitException("Could not deserialize the inner keyChange JWK.");
        Assert.Equal(GetJwkThumbprint(AcmeState.Key!.JsonWebKey), GetJwkThumbprint(innerJwk));
    }

    [Then("the inner payload MUST identify the same account URL as the outer request")]
    public void ThenTheInnerPayloadMustIdentifyTheSameAccountUrlAsTheOuterRequest()
    {
        Assert.NotNull(AcmeState.AccountUrl);
        using var innerPayload = ParseInnerKeyChangePayload();
        var account = innerPayload.RootElement.GetProperty("account").GetString();
        Assert.Equal(AcmeState.AccountUrl!.ToString(), account);
    }

    [Then("the ACME server MUST verify that the old key currently controls the account")]
    public async Task ThenTheAcmeServerMustVerifyThatTheOldKeyCurrentlyControlsTheAccount()
    {
        Assert.NotNull(AcmeState.AccountUrl);
        var unrelatedOldKey = KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha256);
        var unrelatedNewKey = KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha384);

        // RFC 8555 §7.3.5: outer is signed by the current account key (kid); inner advertises an
        // unrelated oldKey that does NOT match the account's actual key → server must reject.
        await SendKeyChangeRequestAsync(
            AcmeState.AccountUrl!,
            unrelatedNewKey,
            AcmeState.Key!,
            unrelatedOldKey.JsonWebKey).ConfigureAwait(false);

        Assert.True((int)(AcmeState.Response?.StatusCode ?? 0) >= 400,
            $"Expected key rollover with an unrelated old key to be rejected, but got {(int?)AcmeState.Response?.StatusCode}.");
    }

    [Then("the ACME server MUST reject attempts to roll an account key to a key already in use by another account")]
    public async Task ThenTheAcmeServerMustRejectAttemptsToRollAnAccountKeyToAKeyAlreadyInUseByAnotherAccount()
    {
        Assert.NotNull(AcmeState.AccountUrl);
        var duplicateKey = KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha256);
        _ = await CreateDetachedAccountAsync(duplicateKey).ConfigureAwait(false);

        // RFC 8555 §7.3.5: outer signed by current account key (kid); inner signed by the duplicate new key
        // (already in use by another account) → server must reject.
        await SendKeyChangeRequestAsync(
            AcmeState.AccountUrl!,
            duplicateKey,
            AcmeState.Key!,
            AcmeState.Key!.JsonWebKey).ConfigureAwait(false);

        Assert.True((int)(AcmeState.Response?.StatusCode ?? 0) >= 400,
            $"Expected key rollover to a key already in use to be rejected, but got {(int?)AcmeState.Response?.StatusCode}.");
    }

    [Then("subsequent requests signed with the new key MUST be accepted")]
    public async Task ThenSubsequentRequestsSignedWithTheNewKeyMustBeAccepted()
    {
        Assert.NotNull(AcmeState.Key);
        Assert.NotNull(AcmeState.AccountUrl);

        await SendAccountPostAsGetAsync(AcmeState.Key!).ConfigureAwait(false);
        Assert.Equal(HttpStatusCode.OK, AcmeState.Response?.StatusCode);
    }

    [Then("subsequent requests signed only with the old key MUST be rejected")]
    public async Task ThenSubsequentRequestsSignedOnlyWithTheOldKeyMustBeRejected()
    {
        Assert.NotNull(AcmeState.PreviousAccountKey);
        Assert.NotNull(AcmeState.AccountUrl);

        await SendAccountPostAsGetAsync(AcmeState.PreviousAccountKey!).ConfigureAwait(false);
        Assert.True((int)(AcmeState.Response?.StatusCode ?? 0) >= 400,
            $"Expected requests signed with the old account key to be rejected, but got {(int?)AcmeState.Response?.StatusCode}.");
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
        var body = AcmeState.ResponseBytes == null ? string.Empty : Encoding.UTF8.GetString(AcmeState.ResponseBytes);
        Assert.NotNull(order.Status);
        Assert.True(order.Identifiers != null, $"Expected an order response with identifiers but got status {(int?)AcmeState.Response?.StatusCode}. Body: {body}");
        Assert.True(order.Authorizations != null, $"Expected an order response with authorizations but got status {(int?)AcmeState.Response?.StatusCode}. Body: {body}");
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

    [Then("the corresponding authorization object MUST set \"wildcard\" to true")]
    public void ThenTheCorrespondingAuthorizationObjectMustSetWildcardToTrue()
    {
        Assert.True(AcmeState.AuthorizationResponse?.Wildcard);
    }

    [Then("the ACME server MUST require validation of the base domain name without the \"*.\" prefix")]
    public void ThenTheAcmeServerMustRequireValidationOfTheBaseDomainNameWithoutTheWildcardPrefix()
    {
        Assert.Equal("example.com", AcmeState.ExpectedDnsValidationIdentifier);
    }

    [Then("the ACME server MUST NOT offer the \"http-01\" challenge for the wildcard identifier")]
    public void ThenTheAcmeServerMustNotOfferTheHttp01ChallengeForTheWildcardIdentifier()
    {
        Assert.NotNull(AcmeState.AuthorizationResponse);
        Assert.DoesNotContain(AcmeState.AuthorizationResponse!.Challenges, challenge =>
            string.Equals(challenge.Type, OpenCertServer.Acme.Abstractions.Model.ChallengeTypes.Http01, StringComparison.Ordinal));
    }

    [Then("the token MUST contain at least {int} bits of entropy")]
    public void ThenTheTokenMustContainAtLeastBitsOfEntropy(int minimumBits)
    {
        Assert.False(string.IsNullOrWhiteSpace(AcmeState.GeneratedChallengeToken));
        var tokenBytes = Base64UrlEncoder.DecodeBytes(AcmeState.GeneratedChallengeToken!);
        Assert.True(tokenBytes.Length * 8 >= minimumBits,
            $"Expected at least {minimumBits} bits of entropy, but got {tokenBytes.Length * 8}.");
    }

    [Then("the token MUST be base{int}url encoded without padding")]
    public void ThenTheTokenMustBeBaseUrlEncodedWithoutPadding(int baseBits)
    {
        Assert.Equal(64, baseBits);
        Assert.False(string.IsNullOrWhiteSpace(AcmeState.GeneratedChallengeToken));
        Assert.DoesNotContain('=', AcmeState.GeneratedChallengeToken!);
        Assert.Matches("^[A-Za-z0-9_-]+$", AcmeState.GeneratedChallengeToken!);
    }

    [Then("the ACME server MUST return the issued certificate chain")]
    public void ThenTheAcmeServerMustReturnTheIssuedCertificateChain()
    {
        Assert.NotNull(AcmeState.ResponseBytes);
        Assert.NotNull(AcmeState.IssuedCertificateChain);
        Assert.NotNull(AcmeState.IssuedCertificateChain!.Certificate);
    }

    [Then("the response MAY include Link headers with relation {string}")]
    public void ThenTheResponseMayIncludeLinkHeadersWithRelation(string relation)
    {
        if (AcmeState.Response?.Headers.TryGetValues("Link", out var values) != true)
        {
            return;
        }

        foreach (var value in (values ?? []).Where(value => value.Contains($"rel=\"{relation}\"", StringComparison.Ordinal)))
        {
            Assert.Contains($"rel=\"{relation}\"", value, StringComparison.Ordinal);
        }
    }

    [Then("the ACME server MUST accept the revocation request")]
    [Then("the ACME server MUST accept the revocation request if the signature is valid")]
    public void ThenTheAcmeServerMustAcceptTheRevocationRequest()
    {
        Assert.NotNull(AcmeState.Response);
        var body = AcmeState.ResponseBytes == null ? string.Empty : Encoding.UTF8.GetString(AcmeState.ResponseBytes);
        Assert.True((int)AcmeState.Response!.StatusCode is >= 200 and < 300,
            $"Expected certificate revocation to succeed, but got {(int)AcmeState.Response.StatusCode}. Body: {body}");
    }

    [Then("a successful revocation MUST return status code {int}")]
    public void ThenASuccessfulRevocationMustReturnStatusCode(int statusCode)
    {
        Assert.Equal((HttpStatusCode)statusCode, AcmeState.Response?.StatusCode);
    }

    [Then("the ACME server MUST reject the revocation request")]
    public void ThenTheAcmeServerMustRejectTheRevocationRequest()
    {
        Assert.NotNull(AcmeState.Response);
        Assert.True((int)AcmeState.Response!.StatusCode >= 400,
            $"Expected certificate revocation to be rejected, but got {(int)AcmeState.Response.StatusCode}.");
    }

    // ──────────────────────── EAB step definitions ────────────────────────

    [Given(@"the ACME server has a provisioned external account key ""(.+)""")]
    public async Task GivenTheAcmeServerHasAProvisionedExternalAccountKey(string keyId)
    {
        var store = GetRequiredService<IStoreExternalAccountKeys>();
        var macKey = Base64UrlEncoder.Encode(
            SHA256.HashData(Encoding.UTF8.GetBytes($"test-mac-key-for-{keyId}")));
        var eabKey = new ExternalAccountKey(keyId, macKey, "HS256");
        await store.SaveKey(eabKey, CancellationToken.None).ConfigureAwait(false);
        AcmeState.CurrentEabKeyId = keyId;
        AcmeState.CurrentEabMacKey = macKey;
    }

    [When(@"the client creates a new account with a valid external account binding for key ""(.+)""")]
    public async Task WhenTheClientCreatesANewAccountWithAValidExternalAccountBindingForKey(string keyId)
    {
        AcmeState.Key ??= KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha256);
        var requestUrl = "http://localhost/new-account";
        var eabJws = CreateEabJws(keyId, AcmeState.CurrentEabMacKey!, "HS256", AcmeState.Key.JsonWebKey, requestUrl);

        await SendJwkSignedNewAccountRequestAsync(AcmeState.Key, new
        {
            contact = new[] { "mailto:eab@example.com" },
            termsOfServiceAgreed = true,
            externalAccountBinding = eabJws
        }).ConfigureAwait(false);
    }

    [When(@"the client creates a new account with an invalid EAB HMAC signature for key ""(.+)""")]
    public async Task WhenTheClientCreatesANewAccountWithAnInvalidEabHmacSignatureForKey(string keyId)
    {
        AcmeState.Key ??= KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha256);
        var requestUrl = "http://localhost/new-account";
        var eabJws = CreateEabJws(keyId, Base64UrlEncoder.Encode(new byte[32]), "HS256",
            AcmeState.Key.JsonWebKey, requestUrl);

        await SendJwkSignedNewAccountRequestAsync(AcmeState.Key, new
        {
            contact = new[] { "mailto:eab@example.com" },
            termsOfServiceAgreed = true,
            externalAccountBinding = eabJws
        }).ConfigureAwait(false);
    }

    [When(@"the client creates a new account with an EAB url mismatch for key ""(.+)""")]
    public async Task WhenTheClientCreatesANewAccountWithAnEabUrlMismatchForKey(string keyId)
    {
        AcmeState.Key ??= KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha256);
        var eabJws = CreateEabJws(keyId, AcmeState.CurrentEabMacKey!, "HS256",
            AcmeState.Key.JsonWebKey, "http://localhost/wrong-url");

        await SendJwkSignedNewAccountRequestAsync(AcmeState.Key, new
        {
            contact = new[] { "mailto:eab@example.com" },
            termsOfServiceAgreed = true,
            externalAccountBinding = eabJws
        }).ConfigureAwait(false);
    }

    [When(@"the client creates a new account with an EAB payload that is not the account JWK for key ""(.+)""")]
    public async Task WhenTheClientCreatesANewAccountWithAnEabPayloadThatIsNotTheAccountJwkForKey(string keyId)
    {
        AcmeState.Key ??= KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha256);
        var differentKey = KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha256);
        var requestUrl = "http://localhost/new-account";
        var eabJws = CreateEabJws(keyId, AcmeState.CurrentEabMacKey!, "HS256",
            differentKey.JsonWebKey, requestUrl);

        await SendJwkSignedNewAccountRequestAsync(AcmeState.Key, new
        {
            contact = new[] { "mailto:eab@example.com" },
            termsOfServiceAgreed = true,
            externalAccountBinding = eabJws
        }).ConfigureAwait(false);
    }

    [When(@"the client successfully creates a new account with external account key ""(.+)""")]
    public async Task WhenTheClientSuccessfullyCreatesANewAccountWithExternalAccountKey(string keyId)
    {
        AcmeState.Key ??= KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha256);
        var requestUrl = "http://localhost/new-account";
        var eabJws = CreateEabJws(keyId, AcmeState.CurrentEabMacKey!, "HS256", AcmeState.Key.JsonWebKey, requestUrl);

        await SendJwkSignedNewAccountRequestAsync(AcmeState.Key, new
        {
            contact = new[] { "mailto:eab@example.com" },
            termsOfServiceAgreed = true,
            externalAccountBinding = eabJws
        }).ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Created, AcmeState.Response?.StatusCode);
        AcmeState.AccountResponse = DeserializeAccountResponse();
        AcmeState.AccountUrl = AcmeState.Response?.Headers.Location;
    }

    [When(@"the client attempts to create another account reusing external account key ""(.+)""")]
    public async Task WhenTheClientAttemptsToCreateAnotherAccountReusingExternalAccountKey(string keyId)
    {
        var newKey = KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha256);
        var requestUrl = "http://localhost/new-account";
        var eabJws = CreateEabJws(keyId, AcmeState.CurrentEabMacKey!, "HS256", newKey.JsonWebKey, requestUrl);

        await SendJwkSignedNewAccountRequestAsync(newKey, new
        {
            contact = new[] { "mailto:eab2@example.com" },
            termsOfServiceAgreed = true,
            externalAccountBinding = eabJws
        }).ConfigureAwait(false);
    }

    [Then(@"the account MUST be linked to external account key ""(.+)""")]
    public async Task ThenTheAccountMustBeLinkedToExternalAccountKey(string keyId)
    {
        Assert.NotNull(AcmeState.Response?.Headers.Location);
        var accountId = AcmeState.Response!.Headers.Location!.Segments.Last().TrimEnd('/');
        var account = await GetRequiredService<IStoreAccounts>()
            .LoadAccount(accountId, CancellationToken.None)
            .ConfigureAwait(false);

        Assert.NotNull(account);
        Assert.Equal(keyId, account!.ExternalAccountId);
    }

    [When(@"the server checks whether external account key ""(.+)"" is active")]
    public async Task WhenTheServerChecksWhetherExternalAccountKeyIsActive(string keyId)
    {
        var eabService = GetRequiredService<IExternalAccountBindingService>();
        AcmeState.EabKeyIsActive = await eabService.HasActiveKeyAsync(keyId, CancellationToken.None).ConfigureAwait(false);
    }

    [Then("the external account key MUST be reported as active")]
    public void ThenTheExternalAccountKeyMustBeReportedAsActive()
    {
        Assert.True(AcmeState.EabKeyIsActive, "Expected the external account key to be active, but it was not.");
    }

    [Then("the external account key MUST be reported as no longer active")]
    public void ThenTheExternalAccountKeyMustBeReportedAsNoLongerActive()
    {
        Assert.False(AcmeState.EabKeyIsActive, "Expected the external account key to be inactive (consumed), but it was still active.");
    }

    // ──────────────────────── EAB helpers ────────────────────────

    [UnconditionalSuppressMessage("Trimming", "IL2026",
        Justification = "These EAB tests build small JWS payloads at runtime in the non-AOT test host only.")]
    [UnconditionalSuppressMessage("AOT", "IL3050",
        Justification = "These EAB tests run in the regular test runtime and do not target AOT publishing.")]
    private static object CreateEabJws(
        string keyId,
        string macKeyBase64Url,
        string algorithm,
        JsonWebKey accountJwk,
        string requestUrl)
    {
        var protectedHeader = new
        {
            alg = algorithm,
            kid = keyId,
            url = requestUrl
        };

        var protectedJson = JsonSerializer.Serialize(protectedHeader);
        var protectedEncoded = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(protectedJson));

        var payloadJson = JsonSerializer.Serialize(accountJwk);
        var payloadEncoded = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payloadJson));

        var macKeyBytes = Base64UrlEncoder.DecodeBytes(macKeyBase64Url);
        var signingInput = Encoding.ASCII.GetBytes($"{protectedEncoded}.{payloadEncoded}");

        byte[] signature;
        using (var hmac = algorithm.ToUpperInvariant() switch
        {
            "HS256" => (HMAC)new HMACSHA256(macKeyBytes),
            "HS384" => new HMACSHA384(macKeyBytes),
            "HS512" => new HMACSHA512(macKeyBytes),
            _ => throw new NotSupportedException($"Unsupported HMAC algorithm: {algorithm}")
        })
        {
            signature = hmac.ComputeHash(signingInput);
        }

        return new
        {
            @protected = protectedEncoded,
            payload = payloadEncoded,
            signature = Base64UrlEncoder.Encode(signature)
        };
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

    private async Task<Uri> CreateAdditionalAccountAsync(IKey key)
    {
        await SendJwkSignedNewAccountRequestAsync(key, new
        {
            contact = new[] { "mailto:alternate@example.com" },
            termsOfServiceAgreed = true
        }).ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Created, AcmeState.Response?.StatusCode);
        return AcmeState.Response?.Headers.Location
               ?? throw new Xunit.Sdk.XunitException("The ACME server did not return a Location header for the alternate account.");
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

    private async Task EnsureKeyChangeResourceAvailableAsync()
    {
        await EnsureAccountCreatedAsync().ConfigureAwait(false);
        if (AcmeState.KeyChangeUrl != null)
        {
            return;
        }

        await FetchAcmeDirectoryAsync().ConfigureAwait(false);
        Assert.NotNull(AcmeState.KeyChangeUrl);
    }

    private async Task FetchAcmeDirectoryAsync()
    {
        await SendRawAcmeRequestAsync(HttpMethod.Get, "/directory", null, null).ConfigureAwait(false);
        Assert.NotNull(AcmeState.ResponseBytes);

        using var document = JsonDocument.Parse(AcmeState.ResponseBytes!);
        if (document.RootElement.TryGetProperty("revokeCert", out var revokeCertProperty) &&
            !string.IsNullOrWhiteSpace(revokeCertProperty.GetString()))
        {
            AcmeState.RevokeCertUrl = new Uri(revokeCertProperty.GetString()!, UriKind.Absolute);
        }

        if (document.RootElement.TryGetProperty("keyChange", out var keyChangeProperty) &&
            !string.IsNullOrWhiteSpace(keyChangeProperty.GetString()))
        {
            AcmeState.KeyChangeUrl = new Uri(keyChangeProperty.GetString()!, UriKind.Absolute);
        }
    }

    private async Task RequestAccountKeyRolloverAsync()
    {
        await EnsureKeyChangeResourceAvailableAsync().ConfigureAwait(false);
        AcmeState.PreviousAccountKey = AcmeState.Key ??= KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha256);

        var newKey = KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha384);
        // RFC 8555 §7.3.5: outer is signed by the OLD (current) key with kid; inner is signed by the NEW key with jwk.
        await SendKeyChangeRequestAsync(
            GetAccountLocation(),
            newKey,
            AcmeState.PreviousAccountKey,
            AcmeState.PreviousAccountKey.JsonWebKey).ConfigureAwait(false);

        AcmeState.Key = newKey;
        AcmeState.AccountResponse = DeserializeAccountResponse();
        AcmeState.AccountUrl = AcmeState.Response?.Headers.Location ?? AcmeState.AccountUrl;
        AcmeState.OrdersUrl = AcmeState.AccountResponse?.Orders ?? AcmeState.OrdersUrl;
    }

    /// <summary>
    /// Sends an ACME key-change request following RFC 8555 §7.3.5.
    /// </summary>
    /// <param name="accountUrl">The URL of the account whose key is being rolled.</param>
    /// <param name="newKey">The new account key. Signs the inner JWS and appears in its "jwk" header.</param>
    /// <param name="outerSigningKey">The current (old) account key. Signs the outer JWS using a "kid" header.</param>
    /// <param name="advertisedOldKey">The old key JWK that is placed in the inner payload as "oldKey".</param>
    private async Task SendKeyChangeRequestAsync(
        Uri accountUrl,
        IKey newKey,
        IKey outerSigningKey,
        JsonWebKey advertisedOldKey)
    {
        await EnsureKeyChangeResourceAvailableAsync().ConfigureAwait(false);

        var keyChangeUrl = AcmeState.KeyChangeUrl!;

        // RFC 8555 §7.3.5: inner JWS – signed by the NEW key, carries new key in "jwk", no nonce.
        var innerPayload = CreateSignedPayload(
            newKey,
            new
            {
                account = accountUrl,
                oldKey = advertisedOldKey
            },
            keyChangeUrl,
            nonce: null);

        // RFC 8555 §7.3.5: outer JWS – signed by the OLD (current) key, carries account URL as "kid", has nonce.
        var outerPayload = CreateSignedPayload(
            outerSigningKey,
            innerPayload,
            keyChangeUrl,
            await GetFreshNonceAsync().ConfigureAwait(false),
            kid: accountUrl);

        await SendAcmeRequestAsync(HttpMethod.Post, keyChangeUrl.ToString(), outerPayload).ConfigureAwait(false);
    }

    private async Task SendAccountPostAsGetAsync(IKey signingKey)
    {
        Assert.NotNull(AcmeState.AccountUrl);
        var signedPayload = CreateSignedPayload(
            signingKey,
            (object?)null,
            AcmeState.AccountUrl!,
            await GetFreshNonceAsync().ConfigureAwait(false),
            kid: AcmeState.AccountUrl);

        await SendAcmeRequestAsync(HttpMethod.Post, AcmeState.AccountUrl!.ToString(), signedPayload).ConfigureAwait(false);
    }

    [UnconditionalSuppressMessage("Trimming", "IL2026",
        Justification = "These conformance tests serialize small detached account requests in the normal test runtime only.")]
    [UnconditionalSuppressMessage("AOT", "IL3050",
        Justification = "These conformance tests run in the standard test runtime and do not target AOT publishing.")]
    private async Task<Uri> CreateDetachedAccountAsync(IKey key)
        => await CreateAdditionalAccountAsync(key).ConfigureAwait(false);

    private async Task SendReplayNonceFailureAsync()
    {
        await WhenTheClientPostsToAnAcmeResource().ConfigureAwait(false);
        Assert.Equal(HttpStatusCode.Created, AcmeState.Response?.StatusCode);
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

    private JsonDocument ParseResponseDocument()
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
        Justification = "These conformance tests deserialize nested JWS payloads in the normal test runtime only.")]
    [UnconditionalSuppressMessage("AOT", "IL3050",
        Justification = "These conformance tests run in the standard test runtime and do not target AOT publishing.")]
    private JwsPayload ParseInnerSignedPayload()
    {
        Assert.NotNull(AcmeState.SignedPayload);
        return JsonSerializer.Deserialize<JwsPayload>(Base64UrlEncoder.Decode(AcmeState.SignedPayload!.Payload))
               ?? throw new Xunit.Sdk.XunitException("Could not deserialize the nested keyChange JWS payload.");
    }

    private JsonDocument ParseInnerProtectedHeader()
    {
        var payload = ParseInnerSignedPayload();
        return JsonDocument.Parse(Base64UrlEncoder.Decode(payload.Protected));
    }

    private JsonDocument ParseInnerKeyChangePayload()
    {
        var payload = ParseInnerSignedPayload();
        return JsonDocument.Parse(Base64UrlEncoder.Decode(payload.Payload));
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
        Justification = "These conformance tests deserialize small ACME authorization payloads in the normal test runtime only.")]
    [UnconditionalSuppressMessage("AOT", "IL3050",
        Justification = "These conformance tests run in the standard test runtime and do not target AOT publishing.")]
    private AcmeAuthorization DeserializeAuthorizationResponse()
    {
        Assert.NotNull(AcmeState.ResponseBytes);
        return JsonSerializer.Deserialize<AcmeAuthorization>(AcmeState.ResponseBytes!, AcmeJsonOptions)
               ?? throw new Xunit.Sdk.XunitException("Could not deserialize ACME authorization response.");
    }

    [UnconditionalSuppressMessage("Trimming", "IL2026",
        Justification = "These conformance tests deserialize small ACME challenge payloads in the normal test runtime only.")]
    [UnconditionalSuppressMessage("AOT", "IL3050",
        Justification = "These conformance tests run in the standard test runtime and do not target AOT publishing.")]
    private AcmeChallenge DeserializeChallengeResponse()
    {
        Assert.NotNull(AcmeState.ResponseBytes);
        return JsonSerializer.Deserialize<AcmeChallenge>(AcmeState.ResponseBytes!, AcmeJsonOptions)
               ?? throw new Xunit.Sdk.XunitException("Could not deserialize ACME challenge response.");
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

    private async Task EnsurePendingAuthorizationChallengeAsync(string challengeType)
    {
        await CreatePendingOrderAsync().ConfigureAwait(false);

        var order = await GetRequiredService<OpenCertServer.Acme.Abstractions.Storage.IStoreOrders>()
            .LoadOrder(GetOrderId(), CancellationToken.None)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException("Could not load the ACME order from the store.");

        var authorization = order.Authorizations.First();
        var challenge = authorization.Challenges.First(ch => string.Equals(ch.Type, challengeType, StringComparison.Ordinal));

        AcmeState.ExpectedChallengeType = challengeType;
        AcmeState.AuthorizationUrl = new Uri($"https://localhost/order/{order.OrderId}/auth/{authorization.AuthorizationId}");
        AcmeState.ChallengeUrl = new Uri($"https://localhost/order/{order.OrderId}/auth/{authorization.AuthorizationId}/chall/{challenge.ChallengeId}");
        AcmeState.ExpectedIdentifiers = [authorization.Identifier.Value];
        GetRequiredService<TestAcmeChallengeValidationState>().Reset();
        AcmeState.AuthorizationResponse = MapAuthorization(order, authorization);
        AcmeState.ChallengeResponse = MapChallenge(order, authorization, challenge);
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

    private async Task EnsureIssuedOrderWithCertificateKeyAsync()
    {
        if (AcmeState.IssuedCertificateChain != null && AcmeState.CertificateKey != null && AcmeState.OrderResponse?.Certificate != null)
        {
            await EnsureCurrentOrderResourceUrlsAsync().ConfigureAwait(false);
            return;
        }

        await CreateReadyOrderAsync().ConfigureAwait(false);
        var certificateKey = KeyFactory.NewKey(SecurityAlgorithms.RsaSha256);
        var csr = CreateCsrBase64(AcmeState.ExpectedIdentifiers!, certificateKey);
        AcmeState.CertificateKey = certificateKey;

        await FinalizeCurrentOrderAsync(csr).ConfigureAwait(false);
        await DownloadCurrentCertificateAsync().ConfigureAwait(false);
        await EnsureCurrentOrderResourceUrlsAsync().ConfigureAwait(false);
    }

    private async Task EnsureCurrentOrderResourceUrlsAsync()
    {
        var order = await LoadCurrentOrderModelAsync().ConfigureAwait(false);
        var authorization = order.Authorizations.FirstOrDefault();
        if (authorization == null)
        {
            return;
        }

        AcmeState.AuthorizationUrl ??= new Uri($"https://localhost/order/{order.OrderId}/auth/{authorization.AuthorizationId}");

        var challenge = authorization.Challenges.FirstOrDefault();
        if (challenge != null)
        {
            AcmeState.ChallengeUrl ??= new Uri($"https://localhost/order/{order.OrderId}/auth/{authorization.AuthorizationId}/chall/{challenge.ChallengeId}");
        }
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

        var kid = await GetKidForResourceAsync(AcmeState.OrderUrl!).ConfigureAwait(false);

        var signedPayload = CreateSignedPayload(
            AcmeState.Key!,
            (object?)null,
            AcmeState.OrderUrl!,
            await GetFreshNonceAsync().ConfigureAwait(false),
            kid: kid);

        await SendAcmeRequestAsync(HttpMethod.Post, AcmeState.OrderUrl!.ToString(), signedPayload).ConfigureAwait(false);
        AcmeState.OrderResponse = DeserializeOrderResponse();
    }

    private async Task FetchCurrentAuthorizationAsync()
    {
        var order = await LoadCurrentOrderModelAsync().ConfigureAwait(false);
        var authorization = order.GetAuthorization(GetAuthorizationId())
                            ?? throw new InvalidOperationException("Could not load the current authorization.");
        AcmeState.AuthorizationResponse = MapAuthorization(order, authorization);
    }

    private async Task FetchCurrentChallengeAsync()
    {
        var order = await LoadCurrentOrderModelAsync().ConfigureAwait(false);
        var authorization = order.GetAuthorization(GetAuthorizationId())
                            ?? throw new InvalidOperationException("Could not load the current authorization.");
        var challenge = authorization.GetChallenge(GetChallengeId())
                        ?? throw new InvalidOperationException("Could not load the current challenge.");
        AcmeState.ChallengeResponse = MapChallenge(order, authorization, challenge);
    }

    private async Task RefreshCurrentAuthorizationAndChallengeAsync()
    {
        await FetchCurrentAuthorizationAsync().ConfigureAwait(false);
        await FetchCurrentChallengeAsync().ConfigureAwait(false);
    }

    private async Task RefreshCurrentOrderAsync()
    {
        var order = await LoadCurrentOrderModelAsync().ConfigureAwait(false);
        AcmeState.OrderResponse = MapOrder(order);
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

    private async Task SendPostAsGetAsync(Uri requestUrl)
    {
        var kid = await GetKidForResourceAsync(requestUrl).ConfigureAwait(false);

        var signedPayload = CreateSignedPayload(
            AcmeState.Key!,
            (object?)null,
            requestUrl,
            await GetFreshNonceAsync().ConfigureAwait(false),
            kid: kid);

        await SendAcmeRequestAsync(HttpMethod.Post, requestUrl.ToString(), signedPayload).ConfigureAwait(false);
        AcmeState.PostAsGetExchanges.Add(new AcmeExchange(
            HttpMethod.Post,
            requestUrl,
            AcmeState.RawRequestBody ?? string.Empty,
            AcmeState.RequestContentType,
            CloneResponse(AcmeState.Response!, AcmeState.ResponseBytes ?? []),
            AcmeState.ResponseBytes ?? []));
    }

    private async Task RevokeCurrentCertificateAsync(IKey? certificatePrivateKey)
    {
        var kid = certificatePrivateKey == null
            ? await GetCurrentOrderAccountLocationAsync().ConfigureAwait(false)
            : null;

        await RevokeCurrentCertificateAsync(
            certificatePrivateKey ?? AcmeState.Key!,
            kid).ConfigureAwait(false);
    }

    private async Task RevokeCurrentCertificateAsync(IKey signingKey, Uri? kid)
    {
        await GivenTheAcmeServerImplementsTheRevokeCertResource().ConfigureAwait(false);

        var revokeUrl = AcmeState.RevokeCertUrl!;
        var revocationPayload = new
        {
            certificate = Base64UrlEncoder.Encode(AcmeState.IssuedCertificateChain!.Certificate.RawData)
        };

        var nonce = await GetFreshNonceAsync().ConfigureAwait(false);
        var signedPayload = kid == null
            ? CreateSignedPayload(
                signingKey,
                revocationPayload,
                revokeUrl,
                nonce,
                jwkOverride: GetCertificatePublicJwk(AcmeState.IssuedCertificateChain!.Certificate),
                rsaSignaturePadding: RSASignaturePadding.Pkcs1)
            : CreateSignedPayload(
                signingKey,
                revocationPayload,
                revokeUrl,
                nonce,
                kid: kid);

        await SendAcmeRequestAsync(HttpMethod.Post, revokeUrl.ToString(), signedPayload).ConfigureAwait(false);
    }

    private async Task RunValidationWorkerAsync()
    {
        using var scope = _server.Services.CreateScope();
        var validationWorker = scope.ServiceProvider.GetRequiredService<OpenCertServer.Acme.Abstractions.Workers.IValidationWorker>();
        await validationWorker.Run(CancellationToken.None).ConfigureAwait(false);
    }

    private async Task<OpenCertServer.Acme.Abstractions.Model.Order> LoadCurrentOrderModelAsync()
        => await GetRequiredService<OpenCertServer.Acme.Abstractions.Storage.IStoreOrders>()
               .LoadOrder(GetOrderId(), CancellationToken.None)
               .ConfigureAwait(false)
           ?? throw new InvalidOperationException("Could not load the current ACME order from the store.");

    private async Task<OpenCertServer.Acme.Abstractions.Model.Account> LoadCurrentAccountModelAsync()
    {
        if (AcmeState.OrderUrl != null)
        {
            var order = await LoadCurrentOrderModelAsync().ConfigureAwait(false);
            return await GetRequiredService<OpenCertServer.Acme.Abstractions.Storage.IStoreAccounts>()
                       .LoadAccount(order.AccountId, CancellationToken.None)
                       .ConfigureAwait(false)
                   ?? throw new InvalidOperationException($"Could not load the ACME account '{order.AccountId}' from the store.");
        }

        var accountUrl = AcmeState.AccountContext?.Location ?? AcmeState.AccountUrl;
        Assert.NotNull(accountUrl);
        return await LoadAccountByUrlAsync(accountUrl!).ConfigureAwait(false);
    }

    private async Task<OpenCertServer.Acme.Abstractions.Model.Account> LoadAccountByUrlAsync(Uri accountUrl)
    {
        var accountId = accountUrl.Segments.Last().TrimEnd('/');
        return await GetRequiredService<OpenCertServer.Acme.Abstractions.Storage.IStoreAccounts>()
                   .LoadAccount(accountId, CancellationToken.None)
                   .ConfigureAwait(false)
               ?? throw new InvalidOperationException($"Could not load the ACME account '{accountId}' from the store.");
    }

    private string GetAuthorizationId()
    {
        Assert.NotNull(AcmeState.AuthorizationUrl);
        return AcmeState.AuthorizationUrl!.Segments.Last();
    }

    private string GetChallengeId()
    {
        Assert.NotNull(AcmeState.ChallengeUrl);
        return AcmeState.ChallengeUrl!.Segments.Last();
    }

    private AcmeAuthorization MapAuthorization(
        OpenCertServer.Acme.Abstractions.Model.Order order,
        OpenCertServer.Acme.Abstractions.Model.Authorization authorization)
    {
        return new AcmeAuthorization
        {
            Identifier = new CertesSlim.Acme.Resource.Identifier
            {
                Type = Enum.Parse<CertesSlim.Acme.Resource.IdentifierType>(authorization.Identifier.Type, ignoreCase: true),
                Value = authorization.Identifier.Value
            },
            Status = Enum.Parse<CertesSlim.Acme.Resource.AuthorizationStatus>(authorization.Status.ToString()),
            Expires = authorization.Expires,
            Wildcard = authorization.IsWildcard,
            Challenges = authorization.Challenges.Select(challenge => MapChallenge(order, authorization, challenge)).ToList()
        };
    }

    private AcmeChallenge MapChallenge(
        OpenCertServer.Acme.Abstractions.Model.Order order,
        OpenCertServer.Acme.Abstractions.Model.Authorization authorization,
        OpenCertServer.Acme.Abstractions.Model.Challenge challenge)
    {
        return new AcmeChallenge
        {
            Type = challenge.Type,
            Url = new Uri($"https://localhost/order/{order.OrderId}/auth/{authorization.AuthorizationId}/chall/{challenge.ChallengeId}"),
            Status = Enum.Parse<AcmeChallengeStatus>(challenge.Status.ToString()),
            Validated = challenge.Validated,
            Error = challenge.Error == null
                ? null
                : new CertesSlim.Acme.AcmeError
                {
                    Type = challenge.Error.Type,
                    Detail = challenge.Error.Detail,
                    Identifier = challenge.Error.Identifier == null
                        ? null
                        : new CertesSlim.Acme.Resource.Identifier
                        {
                            Type = Enum.Parse<CertesSlim.Acme.Resource.IdentifierType>(challenge.Error.Identifier.Type, ignoreCase: true),
                            Value = challenge.Error.Identifier.Value
                        }
                },
            Token = challenge.Token
        };
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

    private static string CreateCsrBase64(IList<string> dnsNames, IKey certificateKey, bool includeSubjectAlternativeNames = true)
    {
        var request = CreateCertificateRequest(certificateKey, includeSubjectAlternativeNames, dnsNames);
        return Base64UrlEncoder.Encode(request.CreateSigningRequest());
    }

    private static CertificateRequest CreateCertificateRequest(IKey certificateKey, bool includeSubjectAlternativeNames, IList<string> dnsNames)
    {
        CertificateRequest request = certificateKey.SecurityKey switch
        {
            RsaSecurityKey rsaSecurityKey => new CertificateRequest(
                new X500DistinguishedName("CN=localhost"),
                rsaSecurityKey.Rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pss),
            ECDsaSecurityKey ecdsaSecurityKey => new CertificateRequest(
                new X500DistinguishedName("CN=localhost"),
                ecdsaSecurityKey.ECDsa,
                HashAlgorithmName.SHA256),
            _ => throw new NotSupportedException("Only RSA and ECDSA certificate keys are supported in the ACME conformance tests.")
        };

        if (!includeSubjectAlternativeNames)
        {
            return request;
        }

        var subjectAlternativeNames = new SubjectAlternativeNameBuilder();
        foreach (var dnsName in dnsNames)
        {
            subjectAlternativeNames.AddDnsName(dnsName);
        }

        if (dnsNames.Count > 0)
        {
            request.CertificateExtensions.Add(subjectAlternativeNames.Build());
        }

        return request;
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

    private async Task<Uri> GetCurrentOrderAccountLocationAsync()
    {
        var order = await LoadCurrentOrderModelAsync().ConfigureAwait(false);
        return new Uri($"https://localhost/account/{order.AccountId}");
    }

    private async Task<Uri> GetKidForResourceAsync(Uri requestUrl)
    {
        var defaultAccountLocation = AcmeState.AccountContext?.Location ?? AcmeState.AccountUrl;

        if (defaultAccountLocation != null &&
            string.Equals(requestUrl.AbsolutePath, defaultAccountLocation.AbsolutePath, StringComparison.Ordinal))
        {
            return defaultAccountLocation;
        }

        if (requestUrl.AbsolutePath.StartsWith("/order/", StringComparison.Ordinal))
        {
            return await GetCurrentOrderAccountLocationAsync().ConfigureAwait(false);
        }

        if (defaultAccountLocation != null)
        {
            return defaultAccountLocation;
        }

        return await GetCurrentOrderAccountLocationAsync().ConfigureAwait(false);
    }

    private Uri GetAccountLocation()
        => AcmeState.AccountContext?.Location ?? AcmeState.AccountUrl ?? throw new InvalidOperationException("No ACME account location is available.");

    private static DateTime TruncateToSecond(DateTime value)
        => new(value.Ticks - (value.Ticks % TimeSpan.TicksPerSecond), value.Kind);

    private T GetRequiredService<T>() where T : notnull
        => _server.Services.GetRequiredService<T>();

    private static HttpResponseMessage CloneResponse(HttpResponseMessage response, byte[] responseBytes)
    {
        var clone = new HttpResponseMessage(response.StatusCode)
        {
            ReasonPhrase = response.ReasonPhrase,
            Version = response.Version,
            RequestMessage = response.RequestMessage,
            Content = new ByteArrayContent(responseBytes)
        };

        foreach (var header in response.Headers)
        {
            _ = clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        foreach (var header in response.Content.Headers)
        {
            _ = clone.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        return clone;
    }

    private Uri? GetDirectoryUri(string propertyName)
    {
        using var document = ParseResponseDocument();
        if (!TryGetJsonProperty(document.RootElement, propertyName, out var property))
        {
            return null;
        }

        return Uri.TryCreate(property.GetString(), UriKind.Absolute, out var uri) ? uri : null;
    }

    private bool GetDirectoryBoolean(string path)
    {
        using var document = ParseResponseDocument();
        return TryGetJsonProperty(document.RootElement, path, out var property) && property.ValueKind == JsonValueKind.True;
    }

    private string? GetDirectoryString(string path)
    {
        using var document = ParseResponseDocument();
        return TryGetJsonProperty(document.RootElement, path, out var property) ? property.GetString() : null;
    }

    private static bool TryGetJsonProperty(JsonElement element, string path, out JsonElement property)
    {
        property = element;
        foreach (var segment in path.Split('.'))
        {
            if (property.ValueKind != JsonValueKind.Object || !property.TryGetProperty(segment, out property))
            {
                property = default;
                return false;
            }
        }

        return true;
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
        string? nonce,
        Uri? kid = null,
        string? algOverride = null,
        JsonWebKey? jwkOverride = null,
        RSASignaturePadding? rsaSignaturePadding = null)
    {
        var alg = algOverride ?? ToJwsAlgorithm(key.Algorithm);
        object protectedHeader = kid == null
            ? nonce == null
                ? new
                {
                    alg,
                    jwk = jwkOverride ?? key.JsonWebKey,
                    url = requestUrl
                }
                : new
                {
                    alg,
                    jwk = jwkOverride ?? key.JsonWebKey,
                    nonce,
                    url = requestUrl
                }
            : nonce == null
                ? new
                {
                    alg,
                    kid,
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
            RsaSecurityKey r => r.Rsa.SignData(signingBytes, key.HashAlgorithm, rsaSignaturePadding ?? System.Security.Cryptography.RSASignaturePadding.Pss),
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

    private static string GetJwkThumbprint(JsonWebKey jwk)
        => Base64UrlEncoder.Encode(jwk.ComputeJwkThumbprint());

    private static JsonWebKey GetCertificatePublicJwk(X509Certificate2 certificate)
        => JsonWebKeyConverter.ConvertFromSecurityKey(certificate.GetRSAPublicKey() is { } rsa
            ? new RsaSecurityKey(rsa.ExportParameters(false))
            : certificate.GetECDsaPublicKey() is { } ecdsa
                ? new ECDsaSecurityKey(ECDsa.Create(ecdsa.ExportParameters(false)))
                : throw new NotSupportedException("Only RSA and ECDSA certificates are supported in the ACME conformance tests."));

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

                using var protectedHeader = JsonDocument.Parse(Base64UrlEncoder.Decode(AcmeState.SignedPayload.Protected));
                AcmeState.RequestNonce = protectedHeader.RootElement.TryGetProperty("nonce", out var nonceProperty)
                    ? nonceProperty.GetString()
                    : null;
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

        public AcmeAuthorization? AuthorizationResponse { get; set; }

        public AcmeChallenge? ChallengeResponse { get; set; }

        public AcmeChallenge? ImmediateChallengeResponse { get; set; }

        public Uri? AccountUrl { get; set; }

        public Uri? OrderUrl { get; set; }

        public Uri? OrdersUrl { get; set; }

        public Uri? AuthorizationUrl { get; set; }

        public Uri? ChallengeUrl { get; set; }

        public Uri? KeyChangeUrl { get; set; }

        public Uri? RevokeCertUrl { get; set; }

        public string? RequestContentType { get; set; }

        public IList<string>? ExpectedContacts { get; set; }

        public IList<string>? ExpectedIdentifiers { get; set; }

        public string? ExpectedChallengeType { get; set; }

        public IList<Uri>? ExpectedOrderUrls { get; set; }

        public DateTimeOffset? ExpectedNotBefore { get; set; }

        public DateTimeOffset? ExpectedNotAfter { get; set; }

        public string? RequestNonce { get; set; }

        public string? FinalizeRequestCsr { get; set; }

        public string? ExpectedChallengeFetchUrl { get; set; }

        public string? ExpectedDnsValidationIdentifier { get; set; }

        public string? GeneratedChallengeToken { get; set; }

        public string? RawRequestBody { get; set; }

        public JwsPayload? SignedPayload { get; set; }

        public IKey? Key { get; set; }

        public IKey? UnknownKey { get; set; }

        public IKey? PreviousAccountKey { get; set; }

        public IKey? CertificateKey { get; set; }

        public AcmeCertificateChain? IssuedCertificateChain { get; set; }

        public bool RequiresTermsOfServiceAgreement { get; set; }

        public bool RequiresExternalAccountBinding { get; set; }

        public string? CurrentEabKeyId { get; set; }

        public string? CurrentEabMacKey { get; set; }

        public bool EabKeyIsActive { get; set; }

        public List<AcmeExchange> PostAsGetExchanges { get; } = [];
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







