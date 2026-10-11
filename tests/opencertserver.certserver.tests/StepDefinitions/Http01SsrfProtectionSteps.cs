namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using CertesSlim.Acme;
using CertesSlim.Acme.Resource;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using OpenCertServer.Acme.Abstractions.Services;
using OpenCertServer.Acme.Server.Services;
using Reqnroll;
using Xunit;
using AcmeAccount = OpenCertServer.Acme.Abstractions.Model.Account;
using AcmeAccountStatus = CertesSlim.Acme.Resource.AccountStatus;
using AcmeAuthorization = OpenCertServer.Acme.Abstractions.Model.Authorization;
using AcmeChallenge = OpenCertServer.Acme.Abstractions.Model.Challenge;
using AcmeError = CertesSlim.Acme.AcmeError;
using AcmeOrder = OpenCertServer.Acme.Abstractions.Model.Order;

[Binding]
public sealed class Http01SsrfProtectionSteps
{
    private readonly ScenarioContext _ctx;

    private AcmeAccount _account = null!;
    private AcmeChallenge _challenge = null!;
    private IDnsResolver _dnsResolver = null!;
    private ICaaValidator _caaValidator = null!;
    private FakeHttpHandler _httpHandler = null!;
    private bool _useProductionHandler;
    private (bool IsValid, AcmeError? Error) _result;

    public Http01SsrfProtectionSteps(ScenarioContext ctx)
    {
        _ctx = ctx;
    }

    [BeforeScenario("http01-ssrf")]
    public void ResetState()
    {
        _dnsResolver = Substitute.For<IDnsResolver>();
        _caaValidator = Substitute.For<ICaaValidator>();
        _httpHandler = new FakeHttpHandler();
        _useProductionHandler = false;

        _caaValidator
            .ValidateAsync(Arg.Any<Identifier>(), Arg.Any<string?>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns((AcmeError?)null);
    }

    [Given("a valid ACME account with a pending http-01 challenge for {string}")]
    public void GivenAccountAndChallenge(string hostname)
    {
        _account = CreateValidAccount();
        _challenge = CreateHttp01Challenge(_account, hostname);
    }

    [Given("the DNS resolver returns the address {string} for the challenge host")]
    public void GivenDnsReturnsAddress(string ip)
    {
        var address = IPAddress.Parse(ip);
        _dnsResolver
            .ResolveIpAddressesAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<IReadOnlyList<IPAddress>>([address]));
    }

    [Given("the challenge server returns status 200 with the expected token")]
    public void GivenChallengeServerReturns200()
    {
        var thumbprint = Base64UrlEncoder.Encode(_account.Jwk.ComputeJwkThumbprint());
        var tokenResponse = $"{_challenge.Token}.{thumbprint}";
        _httpHandler.SetResponse(HttpStatusCode.OK, tokenResponse);
    }

    [Given("the challenge server returns a 302 redirect")]
    public void GivenChallengeServerReturns302()
    {
        _httpHandler.SetRedirect("http://169.254.169.254/");
        _useProductionHandler = true;
    }

    [When("the http-01 challenge is validated")]
    public async Task WhenHttp01ChallengeIsValidated()
    {
        using var httpClient = _useProductionHandler
            ? new HttpClient(SsrfBlockingSocketsHandler.Create())
            : new HttpClient(_httpHandler);
        var validator = new ValidateHttp01Challenges(httpClient, _caaValidator, _dnsResolver);
        _result = await validator.ValidateChallenge(_challenge, _account, CancellationToken.None)
            .ConfigureAwait(false);
    }

    [Then("the challenge must fail with error type {string}")]
    public void ThenChallengeFails(string errorType)
    {
        Assert.False(_result.IsValid, "Expected validation to fail.");
        Assert.NotNull(_result.Error);
        // AcmeError.Type auto-expands short names to urn:ietf:params:acme:error:{short}
        var expectedType = errorType.Contains(':')
            ? errorType
            : $"urn:ietf:params:acme:error:{errorType}";
        Assert.Equal(expectedType, _result.Error.Type);
    }

    [Then("the configured DNS resolver must have been queried for IP addresses")]
    public async Task ThenDnsResolverWasQueried()
    {
        await _dnsResolver
            .Received(1)
            .ResolveIpAddressesAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .ConfigureAwait(false);
    }

    [Then("the challenge must succeed")]
    public void ThenChallengeSucceeds()
    {
        Assert.True(
            _result.IsValid,
            $"Expected validation to succeed but got error: {_result.Error?.Type} — {_result.Error?.Detail}");
        Assert.Null(_result.Error);
    }

    // ─── Test object helpers ────────────────────────────────────────────────

    private static AcmeAccount CreateValidAccount()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(ecdsa));
        var account = new AcmeAccount(jwk, contacts: null, tosAccepted: DateTimeOffset.UtcNow)
        {
            Status = AcmeAccountStatus.Valid
        };
        return account;
    }

    private static AcmeChallenge CreateHttp01Challenge(AcmeAccount account, string hostname)
    {
        var identifier = new Identifier { Type = IdentifierType.Dns, Value = hostname };
        var order = new AcmeOrder(account, [identifier], profile: null)
        {
            Expires = DateTimeOffset.UtcNow.AddDays(1)
        };
        var authorization = new AcmeAuthorization(order, identifier, expires: DateTimeOffset.UtcNow.AddDays(1));
        return new AcmeChallenge(authorization, ChallengeTypes.Http01);
    }

    // ─── Fake HTTP handler ──────────────────────────────────────────────────

    private sealed class FakeHttpHandler : HttpMessageHandler
    {
        private HttpStatusCode _statusCode = HttpStatusCode.OK;
        private string? _body;
        private string? _redirectLocation;

        public void SetResponse(HttpStatusCode status, string body)
        {
            _statusCode = status;
            _body = body;
            _redirectLocation = null;
        }

        public void SetRedirect(string location)
        {
            _statusCode = HttpStatusCode.Found;
            _redirectLocation = location;
            _body = null;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(_statusCode);
            if (_redirectLocation is not null)
            {
                response.Headers.Location = new Uri(_redirectLocation);
            }
            else if (_body is not null)
            {
                response.Content = new StringContent(_body, Encoding.UTF8, "text/plain");
            }

            return Task.FromResult(response);
        }
    }
}
