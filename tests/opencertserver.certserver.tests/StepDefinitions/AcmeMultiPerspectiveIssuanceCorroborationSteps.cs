namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using CertesSlim.Acme.Resource;
using DnsClientX;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using OpenCertServer.Acme.Abstractions.Services;
using OpenCertServer.Acme.Server.Configuration;
using OpenCertServer.Acme.Server.Services;
using Reqnroll;
using Xunit;
using AcmeAccount = OpenCertServer.Acme.Abstractions.Model.Account;
using AcmeAuthorization = OpenCertServer.Acme.Abstractions.Model.Authorization;
using AcmeChallenge = OpenCertServer.Acme.Abstractions.Model.Challenge;
using AcmeError = CertesSlim.Acme.AcmeError;
using AcmeOrder = OpenCertServer.Acme.Abstractions.Model.Order;

[Binding]
public sealed class AcmeMultiPerspectiveIssuanceCorroborationSteps
{
    private AcmeAccount _account = null!;
    private AcmeChallenge _challenge = null!;
    private ICaaValidator _caaValidator = null!;
    private readonly List<IDnsResolver> _perspectives = [];
    private FakeHttpHandler _httpHandler = null!;
    private string[] _dohServers = [];
    private DnsEndpoint _legacyEndpoint = DnsEndpoint.Cloudflare;
    private IReadOnlyList<DnsPerspective> _createdPerspectives = [];
    private (bool IsValid, AcmeError? Error) _result;
    private Exception? _dnsException;

    [Given("an ACME account with a pending dns-01 challenge for {string}")]
    public void GivenDns01Challenge(string hostname)
        => CreateChallenge(hostname, ChallengeTypes.Dns01);

    [Given("an ACME account with a pending http-01 challenge for {string}")]
    public void GivenHttp01Challenge(string hostname)
        => CreateChallenge(hostname, ChallengeTypes.Http01);

    [Given("the DoH servers {string} are configured")]
    public void GivenDohServers(string servers)
        => _dohServers = servers.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    [Given("no DoH servers are configured")]
    public void GivenNoDohServers()
        => _dohServers = [];

    [Given("the legacy DNS endpoint is {string}")]
    public void GivenLegacyEndpoint(string endpoint)
        => _legacyEndpoint = Enum.Parse<DnsEndpoint>(endpoint, ignoreCase: true);

    [Given("the dns-01 perspectives return the expected TXT record")]
    public void GivenDnsPerspectivesReturnExpectedTxt()
    {
        var expected = ComputeDns01Content();
        AddPerspective(new StubDnsResolver(txtRecords: [expected, "unrelated-record"]));
        AddPerspective(new StubDnsResolver(txtRecords: ["unrelated-record", expected]));
        AddPerspective(new StubDnsResolver(txtRecords: [expected, "unrelated-record"]));
    }

    [Given("the dns-01 perspectives return different TXT records")]
    public void GivenDnsPerspectivesReturnDifferentTxt()
    {
        var expected = ComputeDns01Content();
        AddPerspective(new StubDnsResolver(txtRecords: [expected]));
        AddPerspective(new StubDnsResolver(txtRecords: [$"{expected}-different"]));
    }

    [Given("one dns-01 perspective fails")]
    public void GivenOneDnsPerspectiveFails()
    {
        var expected = ComputeDns01Content();
        AddPerspective(new StubDnsResolver(txtRecords: [expected]));
        AddPerspective(new StubDnsResolver(error: new DnsClientException("perspective unavailable")));
    }

    [Given("the http-01 perspectives return the same IP address {string}")]
    public void GivenHttpPerspectivesReturnSameIp(string address)
    {
        var ip = IPAddress.Parse(address);
        AddPerspective(new StubDnsResolver(ipAddresses: [ip]));
        AddPerspective(new StubDnsResolver(ipAddresses: [ip]));
    }

    [Given("the http-01 perspectives return different IP addresses")]
    public void GivenHttpPerspectivesReturnDifferentIps()
    {
        AddPerspective(new StubDnsResolver(ipAddresses: [IPAddress.Parse("93.184.216.34")]));
        AddPerspective(new StubDnsResolver(ipAddresses: [IPAddress.Parse("93.184.216.35")]));
    }

    [Given("the challenge server returns the expected token")]
    public void GivenChallengeServerReturnsExpectedToken()
    {
        var thumbprint = Base64UrlEncoder.Encode(_account.Jwk.ComputeJwkThumbprint());
        _httpHandler.SetResponse(HttpStatusCode.OK, $"{_challenge.Token}.{thumbprint}");
    }

    [Given("two perspectives return different CAA records")]
    public void GivenPerspectivesReturnDifferentCaaRecords()
    {
        AddPerspective(new StubDnsResolver(caaRecords: [new CaaRecord(0, "issue", "ca.example.com")]));
        AddPerspective(new StubDnsResolver(caaRecords: [new CaaRecord(0, "issue", "other.example.com")]));
    }

    [When("the DNS perspectives are created from configuration")]
    public void WhenPerspectivesAreCreated()
    {
        _createdPerspectives = DnsPerspectiveFactory.Create(
            new AcmeServerOptions
            {
                DohServers = _dohServers,
                DnsEndpoint = _legacyEndpoint
            },
            timeoutMilliseconds: 5000);
    }

    [When("the dns-01 challenge is validated with multi-perspective DNS")]
    public async Task WhenDns01ChallengeIsValidated()
    {
        var validator = new ValidateDns01Challenges(
            NullLogger<ValidateDns01Challenges>.Instance,
            CreateResolver(),
            _caaValidator);
        _result = await validator.ValidateChallenge(_challenge, _account, CancellationToken.None)
            .ConfigureAwait(false);
    }

    [When("the http-01 challenge is validated with multi-perspective DNS")]
    public async Task WhenHttp01ChallengeIsValidated()
    {
        using var httpClient = new HttpClient(_httpHandler);
        var validator = new ValidateHttp01Challenges(httpClient, _caaValidator, CreateResolver());
        _result = await validator.ValidateChallenge(_challenge, _account, CancellationToken.None)
            .ConfigureAwait(false);
    }

    [When("CAA is resolved with multi-perspective DNS")]
    public async Task WhenCaaIsResolved()
    {
        try
        {
            await CreateResolver()
                .ResolveCaaRecordsAsync("example.com", CancellationToken.None)
                .ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            _dnsException = exception;
        }
    }

    [Then("there must be {int} distinct DNS perspectives")]
    [Then("there must be {int} distinct DNS perspective")]
    public void ThenThereMustBeDistinctPerspectives(int count)
    {
        Assert.Equal(count, _createdPerspectives.Count);
        Assert.Equal(count, _createdPerspectives.Select(perspective => perspective.Name).Distinct().Count());
    }

    [Then("the corroborated challenge must succeed")]
    public void ThenChallengeSucceeds()
    {
        Assert.True(
            _result.IsValid,
            $"Expected validation to succeed but got error: {_result.Error?.Type} — {_result.Error?.Detail}");
        Assert.Null(_result.Error);
    }

    [Then("the corroborated challenge must fail with error type {string}")]
    public void ThenChallengeFails(string errorType)
    {
        Assert.False(_result.IsValid, "Expected validation to fail.");
        Assert.NotNull(_result.Error);

        var expectedType = errorType.Contains(':')
            ? errorType
            : $"urn:ietf:params:acme:error:{errorType}";
        Assert.Equal(expectedType, _result.Error.Type);
    }

    [Then("the corroborated DNS lookup must fail with a perspective mismatch")]
    public void ThenLookupFailsWithMismatch()
        => Assert.IsType<DnsPerspectiveMismatchException>(_dnsException);

    private void CreateChallenge(string hostname, string type)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(ecdsa));
        _account = new AcmeAccount(jwk, contacts: null, tosAccepted: DateTimeOffset.UtcNow)
        {
            Status = AccountStatus.Valid
        };

        var identifier = new Identifier { Type = IdentifierType.Dns, Value = hostname };
        var order = new AcmeOrder(_account, [identifier], profile: null)
        {
            Expires = DateTimeOffset.UtcNow.AddDays(1)
        };
        var authorization = new AcmeAuthorization(
            order,
            identifier,
            expires: DateTimeOffset.UtcNow.AddDays(1));
        _challenge = new AcmeChallenge(authorization, type);

        _caaValidator = Substitute.For<ICaaValidator>();
        _caaValidator
            .ValidateAsync(
                Arg.Any<Identifier>(),
                Arg.Any<string?>(),
                Arg.Any<string?>(),
                Arg.Any<CancellationToken>())
            .Returns((AcmeError?)null);

        _httpHandler = new FakeHttpHandler();
    }

    private string ComputeDns01Content()
    {
        var thumbprintBytes = _account.Jwk.ComputeJwkThumbprint();
        var thumbprint = Base64UrlEncoder.Encode(thumbprintBytes);
        var keyAuth = Encoding.UTF8.GetBytes($"{_challenge.Token}.{thumbprint}");
        return Base64UrlEncoder.Encode(SHA256.HashData(keyAuth));
    }

    private void AddPerspective(StubDnsResolver resolver)
        => _perspectives.Add(resolver);

    private MultiPerspectiveDnsResolver CreateResolver()
        => new(
            _perspectives
                .Select((resolver, index) => new DnsPerspective($"perspective-{index}", resolver))
                .ToArray(),
            NullLogger<MultiPerspectiveDnsResolver>.Instance);

    private sealed class StubDnsResolver : IDnsResolver
    {
        private readonly IReadOnlyList<CaaRecord> _caaRecords;
        private readonly IReadOnlyList<string> _txtRecords;
        private readonly IReadOnlyList<IPAddress> _ipAddresses;
        private readonly Exception? _error;

        public StubDnsResolver(
            IReadOnlyList<CaaRecord>? caaRecords = null,
            IReadOnlyList<string>? txtRecords = null,
            IReadOnlyList<IPAddress>? ipAddresses = null,
            Exception? error = null)
        {
            _caaRecords = caaRecords ?? [];
            _txtRecords = txtRecords ?? [];
            _ipAddresses = ipAddresses ?? [];
            _error = error;
        }

        public Task<IReadOnlyList<CaaRecord>> ResolveCaaRecordsAsync(
            string name,
            CancellationToken cancellationToken)
            => _error is null
                ? Task.FromResult(_caaRecords)
                : Task.FromException<IReadOnlyList<CaaRecord>>(_error);

        public Task<IReadOnlyList<string>> ResolveTxtRecordsAsync(
            string name,
            CancellationToken cancellationToken)
            => _error is null
                ? Task.FromResult(_txtRecords)
                : Task.FromException<IReadOnlyList<string>>(_error);

        public Task<IReadOnlyList<IPAddress>> ResolveIpAddressesAsync(
            string name,
            CancellationToken cancellationToken)
            => _error is null
                ? Task.FromResult(_ipAddresses)
                : Task.FromException<IReadOnlyList<IPAddress>>(_error);
    }

    private sealed class FakeHttpHandler : HttpMessageHandler
    {
        private HttpStatusCode _statusCode = HttpStatusCode.OK;
        private string? _body;

        public void SetResponse(HttpStatusCode statusCode, string body)
        {
            _statusCode = statusCode;
            _body = body;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(_statusCode);
            if (_body is not null)
            {
                response.Content = new StringContent(_body, Encoding.UTF8, "text/plain");
            }

            return Task.FromResult(response);
        }
    }
}
