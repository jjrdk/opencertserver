namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using CertesSlim.Acme;
using CertesSlim.Acme.Resource;
using DnsClientX;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using OpenCertServer.Acme.Server.Configuration;
using OpenCertServer.Acme.Server.Services;
using Reqnroll;
using Xunit;

[Binding]
public sealed class AcmeCaaSteps
{
    private const string CaaIdentity = "ca.example.com";

    private readonly ScenarioContext _scenarioContext;

    public AcmeCaaSteps(ScenarioContext scenarioContext)
    {
        _scenarioContext = scenarioContext;
    }

    private CaaState State
    {
        get
        {
            if (_scenarioContext.TryGetValue(nameof(CaaState), out var value)
                && value is CaaState state)
            {
                return state;
            }

            state = new CaaState();
            _scenarioContext[nameof(CaaState)] = state;
            return state;
        }
    }

    [BeforeScenario("caa-rfc8657")]
    public void ResetCaaState()
    {
        _scenarioContext.Remove(nameof(CaaState));
    }

    [Given("a CAA \"issue\" record for \"([^\"]+)\" authorizing \"([^\"]+)\"")]
    public void GivenAuthorizingRecord(string domain, string issuer)
    {
        State.Records.Add((domain, issuer));
    }

    [Given("a CAA \"issue\" record for \"([^\"]+)\" authorizing \"([^\"]+)\" with the parameter \"(.*)\"")]
    public void GivenAuthorizingRecordWithParameter(string domain, string issuer, string parameter)
    {
        State.Records.Add((domain, $"{issuer}; {parameter}"));
    }

    [Given("a CAA \"issue\" record for \"([^\"]+)\" authorizing \"([^\"]+)\" with the parameters \"(.*)\"")]
    public void GivenAuthorizingRecordWithParameters(string domain, string issuer, string parameters)
    {
        State.Records.Add((domain, $"{issuer}; {parameters}"));
    }

    [Given("a CAA \"issue\" record for \"([^\"]+)\" with an empty issuer")]
    public void GivenEmptyIssuerRecord(string domain)
    {
        State.Records.Add((domain, string.Empty));
    }

    [Given("the ACME request uses the account \"(.*)\"")]
    public void GivenAccountUri(string accountUri)
    {
        State.AccountUri = accountUri;
    }

    [Given("the validation method \"(.*)\"")]
    public void GivenValidationMethod(string validationMethod)
    {
        State.ValidationMethod = validationMethod;
    }

    [When("CAA validation runs for \"(.+)\"")]
    public async Task WhenCaaValidationRuns(string domain)
    {
        var identifier = new Identifier { Type = IdentifierType.Dns, Value = domain };
        var options = Options.Create(new AcmeServerOptions { CAAIdentities = [CaaIdentity] });
        var client = Substitute.For<IDnsResolver>();
        client
            .ResolveCaaRecordsAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(BuildRecords(domain));
        var validator = new CaaValidator(NullLogger<CaaValidator>.Instance, client, options);
        State.Result = await validator
            .ValidateAsync(identifier, State.AccountUri, State.ValidationMethod, CancellationToken.None)
            .ConfigureAwait(false);
    }

    [Then("the CAA validation must authorize issuance")]
    public void ThenCaaValidationAuthorizes()
    {
        Assert.Null(State.Result);
    }

    [Then("the CAA validation must reject issuance")]
    public void ThenCaaValidationRejects()
    {
        Assert.NotNull(State.Result);
    }

    private IReadOnlyList<CaaRecord> BuildRecords(string domain)
        => State.Records
            .Where(record => string.Equals(record.Domain, domain, StringComparison.OrdinalIgnoreCase))
            .Select(record => new CaaRecord(
                flags: 0,
                tag: "issue",
                value: record.Value))
            .ToList();

    private sealed class CaaState
    {
        public List<(string Domain, string Value)> Records { get; } = [];

        public string? AccountUri { get; set; }

        public string? ValidationMethod { get; set; }

        public AcmeError? Result { get; set; }
    }
}