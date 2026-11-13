namespace OpenCertServer.Ca.Tests;

using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using OpenCertServer.Ca.Utils.Ca;
using Reqnroll;
using Xunit;

[Binding]
public sealed class CertificateRequestPipelineSteps : IDisposable
{
    private readonly ECDsa _key = ECDsa.Create();
    private readonly InMemoryCertificateStore _store = new();
    private readonly List<string> _executed = [];
    private readonly CancellationTokenSource _cancellation = new();
    private readonly ClaimsIdentity _identity = new([new Claim(ClaimTypes.Name, "pipeline.example")], "test");
    private readonly List<IValidateCertificateRequests> _validators = [];
    private readonly List<ValidatorRegistration> _registrations = [];
    private CertificateRequest _request = null!;
    private X509Certificate2 _previous = null!;
    private SignCertificateResponse _response = null!;
    private string? _legacyError;
    private ValidationResult _contextResult = ValidationResult.Passed;
    private byte[]? _postSubject;

    [Given("a CA with legacy and context-based request validators")]
    public async Task GivenMixedValidators()
    {
        _request = new CertificateRequest("CN=pipeline.example", _key, HashAlgorithmName.SHA256);
        _previous = _request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        await _store.AddCertificate(_previous, "default");
        _validators.Add(new LegacyValidator(this));
        _validators.Add(new ContextValidator(this));
    }

    [Given("the legacy request validator rejects the CSR")]
    public void GivenLegacyRejection() => _legacyError = "Legacy request rejected.";

    [Given("the context-based request validator also rejects the CSR")]
    public void GivenContextRejection() => _contextResult = ValidationResult.Error("Context request rejected.");

    [Given("""^a pipeline validator in the "([^"]+)" phase returns "([^"]+)"$""")]
    public void GivenPipelineValidator(string phase, string outcome)
    {
        var parsedPhase = Enum.Parse<ValidatorPhase>(phase);
        var result = outcome switch
        {
            "pass" => ValidationResult.Passed,
            "reject" => ValidationResult.Reject($"Rejected by {phase} validator."),
            "approval" => ValidationResult.NeedsApproval("Manual review required."),
            "custom approval" => ValidationResult.NeedsApproval("Manual review required.", "manual-review"),
            _ => throw new ArgumentOutOfRangeException(nameof(outcome), outcome, "Unknown validation outcome.")
        };
        _registrations.Add(new ValidatorRegistration(phase, parsedPhase, 0,
            new PhaseValidator(this, phase, result)));
    }

    [When(@"^the CA signs through its (request-validator|registered-pipeline) constructor$")]
    public async Task WhenSigning(string constructor)
    {
        var profile = CertificateAuthority.CreateSelfSignedEcdsa(
            "default", new X500DistinguishedName("CN=pipeline-ca"), TimeSpan.FromDays(1));
        using var issuer = profile.CertificateChain[0];
        using var issuerKey = profile.PrivateKey;
        var configuration = new CaConfiguration(new CaProfileSet("default", profile), [], [], []);
        var services = new ServiceCollection();
        foreach (var validator in _validators)
        {
            services.AddSingleton(validator);
        }
        foreach (var registration in _registrations)
        {
            services.AddSingleton(registration);
        }
        services.AddValidatorPipeline();
        using var provider = services.BuildServiceProvider();
        var authority = constructor == "request-validator"
            ? new CertificateAuthority(configuration, _store, new AcceptChain(),
                new RandomNumberCertificateIdGenerator(), NullLogger<CertificateAuthority>.Instance, _validators.ToArray())
            : new CertificateAuthority(configuration, _store, new AcceptChain(),
                new RandomNumberCertificateIdGenerator(), NullLogger<CertificateAuthority>.Instance,
                provider.GetRequiredService<IValidatorPipeline>());
        _response = await authority.SignCertificateRequest(
            _request, "default", _identity, _previous, cancellationToken: _cancellation.Token);
    }

    [Then("both request validator contracts ran with the complete enrollment context")]
    public void ThenBothContractsRan() => Assert.Equal(["legacy", "context"], _executed);

    [Then("the pipeline CA issued and stored the certificate")]
    public async Task ThenIssued()
    {
        var success = Assert.IsType<SignCertificateResponse.Success>(_response);
        Assert.Equal("default", await _store.GetIssuingProfile(success.Certificate.Thumbprint));
        var revoked = await _store.GetRevocationList("default").ToArrayAsync();
        Assert.Equal(_previous.SerialNumber, Assert.Single(revoked).SerialNumber);
    }

    [Then("the pipeline CA rejected without superseding the previous certificate")]
    public async Task ThenRejected()
    {
        var error = Assert.IsType<SignCertificateResponse.Error>(_response);
        Assert.Contains("Legacy request rejected.", string.Join("\n", error.Errors));
        Assert.Empty(await _store.GetRevocationList("default").ToArrayAsync());
        Assert.Single(await _store.GetInventory().ToArrayAsync());
    }

    [Then("""^the pipeline CA refused issuance with "([^"]+)"$""")]
    public async Task ThenRefused(string reason)
    {
        var error = Assert.IsType<SignCertificateResponse.Error>(_response);
        Assert.Contains(reason, string.Join("\n", error.Errors));
        Assert.Empty(await _store.GetRevocationList("default").ToArrayAsync());
        Assert.Single(await _store.GetInventory().ToArrayAsync());
    }

    [Then("""^the CA validation execution order is "([^"]+)"$""")]
    public void ThenExecutionOrder(string order) =>
        Assert.Equal(order.Split(", ", StringSplitOptions.RemoveEmptyEntries), _executed);

    [Then("the post validator inspected the signed certificate before persistence")]
    public void ThenPostCertificate()
    {
        Assert.NotNull(_postSubject);
        Assert.Equal(_request.SubjectName.RawData, _postSubject);
    }

    [When("the CA signing operation is cancelled before validation")]
    public async Task WhenCancelled()
    {
        await _cancellation.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => WhenSigning("registered-pipeline"));
        Assert.Empty(_executed);
        Assert.Single(await _store.GetInventory().ToArrayAsync());
    }

    private void AssertContext(
        CertificateRequest request, string? profile, ClaimsIdentity? identity,
        X509Certificate2? previous, CancellationToken token)
    {
        Assert.Same(_request, request);
        Assert.Equal("default", profile);
        Assert.Same(_identity, identity);
        Assert.Same(_previous, previous);
        Assert.Equal(_cancellation.Token, token);
    }

    public void Dispose()
    {
        (_response as SignCertificateResponse.Success)?.Certificate.Dispose();
        _previous?.Dispose();
        _key.Dispose();
        _cancellation.Dispose();
    }

    private sealed class LegacyValidator(CertificateRequestPipelineSteps state) : IValidateCertificateRequests
    {
        public Task<string?> Validate(
            CertificateRequest request, string? profile = null, ClaimsIdentity? requestor = null,
            X509Certificate2? reenrollingFrom = null, CancellationToken cancellationToken = default)
        {
            state.AssertContext(request, profile, requestor, reenrollingFrom, cancellationToken);
            state._executed.Add("legacy");
            return Task.FromResult(state._legacyError);
        }
    }

    private sealed class ContextValidator(CertificateRequestPipelineSteps state) : IValidateCertificateRequests
    {
        public Task<ValidationResult> Validate(ValidatorContext context, CancellationToken cancellationToken = default)
        {
            state.AssertContext(context.Request, context.Profile, context.Requestor, context.ReenrollingFrom, cancellationToken);
            Assert.Equal(state._cancellation.Token, context.CancellationToken);
            state._executed.Add("context");
            return Task.FromResult(state._contextResult);
        }
    }

    private sealed class PhaseValidator(
        CertificateRequestPipelineSteps state, string phase, ValidationResult result) : IValidateCertificateRequests
    {
        public async Task<ValidationResult> Validate(ValidatorContext context, CancellationToken cancellationToken = default)
        {
            state.AssertContext(context.Request, context.Profile, context.Requestor, context.ReenrollingFrom, cancellationToken);
            state._executed.Add(phase);
            if (phase == "Post")
            {
                var certificate = Assert.IsType<X509Certificate2>(context.IssuedCertificate);
                state._postSubject = certificate.SubjectName.RawData;
                Assert.Null(await state._store.GetIssuingProfile(certificate.Thumbprint));
            }
            else
            {
                Assert.Null(context.IssuedCertificate);
            }
            return result;
        }
    }

    private sealed class AcceptChain : IValidateX509Chains
    {
        public Task<bool> Validate(X509Chain chain, CancellationToken cancellationToken = default) =>
            Task.FromResult(true);
    }
}
