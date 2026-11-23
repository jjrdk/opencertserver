namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Text.Json;
using CertesSlim.Acme;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using OpenCertServer.Acme.Abstractions.Services;
using OpenCertServer.Acme.Server.Filters;
using OpenCertServer.Acme.Server.Extensions;
using OpenCertServer.Acme.Server.Services;
using Reqnroll;
using Xunit;

[Binding]
public sealed class AcmeErrorDisclosureSteps
{
    private AcmeError? _error;
    private ServiceProvider? _services;

    [When("the ACME server uses its default HTTP client registration")]
    public void WhenDefaultHttpClientIsRegistered()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAcmeServer(new ConfigurationBuilder().Build());
        _services = services.BuildServiceProvider();
    }

    [Then("the HTTP challenge validator can be resolved")]
    public void ThenHttpValidatorCanBeResolved()
    {
        using var services = _services!;
        Assert.IsType<ValidateHttp01Challenges>(services.GetRequiredService<IValidateHttp01Challenges>());
    }

    [When("the ACME CSR validator receives {string}")]
    public async Task WhenCsrIsValidated(string csr)
    {
        var validator = new DefaultCsrValidator(NullLogger<DefaultCsrValidator>.Instance);
        var result = await validator.ValidateCsr(null!, csr, CancellationToken.None);
        Assert.False(result.isValid);
        _error = result.error;
    }

    [Then("the CSR validation error has the fixed detail {string}")]
    public void ThenCsrErrorIsSanitized(string detail)
    {
        Assert.NotNull(_error);
        Assert.Equal("urn:ietf:params:acme:error:badCSR", _error.Type);
        Assert.Equal(detail, _error.Detail);
    }

    [When("an ACME endpoint encounters a JSON parser failure")]
    public async Task WhenJsonParsingFails()
    {
        var http = new DefaultHttpContext();
        var filter = new AcmeProtocolResponseFilter(
            Substitute.For<INonceService>(), NullLogger<AcmeProtocolResponseFilter>.Instance);
        var result = await filter.InvokeAsync(
            new TestFilterContext(http),
            _ => throw new JsonException("private-resolver.internal:5432"));
        _error = Assert.IsType<AcmeError>(Assert.IsAssignableFrom<IValueHttpResult>(result).Value);
        Assert.Equal(StatusCodes.Status400BadRequest,
            Assert.IsAssignableFrom<IStatusCodeHttpResult>(result).StatusCode);
    }

    [Then("the ACME problem has the fixed detail {string}")]
    public void ThenProblemIsSanitized(string detail)
    {
        Assert.Equal(detail, _error!.Detail);
    }

    private sealed class TestFilterContext(HttpContext context) : EndpointFilterInvocationContext
    {
        public override HttpContext HttpContext { get; } = context;
        public override IList<object?> Arguments { get; } = [];
        public override T GetArgument<T>(int index) => (T)Arguments[index]!;
    }
}
