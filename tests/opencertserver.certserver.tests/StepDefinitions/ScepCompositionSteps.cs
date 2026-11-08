namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using Microsoft.Extensions.Configuration;
using Reqnroll;
using Xunit;

/// <summary>
/// The SCEP composition gate: the decision that both registers the SCEP services in
/// <c>certserver</c> and maps the <c>/scep</c> routes. A monolith enables SCEP by default; a
/// CA-only host disables it. The gate is <see cref="Program.IsScepEnabled"/>, so exercising it
/// directly proves that a disabled host maps neither the services nor the routes.
/// </summary>
[Binding]
public sealed class ScepCompositionSteps
{
    private bool _scepMapped;

    [Given("a host with no SCEP configuration")]
    public void GivenAHostWithNoScepConfiguration()
    {
        _scepMapped = Program.IsScepEnabled(
            [.. new string[0]],
            new ConfigurationBuilder().AddInMemoryCollection([]).Build());
    }

    [Given("a host with a SCEP challenge {string}")]
    public void GivenAHostWithAScepChallenge(string challenge)
    {
        _scepMapped = Program.IsScepEnabled(
            [.. new string[0]],
            new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?> { ["Scep:Challenge"] = challenge })
                .Build());
    }

    [Given("a host with Intune SCEP validation")]
    public void GivenAHostWithIntuneScepValidation()
    {
        _scepMapped = Program.IsScepEnabled(
            [.. new string[0]],
            new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?> { ["Scep:Intune:TenantId"] = "00000000-0000-0000-0000-000000000000" })
                .Build());
    }

    [Given("a CA-only host that disables SCEP")]
    public void GivenACaOnlyHostThatDisablesScep()
    {
        _scepMapped = Program.IsScepEnabled(
            [.. new string[0]],
            new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?> { ["Scep:Enabled"] = "false" })
                .Build());
    }

    [Given("a host that disables SCEP but also configures a challenge {string}")]
    public void GivenAHostThatDisablesScepButAlsoConfiguresAChallenge(string challenge)
    {
        _scepMapped = Program.IsScepEnabled(
            [.. new string[0]],
            new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Scep:Enabled"] = "false",
                    ["Scep:Challenge"] = challenge
                })
                .Build());
    }

    [When("the host decides whether to map SCEP")]
    public void WhenTheHostDecidesWhetherToMapScep()
    {
        // The decision was taken when the host configuration was read.
    }

    [Then("SCEP is mapped")]
    public void ThenScepIsMapped() => Assert.True(_scepMapped, "SCEP should be mapped on this host.");

    [Then("SCEP is not mapped")]
    public void ThenScepIsNotMapped() => Assert.False(_scepMapped, "SCEP should not be mapped on this host.");
}
